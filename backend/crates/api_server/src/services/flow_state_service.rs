use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use anyhow::Result;
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct HostedAuthFlow {
    pub flow_id: String,
    pub org_id: String,
    pub app_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state_param: Option<String>,
    pub execution_state: serde_json::Value,
    pub current_step: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub completed: bool,
    pub decision_ref: Option<String>,
    /// EIAA: Internal security semantics (authenticate | enroll_identity)
    #[sqlx(default)]
    pub flow_purpose: Option<String>,
}

#[derive(Debug)]
pub struct FlowStateService {
    db: PgPool,
}

impl FlowStateService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create_flow(
        &self,
        org_id: String,
        app_id: Option<String>,
        redirect_uri: Option<String>,
        state_param: Option<String>,
        flow_purpose: Option<String>,
        initial_step: Option<String>,
        ip: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<HostedAuthFlow> {
        let current_step = initial_step.unwrap_or_else(|| flow_steps::INIT.to_string());
        let purpose = flow_purpose.unwrap_or_else(|| flow_purposes::AUTHENTICATE.to_string());
        
        let flow = sqlx::query_as::<_, HostedAuthFlow>(
            r#"
            INSERT INTO hosted_auth_flows (org_id, app_id, redirect_uri, state_param, flow_purpose, current_step, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING flow_id, org_id, app_id, redirect_uri, state_param, execution_state, 
                      current_step, attempts, max_attempts, completed, decision_ref, flow_purpose
            "#
        )
        .bind(org_id)
        .bind(app_id)
        .bind(redirect_uri)
        .bind(state_param)
        .bind(&purpose)
        .bind(&current_step)
        .bind(ip)
        .bind(user_agent)
        .fetch_one(&self.db)
        .await?;

        Ok(flow)
    }

    pub async fn get_flow(&self, flow_id: &str) -> Result<Option<HostedAuthFlow>> {
        let flow = sqlx::query_as::<_, HostedAuthFlow>(
            r#"
            SELECT flow_id, org_id, app_id, redirect_uri, state_param, execution_state,
                   current_step, attempts, max_attempts, completed, decision_ref, flow_purpose
            FROM hosted_auth_flows
            WHERE flow_id = $1 AND expires_at > NOW()
            "#
        )
        .bind(flow_id)
        .fetch_optional(&self.db)
        .await?;

        // EIAA Debug: Log raw execution_state from DB read
        if let Some(ref f) = flow {
            tracing::info!(
                "[FLOW_READ] flow_id={} execution_state={}",
                flow_id,
                serde_json::to_string(&f.execution_state).unwrap_or_else(|_| "<serialize_error>".to_string())
            );
        }

        Ok(flow)
    }

    pub async fn update_state(
        &self,
        flow_id: &str,
        execution_state: serde_json::Value,
        current_step: String,
    ) -> Result<()> {
        // EIAA Debug: Log exact state being persisted
        tracing::info!(
            "[FLOW_WRITE] flow_id={} current_step={} execution_state={}",
            flow_id,
            current_step,
            serde_json::to_string(&execution_state).unwrap_or_else(|_| "<serialize_error>".to_string())
        );

        let rows_affected = sqlx::query(
            r#"
            UPDATE hosted_auth_flows
            SET execution_state = $1, current_step = $2, attempts = attempts + 1
            WHERE flow_id = $3
            "#
        )
        .bind(&execution_state)
        .bind(&current_step)
        .bind(flow_id)
        .execute(&self.db)
        .await?
        .rows_affected();

        tracing::info!("[FLOW_WRITE] flow_id={} rows_affected={}", flow_id, rows_affected);

        Ok(())
    }

    pub async fn complete_flow(&self, flow_id: &str, decision_ref: String) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE hosted_auth_flows
            SET completed = TRUE, decision_ref = $1
            WHERE flow_id = $2
            "#
        )
        .bind(decision_ref)
        .bind(flow_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }



    pub async fn check_attempts(&self, flow_id: &str) -> Result<bool> {
        let exceeded: Option<bool> = sqlx::query_scalar(
            "SELECT attempts >= max_attempts FROM hosted_auth_flows WHERE flow_id = $1"
        )
        .bind(flow_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(exceeded.unwrap_or(true))
    }
}

/// Flow step constants
pub mod flow_steps {
    pub const INIT: &str = "init";
    pub const IDENTIFY: &str = "identify"; // Used for password reset flows
    pub const EMAIL: &str = "email";
    pub const CREDENTIALS: &str = "credentials"; 
    pub const EMAIL_VERIFICATION: &str = "email_verification";
    pub const PASSWORD: &str = "password";
    pub const OTP: &str = "otp";
    pub const MFA: &str = "mfa";
    pub const COMPLETE: &str = "complete";
    pub const ERROR: &str = "error";
    // Credential recovery steps
    pub const RESET_CODE: &str = "reset_code";
    pub const NEW_PASSWORD: &str = "new_password";
}

/// Flow purpose constants
pub mod flow_purposes {
    pub const AUTHENTICATE: &str = "authenticate";
    pub const ADMIN_LOGIN: &str = "admin_login";
    pub const ENROLL_IDENTITY: &str = "enroll_identity";
    pub const CREATE_TENANT: &str = "create_tenant";

    /// EIAA: Credential recovery is distinct from authentication
    pub const CREDENTIAL_RECOVERY: &str = "credential_recovery";
    
    /// Legacy alias for credential recovery
    pub const RESET_PASSWORD: &str = "reset_password";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosted_auth_flow_serialization() {
        let flow = HostedAuthFlow {
            flow_id: "flow_123".to_string(),
            org_id: "org_456".to_string(),
            app_id: Some("app_789".to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            state_param: Some("random_state".to_string()),
            execution_state: serde_json::json!({"step": "password", "user_id": "user_abc"}),
            current_step: "password".to_string(),
            attempts: 1,
            max_attempts: 5,
            completed: false,
            decision_ref: None,
            flow_purpose: Some("authenticate".to_string()),
        };
        
        let json = serde_json::to_string(&flow).unwrap();
        let parsed: HostedAuthFlow = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.flow_id, "flow_123");
        assert_eq!(parsed.org_id, "org_456");
        assert_eq!(parsed.current_step, "password");
        assert_eq!(parsed.attempts, 1);
        assert!(!parsed.completed);
    }

    #[test]
    fn test_hosted_auth_flow_deserialization_with_nulls() {
        let json = r#"{
            "flow_id": "test_flow",
            "org_id": "test_org",
            "app_id": null,
            "redirect_uri": null,
            "state_param": null,
            "execution_state": {},
            "current_step": "init",
            "attempts": 0,
            "max_attempts": 3,
            "completed": false,
            "decision_ref": null,
            "flow_purpose": null
        }"#;
        
        let flow: HostedAuthFlow = serde_json::from_str(json).unwrap();
        
        assert_eq!(flow.flow_id, "test_flow");
        assert!(flow.app_id.is_none());
        assert!(flow.redirect_uri.is_none());
        assert!(flow.decision_ref.is_none());
        assert!(flow.flow_purpose.is_none());
    }

    #[test]
    fn test_flow_step_constants() {
        // Ensure step constants are consistent
        assert_eq!(flow_steps::INIT, "init");
        assert_eq!(flow_steps::IDENTIFY, "identify");
        assert_eq!(flow_steps::PASSWORD, "password");
        assert_eq!(flow_steps::MFA, "mfa");
        assert_eq!(flow_steps::COMPLETE, "complete");
        assert_eq!(flow_steps::ERROR, "error");
    }

    #[test]
    fn test_flow_purpose_constants() {
        assert_eq!(flow_purposes::AUTHENTICATE, "authenticate");
        assert_eq!(flow_purposes::ENROLL_IDENTITY, "enroll_identity");
        assert_eq!(flow_purposes::RESET_PASSWORD, "reset_password");
    }

    #[test]
    fn test_execution_state_json_structure() {
        // Test that execution_state can hold various JSON structures
        let state1 = serde_json::json!({
            "user_id": "usr_123",
            "email_verified": true,
            "mfa_required": false
        });
        
        let state2 = serde_json::json!({
            "factors_completed": ["password", "totp"],
            "risk_score": 25
        });
        
        // Both should be valid execution states
        assert!(state1["user_id"].as_str().is_some());
        assert!(state2["factors_completed"].as_array().is_some());
    }

    #[test]
    fn test_attempts_tracking() {
        let flow = HostedAuthFlow {
            flow_id: "flow_test".to_string(),
            org_id: "org_test".to_string(),
            app_id: None,
            redirect_uri: None,
            state_param: None,
            execution_state: serde_json::json!({}),
            current_step: flow_steps::PASSWORD.to_string(),
            attempts: 3,
            max_attempts: 5,
            completed: false,
            decision_ref: None,
            flow_purpose: None,
        };
        
        // Should not exceed attempts
        assert!(flow.attempts < flow.max_attempts);
        
        // Simulating attempt check
        let exceeded = flow.attempts >= flow.max_attempts;
        assert!(!exceeded);
    }

    #[test]
    fn test_completed_flow_with_decision_ref() {
        let flow = HostedAuthFlow {
            flow_id: "flow_complete".to_string(),
            org_id: "org_test".to_string(),
            app_id: None,
            redirect_uri: Some("https://example.com/done".to_string()),
            state_param: Some("abc123".to_string()),
            execution_state: serde_json::json!({"final": true}),
            current_step: flow_steps::COMPLETE.to_string(),
            attempts: 2,
            max_attempts: 5,
            completed: true,
            decision_ref: Some("dec_xyz789".to_string()),
            flow_purpose: Some(flow_purposes::AUTHENTICATE.to_string()),
        };
        
        assert!(flow.completed);
        assert!(flow.decision_ref.is_some());
        assert_eq!(flow.current_step, "complete");
    }

    #[test]
    fn test_ip_address_formats() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        
        // Test IPv4
        let ipv4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipv4.to_string(), "192.168.1.1");
        
        // Test IPv6
        let ipv6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(ipv6.to_string().contains("2001:db8"));
    }
}
