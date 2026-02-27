//! Authorization Context Builder
//!
//! Implements the Builder pattern to construct a rich context for EIAA policy evaluation.
//! This context is serialized to JSON and passed to the capsule runtime.
//!
//! ## Design Pattern: Builder
//! Complex object with many optional fields, constructed step-by-step.

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::RiskLevel;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Enriched authorization context for EIAA policy evaluation.
///
/// This struct contains all the information a policy might need to make a decision.
/// It follows the EIAA principle: "Policies should have access to rich context."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    // === Identity ===
    /// User ID (from JWT `sub` claim)
    pub user_id: String,
    /// Tenant/Organization ID (from JWT `tenant_id` claim)
    pub tenant_id: String,
    /// Session type: "end_user" | "admin" | "flow" | "service"
    pub session_type: String,
    /// Session ID (for revocation checks)
    pub session_id: String,

    // === Request ===
    /// Action being performed (e.g., "billing:read", "org:config")
    pub action: String,
    /// Optional resource identifier (e.g., "org_123", "user_456")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/api/v1/billing/subscription")
    pub path: String,

    // === Network ===
    /// Client IP address (extracted from X-Forwarded-For or socket)
    pub ip_address: String,
    /// User-Agent header
    pub user_agent: String,
    /// Accept-Language header (for locale-based policies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_language: Option<String>,

    // === Risk Assessment ===
    /// Risk score from Risk Engine (0-100)
    pub risk_score: f64,
    /// Risk level: Low, Medium, High, Critical
    pub risk_level: String,
    /// Device trust level (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_trust: Option<String>,

    // === Time ===
    /// Unix timestamp of the request
    pub timestamp: i64,
    /// Cryptographic nonce for replay protection
    pub nonce: String,
    /// Attestation expiry (Unix timestamp)
    pub expires_at: i64,
}

impl Default for AuthorizationContext {
    fn default() -> Self {
        let now = Utc::now().timestamp();
        Self {
            user_id: String::new(),
            tenant_id: String::new(),
            session_type: "end_user".to_string(),
            session_id: String::new(),
            action: String::new(),
            resource: None,
            method: "GET".to_string(),
            path: String::new(),
            ip_address: "0.0.0.0".to_string(),
            user_agent: String::new(),
            accept_language: None,
            risk_score: 0.0,
            risk_level: "low".to_string(),
            device_trust: None,
            timestamp: now,
            nonce: generate_nonce(),
            expires_at: now + 60, // Default 60s TTL
        }
    }
}

/// Builder for constructing `AuthorizationContext` step-by-step.
///
/// # Example
/// ```rust
/// let context = AuthorizationContextBuilder::new()
///     .with_identity(&claims)
///     .with_action("billing:read")
///     .with_network(ip, user_agent)
///     .with_risk(score, level)
///     .build();
/// ```
#[derive(Default)]
pub struct AuthorizationContextBuilder {
    context: AuthorizationContext,
}

impl AuthorizationContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set identity fields from JWT claims.
    pub fn with_identity(
        mut self,
        user_id: &str,
        tenant_id: &str,
        session_type: &str,
        session_id: &str,
    ) -> Self {
        self.context.user_id = user_id.to_string();
        self.context.tenant_id = tenant_id.to_string();
        self.context.session_type = session_type.to_string();
        self.context.session_id = session_id.to_string();
        self
    }

    /// Set the action being authorized.
    pub fn with_action(mut self, action: &str) -> Self {
        self.context.action = action.to_string();
        self
    }

    /// Set optional resource identifier.
    pub fn with_resource(mut self, resource: &str) -> Self {
        self.context.resource = Some(resource.to_string());
        self
    }

    /// Set HTTP request details.
    pub fn with_request(mut self, method: &str, path: &str) -> Self {
        self.context.method = method.to_string();
        self.context.path = path.to_string();
        self
    }

    /// Set network context (IP, User-Agent).
    pub fn with_network(mut self, ip: IpAddr, user_agent: &str) -> Self {
        self.context.ip_address = ip.to_string();
        self.context.user_agent = user_agent.to_string();
        self
    }

    /// Set Accept-Language header.
    pub fn with_locale(mut self, accept_language: &str) -> Self {
        self.context.accept_language = Some(accept_language.to_string());
        self
    }

    /// Set risk assessment from Risk Engine.
    pub fn with_risk(mut self, score: f64, level: RiskLevel) -> Self {
        self.context.risk_score = score;
        self.context.risk_level = format!("{:?}", level).to_lowercase();
        self
    }

    /// Set device trust level.
    pub fn with_device_trust(mut self, trust: &str) -> Self {
        self.context.device_trust = Some(trust.to_string());
        self
    }

    /// Set custom TTL for attestation.
    pub fn with_ttl_seconds(mut self, ttl: i64) -> Self {
        self.context.expires_at = self.context.timestamp + ttl;
        self
    }

    /// Build the final context.
    pub fn build(self) -> AuthorizationContext {
        self.context
    }

    /// Build and serialize to JSON string.
    pub fn build_json(self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.build())
    }
}

/// Generate a cryptographic nonce (16 bytes, base64-encoded).
fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_builder_basic() {
        let ctx = AuthorizationContextBuilder::new()
            .with_identity("usr_123", "org_456", "end_user", "sess_789")
            .with_action("billing:read")
            .build();

        assert_eq!(ctx.user_id, "usr_123");
        assert_eq!(ctx.tenant_id, "org_456");
        assert_eq!(ctx.action, "billing:read");
    }

    #[test]
    fn test_builder_full() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ctx = AuthorizationContextBuilder::new()
            .with_identity("usr_123", "org_456", "admin", "sess_789")
            .with_action("org:config")
            .with_resource("org_456")
            .with_request("PATCH", "/api/v1/organizations/org_456")
            .with_network(ip, "Mozilla/5.0")
            .with_risk(35.0, RiskLevel::Medium)
            .with_ttl_seconds(30)
            .build();

        assert_eq!(ctx.ip_address, "192.168.1.1");
        assert_eq!(ctx.risk_score, 35.0);
        assert_eq!(ctx.risk_level, "medium");
        assert!(ctx.expires_at > ctx.timestamp);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 22); // Base64 of 16 bytes
    }

    #[test]
    fn test_json_serialization() {
        let ctx = AuthorizationContextBuilder::new()
            .with_identity("u", "t", "end_user", "s")
            .with_action("test")
            .build_json()
            .unwrap();

        assert!(ctx.contains("\"user_id\":\"u\""));
        assert!(ctx.contains("\"action\":\"test\""));
    }
}
