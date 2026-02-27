//! Tenant and Organization Scoped Query Helpers
//!
//! Enforces that all data access passes through scope-verified query builders.
//! Scope values (tenant_id, org_id, user_id) MUST come from JWT Claims or
//! verified membership context — never from request bodies or URL params.
//!
//! # Usage
//! ```rust
//! let scope = TenantScope::from_claims(&claims);
//! let session = scope.get_session(&db, &session_id).await?;
//! ```

use sqlx::PgPool;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

/// Tenant-scoped query scope. The `tenant_id` is always sourced from JWT Claims.
pub struct TenantScope<'a> {
    pub tenant_id: &'a str,
    pub user_id: &'a str,
}

impl<'a> TenantScope<'a> {
    /// Construct from verified JWT claims — the ONLY valid source of scope.
    pub fn from_claims(claims: &'a auth_core::jwt::Claims) -> Self {
        Self {
            tenant_id: &claims.tenant_id,
            user_id: &claims.sub,
        }
    }

    // ─── Sessions ───

    /// Fetch active session by ID, scoped to this tenant.
    pub async fn get_active_session(
        &self,
        db: &PgPool,
        session_id: &str,
    ) -> Result<Option<SessionRow>> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, tenant_id, is_provisional, assurance_level,
                   verified_capabilities, expires_at
            FROM sessions
            WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()
            "#,
        )
        .bind(session_id)
        .bind(self.tenant_id)
        .fetch_optional(db)
        .await?;
        Ok(row)
    }

    /// Fetch non-provisional session (strict auth).
    pub async fn get_strict_session(
        &self,
        db: &PgPool,
        session_id: &str,
    ) -> Result<Option<SessionRow>> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, tenant_id, is_provisional, assurance_level,
                   verified_capabilities, expires_at
            FROM sessions
            WHERE id = $1 AND tenant_id = $2
              AND expires_at > NOW() AND is_provisional = false
            "#,
        )
        .bind(session_id)
        .bind(self.tenant_id)
        .fetch_optional(db)
        .await?;
        Ok(row)
    }

    /// Revoke a session (only if it belongs to this tenant + user).
    pub async fn revoke_session(
        &self,
        db: &PgPool,
        session_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE sessions SET expires_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND user_id = $3
            "#,
        )
        .bind(session_id)
        .bind(self.tenant_id)
        .bind(self.user_id)
        .execute(db)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── EIAA Executions ───

    /// Fetch execution record by decision_ref, scoped to tenant.
    pub async fn get_execution(
        &self,
        db: &PgPool,
        decision_ref: &str,
    ) -> Result<Option<ExecutionRow>> {
        let row = sqlx::query_as::<_, ExecutionRow>(
            r#"
            SELECT id, capsule_name, capsule_version, decision, attestation_body,
                   input_hash, executed_at, execution_time_ms, tenant_id
            FROM eiaa_executions
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(decision_ref)
        .bind(self.tenant_id)
        .fetch_optional(db)
        .await?;
        Ok(row)
    }

    /// List recent executions for this tenant.
    pub async fn list_executions(
        &self,
        db: &PgPool,
        limit: i64,
    ) -> Result<Vec<ExecutionRow>> {
        let rows = sqlx::query_as::<_, ExecutionRow>(
            r#"
            SELECT id, capsule_name, capsule_version, decision, attestation_body,
                   input_hash, executed_at, execution_time_ms, tenant_id
            FROM eiaa_executions
            WHERE tenant_id = $1
            ORDER BY executed_at DESC
            LIMIT $2
            "#,
        )
        .bind(self.tenant_id)
        .bind(limit)
        .fetch_all(db)
        .await?;
        Ok(rows)
    }

    // ─── Policies ───

    /// List policies for this tenant.
    pub async fn list_policies(
        &self,
        db: &PgPool,
    ) -> Result<Vec<PolicyRow>> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            r#"
            SELECT id, action, version, status, tenant_id, created_at
            FROM policies
            WHERE tenant_id = $1
            ORDER BY action, version DESC
            "#,
        )
        .bind(self.tenant_id)
        .fetch_all(db)
        .await?;
        Ok(rows)
    }

    /// Get a specific policy by action, scoped to tenant.
    pub async fn get_policy_by_action(
        &self,
        db: &PgPool,
        action: &str,
    ) -> Result<Option<PolicyRow>> {
        let row = sqlx::query_as::<_, PolicyRow>(
            r#"
            SELECT id, action, version, status, tenant_id, created_at
            FROM policies
            WHERE tenant_id = $1 AND action = $2 AND status = 'active'
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(self.tenant_id)
        .bind(action)
        .fetch_optional(db)
        .await?;
        Ok(row)
    }

    // ─── SSO Connections ───

    /// Load SSO provider config scoped to this tenant.
    pub async fn get_sso_connection(
        &self,
        db: &PgPool,
        provider: &str,
    ) -> Result<Option<serde_json::Value>> {
        let config: Option<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT config FROM sso_connections
            WHERE provider = $1 AND tenant_id = $2 AND enabled = true
            LIMIT 1
            "#,
        )
        .bind(provider)
        .bind(self.tenant_id)
        .fetch_optional(db)
        .await?;
        Ok(config)
    }

    // ─── User Factors ───

    /// Get user factors scoped to this user + tenant.
    pub async fn list_user_factors(
        &self,
        db: &PgPool,
    ) -> Result<Vec<FactorRow>> {
        let rows = sqlx::query_as::<_, FactorRow>(
            r#"
            SELECT id, user_id, tenant_id, factor_type, status, created_at
            FROM user_factors
            WHERE user_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(self.user_id)
        .bind(self.tenant_id)
        .fetch_all(db)
        .await?;
        Ok(rows)
    }
}

/// Organization-scoped query scope. The `org_id` must come from verified membership.
pub struct OrgScope<'a> {
    pub org_id: &'a str,
    pub tenant_id: &'a str,
    pub user_id: &'a str,
}

impl<'a> OrgScope<'a> {
    /// Construct after verifying the user is a member of the org.
    /// Returns None if the user is not a member.
    pub async fn verify_membership(
        db: &PgPool,
        claims: &'a auth_core::jwt::Claims,
        org_id: &'a str,
    ) -> Result<Option<Self>> {
        let is_member: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT true FROM memberships
            WHERE user_id = $1 AND organization_id = $2
            "#,
        )
        .bind(&claims.sub)
        .bind(org_id)
        .fetch_optional(db)
        .await?;

        if is_member.is_some() {
            Ok(Some(Self {
                org_id,
                tenant_id: &claims.tenant_id,
                user_id: &claims.sub,
            }))
        } else {
            Ok(None)
        }
    }

    // ─── Custom Domains ───

    /// List domains for this organization.
    pub async fn list_domains(
        &self,
        db: &PgPool,
    ) -> Result<Vec<DomainRow>> {
        let rows = sqlx::query_as::<_, DomainRow>(
            r#"
            SELECT id, organization_id, domain, verification_status, ssl_status,
                   is_primary, created_at
            FROM custom_domains
            WHERE organization_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(self.org_id)
        .fetch_all(db)
        .await?;
        Ok(rows)
    }

    /// Delete a domain only if it belongs to this org.
    pub async fn delete_domain(
        &self,
        db: &PgPool,
        domain_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM custom_domains WHERE id = $1 AND organization_id = $2"
        )
        .bind(domain_id)
        .bind(self.org_id)
        .execute(db)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Subscriptions ───

    /// Get active subscription for this org.
    pub async fn get_active_subscription(
        &self,
        db: &PgPool,
    ) -> Result<Option<SubscriptionRow>> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            r#"
            SELECT id, organization_id, status, stripe_price_id,
                   current_period_end, cancel_at_period_end
            FROM subscriptions
            WHERE organization_id = $1 AND status = 'active'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(self.org_id)
        .fetch_optional(db)
        .await?;
        Ok(row)
    }
}

// ─── Row types ───

#[derive(sqlx::FromRow, Debug)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub is_provisional: bool,
    pub assurance_level: Option<String>,
    pub verified_capabilities: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct ExecutionRow {
    pub id: String,
    pub capsule_name: String,
    pub capsule_version: String,
    pub decision: String,
    pub attestation_body: Option<serde_json::Value>,
    pub input_hash: String,
    pub executed_at: DateTime<Utc>,
    pub execution_time_ms: i64,
    pub tenant_id: String,
}

#[derive(sqlx::FromRow, Debug)]
pub struct PolicyRow {
    pub id: String,
    pub action: String,
    pub version: i32,
    pub status: String,
    pub tenant_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct FactorRow {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub factor_type: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct DomainRow {
    pub id: String,
    pub organization_id: String,
    pub domain: String,
    pub verification_status: String,
    pub ssl_status: String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct SubscriptionRow {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub stripe_price_id: Option<String>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: Option<bool>,
}
