//! Permission tier enforcement for the Unified Policy Builder.
//!
//! Three tiers, each a superset of the previous:
//!
//!   TenantDeveloper  ⊂  TenantAdmin  ⊂  PlatformAdmin
//!
//! Tier is derived from JWT claims at request time — no extra DB lookup needed.

use auth_core::Claims;
use shared_types::AppError;

/// Permission tier for policy builder operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Any authenticated user with `policies:manage` EIAA action.
    /// Includes: owner, admin, developer, member roles.
    TenantDeveloper = 0,

    /// Tenant owner or admin.
    /// Can compile, activate, rollback, manage templates (custom only).
    TenantAdmin = 1,

    /// AuthStar platform staff: tenant_id = 'system' + owner/admin role.
    /// Can manage platform templates, view cross-tenant audit.
    PlatformAdmin = 2,
}

impl Tier {
    /// Derive the permission tier by querying the database for the user's role.
    pub async fn from_user(db: &sqlx::PgPool, claims: &Claims) -> Result<Self, AppError> {
        let is_platform_tenant = claims.tenant_id == "system";

        let role_opt: Option<String> = sqlx::query_scalar(
            "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2",
        )
        .bind(&claims.sub)
        .bind(&claims.tenant_id)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch user role: {e}")))?;

        // If no membership found, treat as guest/developer (least privilege)
        let role = role_opt.unwrap_or_default();
        let is_admin_role = matches!(role.as_str(), "admin" | "owner");

        if is_platform_tenant && is_admin_role {
            Ok(Self::PlatformAdmin)
        } else if is_admin_role {
            Ok(Self::TenantAdmin)
        } else {
            Ok(Self::TenantDeveloper)
        }
    }

    /// Require at least TenantAdmin tier.
    /// Returns Forbidden if the caller is only TenantDeveloper.
    pub fn require_admin(self) -> Result<(), AppError> {
        if self >= Self::TenantAdmin {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "This operation requires tenant admin or owner role.".into(),
            ))
        }
    }

    /// Require PlatformAdmin tier.
    /// Returns Forbidden for all tenant users.
    pub fn require_platform_admin(self) -> Result<(), AppError> {
        if self >= Self::PlatformAdmin {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "This operation requires AuthStar platform admin access (system tenant).".into(),
            ))
        }
    }

    /// Check if this tier can manage a specific template.
    /// Platform templates (owner_tenant_id = NULL) require PlatformAdmin.
    /// Tenant-custom templates require TenantAdmin.
    pub fn can_manage_template(self, owner_tenant_id: Option<&str>) -> Result<(), AppError> {
        match owner_tenant_id {
            None => self.require_platform_admin(),
            Some(_) => self.require_admin(),
        }
    }
}

/// Verify a config belongs to the caller's tenant.
/// Returns the config row on success, NotFound/Forbidden on failure.
pub async fn verify_config_ownership(
    db: &sqlx::PgPool,
    config_id: &str,
    tenant_id: &str,
) -> Result<ConfigOwnershipRow, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT id, tenant_id, action_key, state, active_version, active_capsule_hash_b64
        FROM policy_builder_configs
        WHERE id = $1 AND tenant_id = $2
        "#,
        config_id,
        tenant_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch config: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Policy config not found: {config_id}")))?;

    Ok(ConfigOwnershipRow {
        id: row.id,
        tenant_id: row.tenant_id,
        action_key: row.action_key,
        state: row.state,
        active_version: row.active_version,
        active_capsule_hash_b64: row.active_capsule_hash_b64,
    })
}

/// Mark a config as dirty (needs recompile) — fire-and-forget, non-fatal.
/// Resets state to 'draft' so the UI shows the config needs recompiling.
pub async fn mark_config_dirty(db: &sqlx::PgPool, config_id: &str) {
    let _ = sqlx::query!(
        "UPDATE policy_builder_configs SET state = 'draft', updated_at = NOW() WHERE id = $1",
        config_id
    )
    .execute(db)
    .await;
}

/// Audit event for policy builder operations.
pub struct PolicyAuditEvent<'a> {
    pub tenant_id: &'a str,
    pub config_id: Option<&'a str>,
    pub action_key: Option<&'a str>,
    pub event_type: &'a str,
    pub actor_id: &'a str,
    pub actor_ip: Option<&'a str>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Write an audit event (fire-and-forget — non-fatal on failure).
pub async fn write_audit(db: &sqlx::PgPool, event: PolicyAuditEvent<'_>) {
    let id = format!("pba_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let _ = sqlx::query!(
        r#"
        INSERT INTO policy_builder_audit
            (id, tenant_id, config_id, action_key, event_type, actor_id, actor_ip, description, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        id,
        event.tenant_id,
        event.config_id,
        event.action_key,
        event.event_type,
        event.actor_id,
        event.actor_ip.map(|s| s.to_string()),
        event.description,
        event.metadata,
    )
    .execute(db)
    .await;
}

/// Minimal config row returned by verify_config_ownership.
pub struct ConfigOwnershipRow {
    pub id: String,
    pub tenant_id: String,
    pub action_key: String,
    pub state: String,
    pub active_version: Option<i32>,
    pub active_capsule_hash_b64: Option<String>,
}
