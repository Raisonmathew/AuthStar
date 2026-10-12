//! Default capsule seeder for new tenants.
//!
//! Called from `POST /api/v1/tenants/provision` during self-serve onboarding.
//! Compiles a minimal "allow authenticated user" capsule for every EIAA action
//! in the registry and inserts them into `eiaa_capsules` using `ON CONFLICT DO NOTHING`
//! so concurrent provisioning calls are safe.
//!
//! ## Why this is not needed for auth decisions
//!
//! `EiaaAuthzLayer` already has an on-demand compilation fallback
//! (`compile_default_capsule_on_demand`) that fires when no capsule exists for a
//! given `(tenant_id, action)`.  The seeder exists for two complementary reasons:
//!
//! 1. **Policy Builder bootstrap** — the UI lists policies for the tenant; without
//!    pre-seeded `policy_builder_configs` rows there is nothing to show and the
//!    admin cannot start editing.
//!
//! 2. **Auditability** — enterprise customers expect an audit record of the default
//!    policy that was in effect from the moment their account was created, not from
//!    the moment of the first authorization request.
//!
//! ## Idempotency
//!
//! Every insert uses `ON CONFLICT DO NOTHING`.  Running the seeder twice on the
//! same tenant is a no-op.  The `policy_builder_configs` insert uses the same
//! pattern.

use crate::middleware::org_context::set_rls_context_on_conn;
use capsule_compiler::ast::{IdentitySource, Program, Step};
use keystore::{InMemoryKeystore, KeyId};
use shared_types::{AppError, Result};
use sqlx::PgPool;

/// All EIAA action strings that must be seeded for every new tenant.
///
/// This list is the canonical source for the self-serve seeder. It is separate
/// from the `Action` enum so the seeder does not take a compile-time dependency
/// on the middleware crate; any new action added to `eiaa_actions.rs` must also
/// be added here.
const SEEDED_ACTIONS: &[&str] = &[
    "admin:manage",
    "agent:manage",
    "agent:token",
    "apikeys:manage",
    "audit:read",
    "audit:verify",
    "auth:step_up",
    "billing:read",
    "billing:write",
    "domains:manage",
    "eiaa:manage",
    "members:manage",
    "mfa:manage",
    "oauth:consent",
    "org:config",
    "org:create",
    "org:read",
    "org:switch",
    "passkeys:manage",
    "policies:manage",
    "policies:nl_compile",
    "publishable_keys:manage",
    "roles:manage",
    "session:logout",
    "tenant:provision",
    "user:consent",
    "user:manage_factors",
    "user:manage_profile",
    "user:read",
];

/// Seed default capsules and policy-builder configs for a freshly created tenant.
///
/// Must be called **inside a transaction** that has already set the RLS context via
/// `set_rls_context_on_conn` / `set_rls_context_on_tx` for the new `tenant_id`.
///
/// Returns `Ok(n)` where `n` is the number of capsule rows actually inserted
/// (0 = already seeded, idempotent).
pub async fn seed_tenant(
    tenant_id: &str,
    db: &PgPool,
    ks: &InMemoryKeystore,
    compiler_kid: &KeyId,
) -> Result<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AppError::Internal(format!("system clock error: {e}")))?
        .as_secs() as i64;
    let not_after = now + 365 * 24 * 3600; // 1-year validity

    let mut seeded = 0usize;

    // Acquire a dedicated connection so we can set the RLS context.
    let mut conn = db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("seeder: failed to acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("seeder: RLS context: {e}")))?;

    for &action in SEEDED_ACTIONS {
        let policy = default_policy(action);

        let compiled = capsule_compiler::compile(
            policy,
            tenant_id.to_string(),
            action.to_string(),
            now,
            not_after,
            ks,
            compiler_kid,
        )
        .map_err(|e| {
            AppError::Internal(format!("seeder: compile failed for action '{action}': {e}"))
        })?;

        let meta_json = serde_json::to_value(&compiled.meta)
            .map_err(|e| AppError::Internal(format!("seeder: meta serialization: {e}")))?;

        let capsule_hash_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = hex::decode(&compiled.wasm_hash).unwrap_or_default();
            URL_SAFE_NO_PAD.encode(&bytes)
        };

        let result = sqlx::query(
            r#"
            INSERT INTO eiaa_capsules
                (tenant_id, action, policy_version, meta, policy_hash_b64, capsule_hash_b64,
                 compiler_kid, compiler_sig_b64, wasm_bytes, ast_bytes, principal_type)
            VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9, 'human')
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(action)
        .bind(&meta_json)
        .bind(&compiled.meta.ast_hash_b64)
        .bind(&capsule_hash_b64)
        .bind(&compiled.compiler_kid)
        .bind(&compiled.compiler_sig_b64)
        .bind(&compiled.wasm_bytes)
        .bind(&compiled.ast_bytes)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            AppError::Internal(format!("seeder: eiaa_capsules insert for '{action}': {e}"))
        })?;

        if result.rows_affected() > 0 {
            // Also create a policy_builder_configs row so the Policy Builder UI
            // can display and edit this action immediately after signup.
            let config_id = format!(
                "pbc_{}",
                uuid::Uuid::new_v4().to_string().replace('-', "")
            );
            sqlx::query(
                r#"
                INSERT INTO policy_builder_configs
                    (id, tenant_id, action_key, state, active_capsule_hash_b64,
                     active_version, draft_version, created_by, created_at, updated_at)
                VALUES ($1, $2, $3, 'active', $4, 1, 2, 'system', NOW(), NOW())
                ON CONFLICT (tenant_id, action_key) DO NOTHING
                "#,
            )
            .bind(&config_id)
            .bind(tenant_id)
            .bind(action)
            .bind(&capsule_hash_b64)
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "seeder: policy_builder_configs insert for '{action}': {e}"
                ))
            })?;

            seeded += 1;
        }
    }

    tracing::info!(
        tenant_id = %tenant_id,
        seeded = seeded,
        total_actions = SEEDED_ACTIONS.len(),
        "Tenant capsule seeding complete"
    );

    Ok(seeded)
}

/// Build the minimal default policy for a given action.
///
/// Policy: VerifyIdentity (primary) → AuthorizeAction → Allow.
/// This is the same policy as `compile_default_capsule_on_demand` in
/// `eiaa_authz.rs`, kept in sync manually.
fn default_policy(action: &str) -> Program {
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: action.to_string(),
                resource: "*".to_string(),
            },
            Step::Allow(true),
        ],
    }
}
