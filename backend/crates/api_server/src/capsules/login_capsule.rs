use crate::state::AppState;
use anyhow::Result;
use capsule_compiler::ast::{IdentitySource, Program, Step};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};

/// Build the default login capsule AST (password verification + allow)
pub fn build_default_login_capsule(tenant_id: &str) -> Program {
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "auth:login".to_string(),
                resource: tenant_id.to_string(),
            },
            Step::Allow(true),
        ],
    }
}

/// Load org-specific login policy or fallback to default.
/// Returns (program, version) where version=0 means using the default.
pub async fn load_login_policy(tenant_id: &str, db: &sqlx::PgPool) -> Result<(Program, i32)> {
    let row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some((version, json)) = row {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
        }
    }

    Ok((build_default_login_capsule(tenant_id), 0))
}

/// Compile a login capsule from a given AST program
pub async fn compile_login_capsule(
    policy: &Program,
    tenant_id: &str,
    state: &AppState,
) -> Result<CapsuleSigned> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let compiled = capsule_compiler::compile(
        policy.clone(),
        tenant_id.to_string(),
        "auth:login".to_string(),
        now,
        now + 300, // 5 minute validity
        &state.ks,
        &state.compiler_kid,
    )?;

    Ok(CapsuleSigned {
        meta: Some(CapsuleMeta {
            tenant_id: compiled.meta.tenant_id,
            action: compiled.meta.action,
            not_before_unix: compiled.meta.not_before_unix,
            not_after_unix: compiled.meta.not_after_unix,
            policy_hash_b64: compiled.meta.ast_hash_b64,
        }),
        ast_bytes: compiled.ast_bytes,
        capsule_hash_b64: compiled.ast_hash.clone(),
        compiler_kid: compiled.compiler_kid,
        compiler_sig_b64: compiled.compiler_sig_b64,
        ast_hash_b64: compiled.ast_hash,
        wasm_hash_b64: compiled.wasm_hash,
        lowering_version: compiled.lowering_version,
        wasm_bytes: compiled.wasm_bytes,
    })
}
