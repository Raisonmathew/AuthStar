use crate::state::AppState;
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use capsule_compiler::ast::{Comparator, Condition, ContextValue, IdentitySource, Program, Step};
use grpc_api::eiaa::runtime::CapsuleSigned;
use sha2::{Digest, Sha256};

/// Build the default EIAA signup capsule AST
pub fn build_default_signup_capsule() -> Program {
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            // Step 1: Verify email ownership
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            // Step 2: Deny if ticket expired
            Step::Conditional {
                condition: Condition::Context {
                    key: "ticket_expired".to_string(),
                    comparator: Comparator::Eq,
                    value: ContextValue::Integer(1),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            // Step 3: Deny if attempts exceeded
            Step::Conditional {
                condition: Condition::Context {
                    key: "attempts_exceeded".to_string(),
                    comparator: Comparator::Eq,
                    value: ContextValue::Integer(1),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            // Step 4: Deny if code mismatch
            Step::Conditional {
                condition: Condition::Context {
                    key: "code_valid".to_string(),
                    comparator: Comparator::Eq,
                    value: ContextValue::Integer(0),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            // Step 5: Authorize identity creation
            Step::AuthorizeAction {
                action: "create_identity".to_string(),
                resource: "user".to_string(),
            },
            // Step 6: Allow
            Step::Allow(true),
        ],
    }
}

/// Load org-specific signup policy or fallback to default
async fn load_signup_policy(org_id: &str, db: &sqlx::PgPool) -> Result<Program> {
    // Try org-specific override
    let policy_row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'signup' ORDER BY version DESC LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(db)
    .await?;

    if let Some((spec,)) = policy_row {
        if let Ok(program) = serde_json::from_value::<Program>(spec) {
            return Ok(program);
        } else {
            tracing::warn!("Failed to parse signup policy for org {}", org_id);
        }
    }

    // Fallback to default
    Ok(build_default_signup_capsule())
}

/// Compile signup capsule for org
pub async fn compile_signup_capsule(org_id: &str, state: &AppState) -> Result<CapsuleSigned> {
    let policy = load_signup_policy(org_id, &state.db).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let compiled = capsule_compiler::compile(
        policy,
        org_id.to_string(),
        "signup".to_string(),
        now,
        now + 86400, // 24 hours
        &state.ks,
        &state.compiler_kid,
    )?;

    // Convert to gRPC type
    Ok(CapsuleSigned {
        meta: Some(grpc_api::eiaa::runtime::CapsuleMeta {
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

/// Build context inputs for signup capsule execution
pub fn build_signup_context(
    ticket: &identity_engine::models::SignupTicket,
    submitted_code: &str,
) -> serde_json::Value {
    let now = chrono::Utc::now();

    // Hash the submitted code for comparison
    let submitted_hash = hash_code(submitted_code);
    let stored_hash = ticket
        .verification_code
        .as_ref()
        .map(|c| hash_code(c))
        .unwrap_or_default();

    serde_json::json!({
        "ticket_id": ticket.id,
        "ticket_expired": if ticket.expires_at < now { 1 } else { 0 },
        "attempts_exceeded": if ticket.verification_attempts >= 3 { 1 } else { 0 },
        "code_valid": if submitted_hash == stored_hash { 1 } else { 0 },
        "timestamp": now.to_rfc3339(),
    })
}

fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
