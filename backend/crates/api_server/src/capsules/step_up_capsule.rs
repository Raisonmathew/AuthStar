use crate::state::AppState;
use anyhow::Result;
use capsule_compiler::ast::{
    Comparator, Condition, ContextValue, FactorType, IdentitySource, Program, Step,
};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};

/// Build the default step-up capsule AST.
///
/// **Capability-first design:** The capsule never assumes which factor types
/// a user has enrolled.  It receives `enrolled_factor_count` and the actual
/// `submitted_factor_type` from the route handler and decides based on reality:
///
///   1. Verify identity (session must be valid)
///   2. Evaluate risk for step-up context
///   3. If enrolled_factor_count == 0 → **Deny** ("no_factors_enrolled")
///      The route returns `action_required: ENROLL_FACTOR` so the frontend
///      redirects to enrollment instead of showing a code input.
///   4. If risk > 70 AND has_passkey_enrolled:
///      → require passkey (phishing-resistant)
///   5. If risk > 70 AND no passkey enrolled:
///      → accept whatever the user verified (graceful degradation, flagged)
///   6. Normal risk → accept any verified factor
///   7. Authorize the step-up action
///   8. Allow
pub fn build_default_step_up_capsule(tenant_id: &str) -> Program {
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::EvaluateRisk {
                profile: "step_up".to_string(),
            },
            // Gate 1: Zero factors enrolled → deny immediately.
            // The route handler checks enrolled_factor_count to produce the
            // "no_factors_enrolled" reason string for the frontend.
            Step::Conditional {
                condition: Condition::Context {
                    key: "enrolled_factor_count".to_string(),
                    comparator: Comparator::Eq,
                    value: ContextValue::Integer(0),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            // Gate 2: High phishing risk → branch on passkey availability
            Step::Conditional {
                condition: Condition::RiskScore {
                    comparator: Comparator::Gt,
                    value: Some(70),
                },
                then_branch: vec![Step::Conditional {
                    condition: Condition::Context {
                        key: "has_passkey_enrolled".to_string(),
                        comparator: Comparator::Eq,
                        value: ContextValue::Integer(1),
                    },
                    // Has passkey → require it (phishing-resistant)
                    then_branch: vec![Step::RequireFactor {
                        factor_type: FactorType::Passkey,
                    }],
                    // No passkey → accept whatever factor the user verified.
                    // The route handler detects `degraded_assurance` and applies
                    // restricted session parameters / passkey enrollment nudge.
                    else_branch: Some(vec![Step::RequireFactor {
                        factor_type: FactorType::Any(vec![
                            FactorType::Otp,
                            FactorType::Passkey,
                            FactorType::Password,
                        ]),
                    }]),
                }],
                // Normal risk → any verified factor is acceptable
                else_branch: Some(vec![Step::RequireFactor {
                    factor_type: FactorType::Any(vec![
                        FactorType::Otp,
                        FactorType::Passkey,
                        FactorType::Password,
                    ]),
                }]),
            },
            Step::AuthorizeAction {
                action: "auth:step_up".to_string(),
                resource: tenant_id.to_string(),
            },
            Step::Allow(true),
        ],
    }
}

/// Load tenant-specific step-up policy or fallback to default.
/// Returns (program, version) where version=0 means using the default.
pub async fn load_step_up_policy(tenant_id: &str, db: &sqlx::PgPool) -> Result<(Program, i32)> {
    let row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:step_up' ORDER BY version DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some((version, json)) = row {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
        }
        tracing::warn!(
            tenant_id = %tenant_id,
            "Failed to parse step-up policy, falling back to default"
        );
    }

    Ok((build_default_step_up_capsule(tenant_id), 0))
}

/// Compile a step-up capsule from a given AST program.
pub async fn compile_step_up_capsule(
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
        "auth:step_up".to_string(),
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
