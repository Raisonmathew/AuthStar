pub mod resolver;
pub mod wasm_host;

use anyhow::{anyhow, Result};
use attestation::{sign_attestation, Attestation, AttestationBody, Decision};
use capsule_compiler::{
    ast::{Program, Step},
    CapsuleSigned,
};

use crate::resolver::{CapsuleResolver, NoopCapsuleResolver};
use crate::wasm_host::EiaaRuntime;
use sha2::Digest; // Required for Sha256's .update() and .finalize() methods

/// Hard cap on recursive sub-capsule depth, defence-in-depth on top of
/// cycle detection. Real policy graphs are shallow; anything past 8 nested
/// `AggregateDecision` levels is almost certainly malformed.
const MAX_SUBCAPSULE_DEPTH: usize = 8;

/// Parameters for capsule execution — groups all inputs to avoid long argument lists.
pub struct ExecuteParams<'a> {
    pub capsule: &'a CapsuleSigned,
    pub input_ctx: RuntimeContext,
    pub runtime_kid: &'a str,
    pub sign_fn: &'a dyn Fn(&[u8]) -> Result<ed25519_dalek::Signature>,
    pub now_unix: i64,
    pub expires_at_unix: i64,
    pub nonce_b64: &'a str,
    /// Expected AST hash for integrity enforcement (optional).
    pub expected_ast_hash: Option<&'a str>,
    /// Expected WASM hash for integrity enforcement (optional).
    pub expected_wasm_hash: Option<&'a str>,
}

pub fn execute(params: ExecuteParams<'_>) -> Result<(DecisionOutput, Attestation)> {
    // Backwards-compatible path: no sub-capsule resolution. Parents that use
    // `Step::AggregateDecision` will see an empty `sub_decisions` map and the
    // host import will fold to Deny (fail closed). Callers that need
    // resolution must use `execute_with_resolver`.
    let _ = NoopCapsuleResolver; // keep the resolver type referenced
    execute_inner(params)
}

/// Execute a capsule with a [`CapsuleResolver`] for `AggregateDecision`
/// children.
///
/// T4.3 — Before invoking the WASM, this function walks the parent's AST,
/// recursively resolves every `Step::AggregateDecision::sub_capsules` entry
/// via `resolver`, executes each child under a *cloned* `RuntimeContext`,
/// and writes the resulting decision (1 = Allow, 0 = Deny) into the parent
/// context's `sub_decisions` map keyed by child `ast_hash`. The parent's
/// `aggregate_decision` host import then folds those values per strategy.
///
/// Cycle protection: each recursive call carries a stack of in-flight
/// hashes; if the same hash reappears, the child resolves to Deny without
/// re-execution. A hard depth cap (`MAX_SUBCAPSULE_DEPTH`) caps pathological
/// graphs even when each node is unique.
///
/// Errors during child execution (resolver miss, hash mismatch, WASM trap)
/// fail the parent closed — the function returns `Err`. This matches the
/// existing `aggregate_decision` host-import contract that treats missing
/// children as Deny.
pub fn execute_with_resolver(
    params: ExecuteParams<'_>,
    resolver: &dyn CapsuleResolver,
) -> Result<(DecisionOutput, Attestation)> {
    let mut params = params;
    // Pre-resolve children only when the parent has at least one
    // AggregateDecision step. Avoids deserializing AST bytes for the common
    // case (no composition).
    if ast_has_aggregate(&params.capsule.ast_bytes)? {
        let mut stack: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        stack.insert(params.capsule.ast_hash.clone());
        let sub_decisions = resolve_children(
            &params.capsule.ast_bytes,
            resolver,
            params.runtime_kid,
            params.sign_fn,
            params.now_unix,
            params.expires_at_unix,
            params.nonce_b64,
            &params.input_ctx,
            &mut stack,
            0,
        )?;
        params.input_ctx.sub_decisions.extend(sub_decisions);
    }
    execute_inner(params)
}

fn ast_has_aggregate(ast_bytes: &[u8]) -> Result<bool> {
    let program: Program = serde_json::from_slice(ast_bytes)
        .map_err(|e| anyhow!("failed to deserialize parent AST: {e}"))?;
    Ok(program_has_aggregate(&program))
}

fn program_has_aggregate(program: &Program) -> bool {
    program.sequence.iter().any(step_has_aggregate)
}

fn step_has_aggregate(step: &Step) -> bool {
    match step {
        Step::AggregateDecision { .. } => true,
        Step::Conditional {
            then_branch,
            else_branch,
            ..
        } => {
            then_branch.iter().any(step_has_aggregate)
                || else_branch
                    .as_ref()
                    .map(|b| b.iter().any(step_has_aggregate))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_children(
    parent_ast_bytes: &[u8],
    resolver: &dyn CapsuleResolver,
    runtime_kid: &str,
    sign_fn: &dyn Fn(&[u8]) -> Result<ed25519_dalek::Signature>,
    now_unix: i64,
    expires_at_unix: i64,
    nonce_b64: &str,
    parent_ctx: &RuntimeContext,
    stack: &mut std::collections::HashSet<String>,
    depth: usize,
) -> Result<std::collections::HashMap<String, i32>> {
    if depth >= MAX_SUBCAPSULE_DEPTH {
        return Err(anyhow!(
            "sub-capsule recursion exceeded max depth {MAX_SUBCAPSULE_DEPTH}"
        ));
    }
    let program: Program = serde_json::from_slice(parent_ast_bytes)
        .map_err(|e| anyhow!("failed to deserialize parent AST: {e}"))?;
    let mut out: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    collect_and_execute_children(
        &program.sequence,
        resolver,
        runtime_kid,
        sign_fn,
        now_unix,
        expires_at_unix,
        nonce_b64,
        parent_ctx,
        stack,
        depth,
        &mut out,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn collect_and_execute_children(
    steps: &[Step],
    resolver: &dyn CapsuleResolver,
    runtime_kid: &str,
    sign_fn: &dyn Fn(&[u8]) -> Result<ed25519_dalek::Signature>,
    now_unix: i64,
    expires_at_unix: i64,
    nonce_b64: &str,
    parent_ctx: &RuntimeContext,
    stack: &mut std::collections::HashSet<String>,
    depth: usize,
    out: &mut std::collections::HashMap<String, i32>,
) -> Result<()> {
    for step in steps {
        match step {
            Step::AggregateDecision { sub_capsules, .. } => {
                for child_ref in sub_capsules {
                    let hash = &child_ref.ast_hash;
                    if out.contains_key(hash) {
                        continue;
                    }
                    if stack.contains(hash) {
                        // Cycle: fail closed for this child without recursing.
                        out.insert(hash.clone(), 0);
                        continue;
                    }
                    let child = resolver.load(hash)?;
                    if child.ast_hash != *hash {
                        return Err(anyhow!(
                            "resolver returned mismatched ast_hash: requested {hash}, got {}",
                            child.ast_hash
                        ));
                    }
                    stack.insert(hash.clone());
                    // Recurse into the child's own AggregateDecision steps
                    // first so its `sub_decisions` map is populated before
                    // it executes.
                    let grandchildren = resolve_children(
                        &child.ast_bytes,
                        resolver,
                        runtime_kid,
                        sign_fn,
                        now_unix,
                        expires_at_unix,
                        nonce_b64,
                        parent_ctx,
                        stack,
                        depth + 1,
                    )?;
                    let mut child_ctx = parent_ctx.clone();
                    child_ctx.sub_decisions.extend(grandchildren);
                    let child_params = ExecuteParams {
                        capsule: &child,
                        input_ctx: child_ctx,
                        runtime_kid,
                        sign_fn,
                        now_unix,
                        expires_at_unix,
                        nonce_b64,
                        expected_ast_hash: Some(hash.as_str()),
                        expected_wasm_hash: None,
                    };
                    let (decision, _att) = execute_inner(child_params)?;
                    stack.remove(hash);
                    out.insert(hash.clone(), decision.decision);
                }
            }
            Step::Conditional {
                then_branch,
                else_branch,
                ..
            } => {
                collect_and_execute_children(
                    then_branch,
                    resolver,
                    runtime_kid,
                    sign_fn,
                    now_unix,
                    expires_at_unix,
                    nonce_b64,
                    parent_ctx,
                    stack,
                    depth,
                    out,
                )?;
                if let Some(eb) = else_branch {
                    collect_and_execute_children(
                        eb,
                        resolver,
                        runtime_kid,
                        sign_fn,
                        now_unix,
                        expires_at_unix,
                        nonce_b64,
                        parent_ctx,
                        stack,
                        depth,
                        out,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn execute_inner(params: ExecuteParams<'_>) -> Result<(DecisionOutput, Attestation)> {
    let capsule = params.capsule;
    // 1. Integrity Check (Inputs vs Expected)
    if let Some(exp) = params.expected_ast_hash {
        if capsule.ast_hash != exp {
            return Err(anyhow!(
                "AST Hash mismatch. Expected: {}, Got: {}",
                exp,
                capsule.ast_hash
            ));
        }
    }
    if let Some(exp) = params.expected_wasm_hash {
        if capsule.wasm_hash != exp {
            return Err(anyhow!(
                "WASM Hash mismatch. Expected: {}, Got: {}",
                exp,
                capsule.wasm_hash
            ));
        }
    }

    // 2. Time Validity Check
    if params.now_unix < capsule.meta.not_before_unix
        || params.now_unix > capsule.meta.not_after_unix
    {
        return Err(anyhow!("capsule not valid at this time"));
    }

    // 3. Internal Integrity (WASM Bytes vs Hash)
    // We assume the caller or "Re-Execution Verification" step has verified AST->WASM match if strictly required.
    // Here we MUST verify that `capsule.wasm_bytes` matches `capsule.wasm_hash`.
    let mut hasher = sha2::Sha256::new();
    hasher.update(&capsule.wasm_bytes);
    let actual_wasm_hash = hex::encode(hasher.finalize());
    if actual_wasm_hash != capsule.wasm_hash {
        return Err(anyhow!("WASM hash mismatch! Integrity compromised."));
    }

    // 4. Execute
    let runtime = EiaaRuntime::new()?;
    let output = runtime.execute(&capsule.wasm_bytes, &capsule.wasm_hash, params.input_ctx)?;

    // 4. Attest
    // We need to construct the Decision struct for Attestation.
    // Attestation crate usually expects `Decision` enum.
    // Our output.decision is i32 (1=Allow, 0=Deny).
    // Let's coerce.
    let allow = output.decision == 1;

    // AttestationBody now implies new fields (ast_hash, wasm_hash).
    // We need to update `attestation` crate to support these.
    // For now, we will pack them into available fields or update the crate in next step.
    // Let's assume we update attestation crate next.

    // Current AttestationBody in `capsule_runtime` (from existing code)
    let decision_struct = Decision {
        allow,
        reason: None,
    };
    let decision_hash_b64 = attestation::hash_decision(&decision_struct);

    let body = AttestationBody {
        capsule_hash_b64: capsule.wasm_hash.clone(), // Legacy compat
        decision_hash_b64,
        executed_at_unix: params.now_unix,
        expires_at_unix: params.expires_at_unix,
        nonce_b64: params.nonce_b64.to_string(),
        runtime_kid: params.runtime_kid.to_string(),

        ast_hash_b64: capsule.ast_hash.clone(),
        lowering_version: capsule.lowering_version.clone(),
        wasm_hash_b64: capsule.wasm_hash.clone(),
    };

    let att = sign_attestation(body, params.sign_fn)?;

    Ok((output, att))
}

pub use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
pub use wasm_host::DecisionOutput;
pub use wasm_host::RuntimeContext;

pub fn encode_runtime_pk(pk: &ed25519_dalek::VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(pk.as_bytes())
}
