pub mod wasm_host;

use anyhow::{anyhow, Result};
use attestation::{sign_attestation, Attestation, AttestationBody, Decision};
use capsule_compiler::CapsuleSigned;

use crate::wasm_host::EiaaRuntime;
use sha2::Digest; // Required for Sha256's .update() and .finalize() methods

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
    let capsule = params.capsule;
    // 1. Integrity Check (Inputs vs Expected)
    if let Some(exp) = params.expected_ast_hash {
        if capsule.ast_hash != exp {
            return Err(anyhow!("AST Hash mismatch. Expected: {}, Got: {}", exp, capsule.ast_hash));
        }
    }
    if let Some(exp) = params.expected_wasm_hash {
        if capsule.wasm_hash != exp {
            return Err(anyhow!("WASM Hash mismatch. Expected: {}, Got: {}", exp, capsule.wasm_hash));
        }
    }

    // 2. Time Validity Check
    if params.now_unix < capsule.meta.not_before_unix || params.now_unix > capsule.meta.not_after_unix {
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
    let decision_struct = Decision { allow, reason: None };
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

pub use wasm_host::DecisionOutput;
pub use wasm_host::RuntimeContext;
pub use base64::engine::general_purpose::URL_SAFE_NO_PAD; 
use base64::Engine;

pub fn encode_runtime_pk(pk: &ed25519_dalek::VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(pk.as_bytes())
}
