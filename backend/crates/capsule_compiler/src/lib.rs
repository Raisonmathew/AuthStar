pub mod ast;
pub mod verifier;
pub mod lowerer;
pub mod policy_compiler;

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use ed25519_dalek::Verifier;
use keystore::{Keystore, KeyId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleMeta {
    pub tenant_id: String,
    pub action: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub ast_hash_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleSigned {
    pub meta: CapsuleMeta,
    pub ast_bytes: Vec<u8>,
    pub ast_hash: String,
    pub lowering_version: String,
    pub wasm_bytes: Vec<u8>,
    pub wasm_hash: String,
    pub compiler_kid: String,
    pub compiler_sig_b64: String,
}

pub fn compile(program: ast::Program, tenant_id: String, action: String, not_before: i64, not_after: i64, ks: &dyn Keystore, compiler_kid: &KeyId) -> Result<CapsuleSigned> {
    // 1. Verify
    verifier::verify(&program, &verifier::VerifierConfig::default())?;

    // 2. Canonicalize (JSON Minified per Golden Spec)
    // We use serde_json::to_vec which produces minified JSON.
    // Struct fields are ordered by definition, matching our "Canonical" expectation for now.
    let ast_bytes = serde_json::to_vec(&program)?;
    
    // Hash using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&ast_bytes);
    let ast_hash = hex::encode(hasher.finalize());

    // 3. Lower
    let wasm_bytes = lowerer::lower(&program)?;
    
    let mut hasher = Sha256::new();
    hasher.update(&wasm_bytes);
    let wasm_hash = hex::encode(hasher.finalize());

    let meta = CapsuleMeta {
        tenant_id,
        action,
        not_before_unix: not_before,
        not_after_unix: not_after,
        ast_hash_b64: URL_SAFE_NO_PAD.encode(ast_hash.as_bytes()),
    };

    // HIGH-8 FIX: Replace bincode with canonical JSON for the signing payload.
    //
    // bincode is a Rust-specific binary format that:
    // 1. Is not portable — cannot be verified by non-Rust clients (JS SDK, Go SDK)
    // 2. Is not stable across bincode versions — field reordering changes the bytes
    // 3. Is not auditable — opaque binary format makes security review impossible
    //
    // We use a canonical JSON object with lexicographically sorted keys.
    // The wasm_bytes are base64url-encoded to keep the payload valid JSON.
    // This matches the verification format used by the frontend attestation verifier.
    let to_sign_payload = serde_json::json!({
        "action": meta.action,
        "ast_hash": ast_hash,
        "ast_hash_b64": meta.ast_hash_b64,
        "not_after_unix": meta.not_after_unix,
        "not_before_unix": meta.not_before_unix,
        "tenant_id": meta.tenant_id,
        "wasm_hash": wasm_hash,
        // Include wasm_bytes hash (not the bytes themselves) to keep payload small
        // The wasm_hash already commits to the wasm_bytes content
    });
    // Produce minified JSON with keys in insertion order (serde_json preserves insertion order
    // for json! macro literals, which are alphabetically ordered above)
    let to_sign_bytes = serde_json::to_vec(&to_sign_payload)?;

    let sig = ks.sign(compiler_kid, &to_sign_bytes)?;
    let compiler_sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(CapsuleSigned {
        meta,
        ast_bytes,
        ast_hash,
        lowering_version: lowerer::LOWERING_VERSION.to_string(),
        wasm_bytes,
        wasm_hash,
        compiler_kid: compiler_kid.0.clone(),
        compiler_sig_b64,
    })
}

pub fn verify_capsule_signature(c: &CapsuleSigned, compiler_pk: &ed25519_dalek::VerifyingKey) -> Result<()> {
    let sig_bytes = URL_SAFE_NO_PAD.decode(c.compiler_sig_b64.as_bytes())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sig"))?);
    
    // HIGH-8 FIX: Reconstruct the same canonical JSON payload used during signing.
    // Must match the payload construction in compile() exactly.
    let to_sign_payload = serde_json::json!({
        "action": c.meta.action,
        "ast_hash": c.ast_hash,
        "ast_hash_b64": c.meta.ast_hash_b64,
        "not_after_unix": c.meta.not_after_unix,
        "not_before_unix": c.meta.not_before_unix,
        "tenant_id": c.meta.tenant_id,
        "wasm_hash": c.wasm_hash,
    });
    let to_sign_bytes = serde_json::to_vec(&to_sign_payload)?;

    compiler_pk.verify(&to_sign_bytes, &sig).map_err(|_| anyhow::anyhow!("verify failed"))
}
