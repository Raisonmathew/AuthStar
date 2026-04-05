use crate::state::AppState;
use attestation::{
    hash_decision, verify_attestation, Attestation as ExecAttestation, Decision as ExecDecision,
};
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, State},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use capsule_compiler::CapsuleSigned as CompiledCapsule;
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use grpc_api::eiaa::runtime::{CapsuleMeta as RpcMeta, CapsuleSigned as RpcCapsule};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json as json;
use sha2::{Digest, Sha256};
use shared_types::id_generator;

pub fn manage_router() -> Router<AppState> {
    Router::new()
        .route("/capsules/compile", post(compile_capsule))
        .route("/execute", post(execute_capsule))
        .route("/verify", post(verify_artifact))
}

pub fn runtime_keys_router() -> Router<AppState> {
    Router::new().route("/runtime/keys", get(get_runtime_keys))
}

#[derive(Deserialize, Debug)]
pub struct CapsuleSpec {
    pub program: capsule_compiler::ast::Program,
    pub tenant_id: String,
    pub action: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

fn hex_to_b64(hex: &str) -> String {
    let bytes = hex::decode(hex).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(&bytes)
}

#[tracing::instrument(skip(state, claims), fields(user_id = %claims.sub, tenant_id = %claims.tenant_id))]
async fn compile_capsule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(spec): Json<CapsuleSpec>,
) -> Result<Json<CompiledCapsule>, (axum::http::StatusCode, String)> {
    // SECURITY: Validate tenant_id
    if spec.tenant_id != claims.tenant_id {
        tracing::warn!(
            "Tenant ID mismatch: claims.tenant_id={}, spec.tenant_id={}",
            claims.tenant_id,
            spec.tenant_id
        );
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "Tenant ID mismatch".into(),
        ));
    }

    let signed = capsule_compiler::compile(
        spec.program,
        spec.tenant_id,
        spec.action,
        spec.not_before_unix,
        spec.not_after_unix,
        &state.ks,
        &state.compiler_kid,
    )
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("compile: {e}"),
        )
    })?;

    // Persist capsule
    let meta_json = json::to_value(&signed.meta).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("meta json: {e}"),
        )
    })?;

    let policy_hash_b64 = signed.meta.ast_hash_b64.clone();
    let capsule_hash_b64 = hex_to_b64(&signed.wasm_hash);

    sqlx::query(
        r#"
        INSERT INTO eiaa_capsules
            (tenant_id, action, policy_version, meta, policy_hash_b64, capsule_hash_b64,
             compiler_kid, compiler_sig_b64, wasm_bytes, ast_bytes)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (capsule_hash_b64) DO UPDATE
            SET wasm_bytes = EXCLUDED.wasm_bytes,
                ast_bytes  = EXCLUDED.ast_bytes
        "#,
    )
    .bind(&signed.meta.tenant_id)
    .bind(&signed.meta.action)
    .bind(1_i32)
    .bind(meta_json)
    .bind(&policy_hash_b64)
    .bind(&capsule_hash_b64)
    .bind(&signed.compiler_kid)
    .bind(&signed.compiler_sig_b64)
    .bind(&signed.wasm_bytes)
    .bind(&signed.ast_bytes)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist capsule: {e}"),
        )
    })?;

    tracing::info!(capsule_hash = %capsule_hash_b64, "Capsule compiled and persisted");

    Ok(Json(signed))
}

#[derive(Deserialize)]
struct ExecuteReq {
    capsule: CompiledCapsule,
    input: serde_json::Value,
    expires_at_unix: Option<i64>,
}

#[derive(Serialize)]
struct ExecuteResp {
    decision: ExecDecision,
    attestation: ExecAttestation,
}

#[tracing::instrument(skip(state, req))]
async fn execute_capsule(
    State(state): State<AppState>,
    Json(req): Json<ExecuteReq>,
) -> Result<Json<ExecuteResp>, (axum::http::StatusCode, String)> {
    let now = Utc::now().timestamp();
    let _exp = req.expires_at_unix.unwrap_or(now + 120);
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    let _meta = &req.capsule.meta;
    let wasm_hash_b64 = hex_to_b64(&req.capsule.wasm_hash);
    let _ast_hash_b64 = hex_to_b64(&req.capsule.ast_hash);

    let input_json_str = serde_json::to_string(&req.input)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    let rpc_capsule = RpcCapsule {
        meta: Some(RpcMeta {
            tenant_id: req.capsule.meta.tenant_id.clone(),
            action: req.capsule.meta.action.clone(),
            not_before_unix: req.capsule.meta.not_before_unix,
            not_after_unix: req.capsule.meta.not_after_unix,
            policy_hash_b64: req.capsule.meta.ast_hash_b64.clone(),
        }),
        ast_bytes: req.capsule.ast_bytes.clone(),
        capsule_hash_b64: req.capsule.wasm_hash.clone(),
        compiler_kid: req.capsule.compiler_kid.clone(),
        compiler_sig_b64: req.capsule.compiler_sig_b64.clone(),
        ast_hash_b64: req.capsule.ast_hash.clone(),
        wasm_hash_b64: req.capsule.wasm_hash.clone(),
        lowering_version: req.capsule.lowering_version.clone(),
        wasm_bytes: req.capsule.wasm_bytes.clone(),
    };

    let client = state.runtime_client.clone();
    let resp = client
        .execute_capsule(rpc_capsule, input_json_str, nonce_b64.clone())
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, format!("runtime: {e}")))?;

    let dec = resp.decision.ok_or((
        axum::http::StatusCode::BAD_GATEWAY,
        "missing decision".into(),
    ))?;
    let att = resp.attestation.ok_or((
        axum::http::StatusCode::BAD_GATEWAY,
        "missing attestation".into(),
    ))?;

    let decision = ExecDecision {
        allow: dec.allow,
        reason: if dec.reason.is_empty() {
            None
        } else {
            Some(dec.reason)
        },
    };
    let body = att.body.ok_or((
        axum::http::StatusCode::BAD_GATEWAY,
        "missing attestation body".into(),
    ))?;
    let attestation = ExecAttestation {
        body: attestation::AttestationBody {
            capsule_hash_b64: body.capsule_hash_b64,
            decision_hash_b64: body.decision_hash_b64,
            executed_at_unix: body.executed_at_unix,
            expires_at_unix: body.expires_at_unix,
            nonce_b64: body.nonce_b64,
            runtime_kid: body.runtime_kid,
            ast_hash_b64: body.ast_hash_b64,
            wasm_hash_b64: body.wasm_hash_b64,
            lowering_version: body.lowering_version,
        },
        signature_b64: att.signature_b64,
    };

    // Ensure capsule exists
    let meta_json = json::to_value(&req.capsule.meta).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("meta json: {e}"),
        )
    })?;

    sqlx::query(
        r#"
        INSERT INTO eiaa_capsules
            (tenant_id, action, policy_version, meta, policy_hash_b64, capsule_hash_b64,
             compiler_kid, compiler_sig_b64, wasm_bytes, ast_bytes)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (capsule_hash_b64) DO UPDATE
            SET wasm_bytes = EXCLUDED.wasm_bytes,
                ast_bytes  = EXCLUDED.ast_bytes
        "#,
    )
    .bind(&req.capsule.meta.tenant_id)
    .bind(&req.capsule.meta.action)
    .bind(1_i32)
    .bind(meta_json)
    .bind(&req.capsule.meta.ast_hash_b64)
    .bind(&wasm_hash_b64)
    .bind(&req.capsule.compiler_kid)
    .bind(&req.capsule.compiler_sig_b64)
    .bind(&req.capsule.wasm_bytes)
    .bind(&req.capsule.ast_bytes)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist capsule: {e}"),
        )
    })?;

    // Persist execution record via AuditWriter.
    //
    // C-4 FIX: Store the full `input_context` JSON string alongside `input_digest`.
    // The ReExecutionService needs the full context to replay the capsule execution
    // and verify the decision matches. Without it, re-execution verification is impossible.
    //
    // We serialize `req.input` to a canonical JSON string (minified, deterministic).
    // The `input_digest` is SHA-256 of this string for fast tamper detection.
    let input_context_json = serde_json::to_string(&req.input).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("input json: {e}"),
        )
    })?;

    let input_digest = {
        let mut hasher = Sha256::new();
        hasher.update(input_context_json.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    };

    let attestation_hash_b64 = {
        let body_json = serde_json::to_vec(&attestation.body).map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("attestation body json: {e}"),
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&body_json);
        Some(URL_SAFE_NO_PAD.encode(hasher.finalize()))
    };

    let decision_ref = id_generator::generate_id("dec");
    state
        .audit_writer
        .record(crate::services::audit_writer::AuditRecord {
            decision_ref,
            capsule_hash_b64: wasm_hash_b64.clone(),
            capsule_version: "1.0".to_string(),
            action: req.capsule.meta.action.clone(),
            tenant_id: req.capsule.meta.tenant_id.clone(),
            input_digest,
            // C-4 FIX: Store full input context for re-execution verification.
            input_context: Some(input_context_json),
            nonce_b64: attestation.body.nonce_b64.clone(),
            decision: crate::services::audit_writer::AuditDecision {
                allow: decision.allow,
                reason: decision.reason.clone(),
            },
            attestation_signature_b64: attestation.signature_b64.clone(),
            attestation_timestamp: Utc::now(),
            attestation_hash_b64,
            user_id: None,
        });

    tracing::info!(decision_allow = %decision.allow, "Capsule executed and attestation persisted");

    Ok(Json(ExecuteResp {
        decision,
        attestation,
    }))
}

#[derive(Deserialize)]
struct VerifyReq {
    decision: ExecDecision,
    attestation: ExecAttestation,
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
}

#[tracing::instrument(skip(state, req))]
async fn verify_artifact(
    State(state): State<AppState>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (axum::http::StatusCode, String)> {
    let client = state.runtime_client.clone();
    let keys = client.get_public_keys().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("runtime keys: {e}"),
        )
    })?;
    let mut map = std::collections::HashMap::new();
    for (kid, pk_b64) in keys {
        let bytes = URL_SAFE_NO_PAD
            .decode(pk_b64.as_bytes())
            .map_err(|_| (axum::http::StatusCode::BAD_GATEWAY, "bad pk".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| (axum::http::StatusCode::BAD_GATEWAY, "pk len".into()))?;
        let pk = VerifyingKey::from_bytes(&arr)
            .map_err(|_| (axum::http::StatusCode::BAD_GATEWAY, "pk invalid".into()))?;
        map.insert(kid, pk);
    }
    let lookup = |kid: &str| map.get(kid).cloned();

    let expected = hash_decision(&req.decision);
    if expected != req.attestation.body.decision_hash_b64 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "decision hash mismatch".into(),
        ));
    }

    verify_attestation(
        &attestation::Attestation {
            body: req.attestation.body.clone(),
            signature_b64: req.attestation.signature_b64.clone(),
        },
        &lookup,
        Utc::now(),
    )
    .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, format!("verify: {e}")))?;

    tracing::info!("Artifact verification successful");

    Ok(Json(VerifyResp { valid: true }))
}

#[derive(Serialize)]
struct RuntimeKey {
    kid: String,
    pk_b64: String,
}

async fn get_runtime_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<RuntimeKey>>, (axum::http::StatusCode, String)> {
    let client = state.runtime_client.clone();
    let keys_vec = client.get_public_keys().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("runtime keys: {e}"),
        )
    })?;
    let keys = keys_vec
        .into_iter()
        .map(|(kid, pk_b64)| RuntimeKey { kid, pk_b64 })
        .collect::<Vec<_>>();
    Ok(Json(keys))
}
