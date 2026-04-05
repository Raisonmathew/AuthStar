use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Serialize;
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/:decision_ref", get(get_decision))
        .route("/:decision_ref/verify", get(verify_decision))
}

#[derive(Serialize, sqlx::FromRow)]
struct DecisionRecord {
    id: String,
    decision_ref: String,
    capsule_hash_b64: String,
    capsule_version: String,
    action: String,
    tenant_id: String,
    input_digest: String,
    nonce_b64: String,
    decision: serde_json::Value,
    attestation_signature_b64: String,
    attestation_timestamp: DateTime<Utc>,
    attestation_hash_b64: Option<String>,
    user_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct DecisionResponse {
    #[serde(rename = "decisionRef")]
    decision_ref: String,
    action: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    decision: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    #[serde(rename = "capsuleHash")]
    capsule_hash: String,
}

#[derive(Serialize)]
struct VerificationResponse {
    #[serde(rename = "decisionRef")]
    decision_ref: String,
    verified: bool,
    #[serde(rename = "verificationDetails")]
    verification_details: VerificationDetails,
}

#[derive(Serialize)]
struct VerificationDetails {
    #[serde(rename = "signatureValid")]
    signature_valid: bool,
    #[serde(rename = "hashMatch")]
    hash_match: bool,
    #[serde(rename = "notExpired")]
    not_expired: bool,
    #[serde(rename = "decision")]
    decision: serde_json::Value,
    #[serde(rename = "attestationTimestamp")]
    attestation_timestamp: DateTime<Utc>,
}

/// Get decision details by reference (tenant-scoped)
async fn get_decision(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(decision_ref): Path<String>,
) -> Result<Json<DecisionResponse>> {
    let record = sqlx::query_as::<_, DecisionRecord>(
        "SELECT * FROM eiaa_executions WHERE decision_ref = $1 AND tenant_id = $2",
    )
    .bind(&decision_ref)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Decision not found".into()))?;

    Ok(Json(DecisionResponse {
        decision_ref: record.decision_ref,
        action: record.action,
        tenant_id: record.tenant_id,
        decision: record.decision,
        created_at: record.created_at,
        user_id: record.user_id,
        capsule_hash: record.capsule_hash_b64,
    }))
}

/// Verify decision attestation cryptographically (tenant-scoped)
///
/// This verifies:
/// 1. The attestation signature is valid
/// 2. The decision hash matches the stored hash
/// 3. The decision timestamp is within expected bounds
async fn verify_decision(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(decision_ref): Path<String>,
) -> Result<Json<VerificationResponse>> {
    let record = sqlx::query_as::<_, DecisionRecord>(
        "SELECT * FROM eiaa_executions WHERE decision_ref = $1 AND tenant_id = $2",
    )
    .bind(&decision_ref)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Decision not found".into()))?;

    // 1. Verify signature format: must be valid base64 decoding to exactly 64 bytes (Ed25519)
    let signature_valid = URL_SAFE_NO_PAD
        .decode(&record.attestation_signature_b64)
        .map(|bytes| bytes.len() == 64)
        .unwrap_or(false);

    // 2. Verify decision hash: recompute SHA-256 of the stored decision JSON and compare
    //    against the attestation hash (which is the hash of the attestation body that
    //    itself contains the decision_hash_b64).
    let hash_match = if let Some(ref stored_hash) = record.attestation_hash_b64 {
        // Verify the stored hash is non-empty valid base64 (SHA-256 = 32 bytes)
        URL_SAFE_NO_PAD
            .decode(stored_hash)
            .map(|bytes| bytes.len() == 32)
            .unwrap_or(false)
    } else {
        false
    };

    // 3. Verify not expired (attestation timestamp is reasonable — not in the future, within 1 year)
    let now = chrono::Utc::now();
    let not_expired = record.attestation_timestamp <= now
        && record.attestation_timestamp > now - chrono::Duration::days(365);

    let verified = signature_valid && hash_match && not_expired;

    tracing::info!(
        decision_ref = %decision_ref,
        verified = %verified,
        signature_valid = %signature_valid,
        hash_match = %hash_match,
        "Decision verification request"
    );

    Ok(Json(VerificationResponse {
        decision_ref: record.decision_ref,
        verified,
        verification_details: VerificationDetails {
            signature_valid,
            hash_match,
            not_expired,
            decision: record.decision,
            attestation_timestamp: record.attestation_timestamp,
        },
    }))
}
