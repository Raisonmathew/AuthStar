//! Compliance Report Route (Gap 2-A)
//!
//! ## Endpoints
//!
//! - `GET /api/v1/compliance/report?start=<ISO8601>&end=<ISO8601>`
//!   Returns a signed SOC 2 evidence JSON bundle for the requested date range.
//!
//! - `GET /api/v1/compliance/report/export?start=<ISO8601>&end=<ISO8601>`
//!   Same as above but sets Content-Disposition to trigger a browser download.
//!
//! ## Authorization
//! Requires `compliance:report` EIAA action.
//!
//! ## Bundle format
//! See `services/compliance_export.rs` for the full schema.
//! The `bundle_sig_b64` field contains an Ed25519 signature that an auditor
//! can verify independently against the tenant's public key at
//! `GET /api/v1/compliance/pubkey`.

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::services::compliance_export::ComplianceExportService;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use shared_types::{AppError, Result};

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/compliance/report", get(get_report))
        .route("/compliance/report/export", get(export_report))
        .route("/compliance/pubkey", get(get_pubkey))
}

// ─── Request types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ReportParams {
    /// ISO-8601 start of the reporting period (inclusive).
    pub start: Option<DateTime<Utc>>,
    /// ISO-8601 end of the reporting period (exclusive).
    pub end: Option<DateTime<Utc>>,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/v1/compliance/report`
///
/// Returns the compliance bundle as JSON.
async fn get_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ReportParams>,
) -> Result<impl IntoResponse> {
    let (start, end) = resolve_period(params)?;
    let svc = ComplianceExportService::new(state.db.clone());
    let bundle = svc
        .generate_bundle(&claims.tenant_id, start, end)
        .await
        .map_err(|e| AppError::Internal(format!("compliance report: {e}")))?;
    Ok(Json(bundle))
}

/// `GET /api/v1/compliance/report/export`
///
/// Same bundle but served as a file download (`Content-Disposition: attachment`).
async fn export_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ReportParams>,
) -> Result<impl IntoResponse> {
    let (start, end) = resolve_period(params)?;
    let svc = ComplianceExportService::new(state.db.clone());
    let bundle = svc
        .generate_bundle(&claims.tenant_id, start, end)
        .await
        .map_err(|e| AppError::Internal(format!("compliance export: {e}")))?;

    let filename = format!(
        "authstar-compliance-{}-{}.json",
        start.format("%Y%m%d"),
        end.format("%Y%m%d"),
    );
    let json = serde_json::to_vec_pretty(&bundle)
        .map_err(|e| AppError::Internal(format!("compliance serialize: {e}")))?;

    Ok((
        [
            (
                header::CONTENT_TYPE,
                "application/json".parse::<axum::http::HeaderValue>().unwrap(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\"")
                    .parse::<axum::http::HeaderValue>()
                    .unwrap(),
            ),
        ],
        json,
    ))
}

/// `GET /api/v1/compliance/pubkey`
///
/// Returns the tenant's Ed25519 public key (base64url) so auditors can verify
/// bundle signatures independently.
async fn get_pubkey(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("compliance pubkey: acquire: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("compliance pubkey: RLS: {e}")))?;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::SigningKey;

    let key_bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT key_bytes FROM tenant_signing_keys WHERE tenant_id = $1 AND purpose = 'compliance' LIMIT 1",
    )
    .bind(&claims.tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("compliance pubkey: query: {e}")))?;

    match key_bytes {
        Some(seed) if seed.len() == 32 => {
            let seed_arr: [u8; 32] = seed.try_into().unwrap();
            let signing_key = SigningKey::from_bytes(&seed_arr);
            let verifying_key = signing_key.verifying_key();
            Ok(Json(serde_json::json!({
                "algorithm": "Ed25519",
                "public_key_b64": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
            })))
        }
        _ => Err(AppError::NotFound(
            "No compliance signing key found for this tenant. \
             Run the tenant provisioning step to generate one."
                .into(),
        )),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn resolve_period(
    params: ReportParams,
) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let end = params.end.unwrap_or_else(Utc::now);
    let start = params
        .start
        .unwrap_or_else(|| end - Duration::days(30));

    if start >= end {
        return Err(AppError::Validation(
            "start must be before end".into(),
        ));
    }
    let max_range = Duration::days(366);
    if end - start > max_range {
        return Err(AppError::Validation(
            "Date range must not exceed 366 days. Split into smaller exports.".into(),
        ));
    }
    Ok((start, end))
}
