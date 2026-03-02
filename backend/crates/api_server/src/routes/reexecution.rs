/**
 * Re-Execution Verification API Routes
 * 
 * Provides endpoints for verifying past EIAA authorization decisions.
 */

use axum::{
    extract::{Path, Query, State, Extension},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use auth_core::jwt::Claims;
use crate::state::AppState;
use crate::services::reexecution_service::{ReExecutionService, ReExecutionResult, VerificationStatus};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/verify/:decision_ref", get(verify_execution))
        .route("/verify/batch", post(batch_verify))
        .route("/history", get(list_executions))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    action: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
pub struct BatchVerifyRequest {
    decision_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub result: ReExecutionResult,
}

#[derive(Debug, Serialize)]
pub struct BatchVerifyResponse {
    pub results: Vec<ReExecutionResult>,
    pub summary: BatchSummary,
}

#[derive(Debug, Serialize)]
pub struct BatchSummary {
    pub total: usize,
    pub verified: usize,
    pub discrepancies: usize,
    pub errors: usize,
}

/// Verify a single past execution (tenant-scoped)
async fn verify_execution(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(decision_ref): Path<String>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    // GAP-1 FIX: pass shared singleton client instead of runtime_addr string
    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    let result = service
        .verify_execution(&decision_ref, &claims.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Verification failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(VerifyResponse { result }))
}

/// Batch verify multiple executions (tenant-scoped)
async fn batch_verify(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(request): Json<BatchVerifyRequest>,
) -> Result<Json<BatchVerifyResponse>, StatusCode> {
    if request.decision_refs.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // GAP-1 FIX: pass shared singleton client instead of runtime_addr string
    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    let results = service
        .batch_verify(request.decision_refs, &claims.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Batch verification failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let summary = BatchSummary {
        total: results.len(),
        verified: results.iter().filter(|r| r.verification_status == VerificationStatus::Verified).count(),
        discrepancies: results.iter().filter(|r| r.verification_status == VerificationStatus::Discrepancy).count(),
        errors: results.iter().filter(|r| {
            matches!(r.verification_status, VerificationStatus::CapsuleNotFound | VerificationStatus::ExecutionError)
        }).count(),
    };

    Ok(Json(BatchVerifyResponse { results, summary }))
}

/// List execution history for audit
async fn list_executions(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    axum::Extension(claims): axum::Extension<auth_core::jwt::Claims>,
) -> Result<Json<Vec<crate::services::reexecution_service::StoredExecution>>, StatusCode> {
    // GAP-1 FIX: pass shared singleton client instead of runtime_addr string
    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    let executions = service
        .list_executions(
            &claims.tenant_id,
            query.action.as_deref(),
            query.limit,
            query.offset,
        )
        .await
        .map_err(|e| {
            tracing::error!("List executions failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(executions))
}
