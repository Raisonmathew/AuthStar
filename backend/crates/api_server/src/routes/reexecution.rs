//! Re-Execution Verification API Routes
//!
//! Provides endpoints for verifying past EIAA authorization decisions.

use axum::{
    extract::{Path, Query, State, Extension},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use auth_core::jwt::Claims;
use shared_types::AppError;
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
) -> Result<Json<VerifyResponse>, AppError> {
    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    let result = service
        .verify_execution(&decision_ref, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("Verification failed: {e}")))?;

    Ok(Json(VerifyResponse { result }))
}

/// Batch verify multiple executions (tenant-scoped)
async fn batch_verify(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(request): Json<BatchVerifyRequest>,
) -> Result<Json<BatchVerifyResponse>, AppError> {
    if request.decision_refs.len() > 100 {
        return Err(AppError::BadRequest("Batch size must be <= 100".into()));
    }

    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    let results = service
        .batch_verify(request.decision_refs, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("Batch verification failed: {e}")))?;

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
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::services::reexecution_service::StoredExecution>>, AppError> {
    let service = ReExecutionService::new(
        state.db.clone(),
        state.runtime_client.clone(),
    );

    // Cap limit to prevent unbounded queries
    let limit = query.limit.min(200);

    let executions = service
        .list_executions(
            &claims.tenant_id,
            query.action.as_deref(),
            limit,
            query.offset,
        )
        .await
        .map_err(|e| AppError::Internal(format!("List executions failed: {e}")))?;

    Ok(Json(executions))
}
