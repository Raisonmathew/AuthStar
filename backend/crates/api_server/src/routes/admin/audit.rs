use crate::middleware::TenantId;
use crate::services::audit_query_service::{AuditListQuery, StatsResponse};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_executions))
        .route("/stats", get(get_stats))
        .route("/:id", get(get_execution))
}

async fn list_executions(
    State(state): State<AppState>,
    tenant: TenantId,
    Query(params): Query<AuditListQuery>,
) -> Result<Json<serde_json::Value>> {
    let result = state
        .audit_query_service
        .list_executions(tenant.as_str(), &params)
        .await?;
    Ok(Json(serde_json::json!(result)))
}

async fn get_stats(State(state): State<AppState>, tenant: TenantId) -> Result<Json<StatsResponse>> {
    let stats = state.audit_query_service.get_stats(tenant.as_str()).await?;
    Ok(Json(stats))
}

async fn get_execution(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let log = state
        .audit_query_service
        .get_execution(&id, tenant.as_str())
        .await?;
    Ok(Json(log))
}
