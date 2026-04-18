use crate::middleware::TenantId;
use crate::services::audit_event_service::{AuditEventListQuery, AuditEventStats};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_events))
        .route("/stats", get(get_stats))
        .route("/:id", get(get_event))
}

async fn list_events(
    State(state): State<AppState>,
    tenant: TenantId,
    Query(params): Query<AuditEventListQuery>,
) -> Result<Json<serde_json::Value>> {
    let result = state
        .audit_event_service
        .list_events(tenant.as_str(), &params)
        .await?;
    Ok(Json(serde_json::json!(result)))
}

async fn get_stats(
    State(state): State<AppState>,
    tenant: TenantId,
) -> Result<Json<AuditEventStats>> {
    let stats = state.audit_event_service.get_stats(tenant.as_str()).await?;
    Ok(Json(stats))
}

async fn get_event(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let event = state
        .audit_event_service
        .get_event(&id, tenant.as_str())
        .await?;
    Ok(Json(event))
}
