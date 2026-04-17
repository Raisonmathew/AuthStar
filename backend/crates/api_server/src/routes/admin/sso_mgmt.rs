use crate::middleware::TenantId;
use crate::services::sso_connection_service::{
    CreateConnectionParams, SsoConnection, UpdateConnectionParams,
};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use shared_types::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connections).post(create_connection))
        .route("/:id", get(get_connection).put(update_connection).delete(delete_connection))
        .route("/:id/test", post(test_connection))
        .route("/:id/toggle", put(toggle_connection))
}

async fn list_connections(
    State(state): State<AppState>,
    tenant: TenantId,
) -> Result<Json<Vec<SsoConnection>>, AppError> {
    let connections = state.sso_connection_service.list(tenant.as_str()).await?;
    Ok(Json(connections))
}

async fn create_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Json(payload): Json<CreateConnectionParams>,
) -> Result<Json<SsoConnection>, AppError> {
    let conn = state
        .sso_connection_service
        .create(tenant.as_str(), &payload)
        .await?;
    Ok(Json(conn))
}

async fn get_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<SsoConnection>, AppError> {
    let conn = state
        .sso_connection_service
        .get(&id, tenant.as_str())
        .await?;
    Ok(Json(conn))
}

async fn update_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
    Json(payload): Json<UpdateConnectionParams>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .update(&id, tenant.as_str(), &payload)
        .await?;
    Ok(StatusCode::OK)
}

async fn delete_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .delete(&id, tenant.as_str())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .sso_connection_service
        .test_connection(&id, tenant.as_str())
        .await?;
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
struct ToggleParams {
    enabled: bool,
}

async fn toggle_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
    Json(payload): Json<ToggleParams>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .toggle(&id, tenant.as_str(), payload.enabled)
        .await?;
    Ok(StatusCode::OK)
}
