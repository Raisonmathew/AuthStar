use crate::middleware::{AuthenticatedUser, TenantId};
use crate::services::audit_event_service::{event_types, RecordEventParams};
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
        .route(
            "/:id",
            get(get_connection)
                .put(update_connection)
                .delete(delete_connection),
        )
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
    user: AuthenticatedUser,
    Json(payload): Json<CreateConnectionParams>,
) -> Result<Json<SsoConnection>, AppError> {
    let conn = state
        .sso_connection_service
        .create(tenant.as_str(), &payload)
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_CREATED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(conn.id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"provider": &payload.provider, "name": &payload.name}),
        })
        .await;
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
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<UpdateConnectionParams>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .update(&id, tenant.as_str(), &payload)
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_UPDATED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;
    Ok(StatusCode::OK)
}

async fn delete_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .delete(&id, tenant.as_str())
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_DELETED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;
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
