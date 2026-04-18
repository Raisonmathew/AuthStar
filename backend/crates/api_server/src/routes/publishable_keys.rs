use crate::middleware::AuthenticatedUser;
use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::services::publishable_key_service::{
    CreatePublishableKeyParams, PublishableKeyItem, PublishableKeyResponse,
};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_publishable_keys).post(create_publishable_key))
        .route("/:id", delete(revoke_publishable_key))
}

async fn list_publishable_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<PublishableKeyItem>>> {
    let keys = state
        .publishable_key_service
        .list(&user.tenant_id)
        .await?;
    Ok(Json(keys))
}

async fn create_publishable_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(params): Json<CreatePublishableKeyParams>,
) -> Result<Json<PublishableKeyResponse>> {
    let response = state
        .publishable_key_service
        .create(&user.tenant_id, &params)
        .await?;
    state.audit_event_service.record(RecordEventParams {
        tenant_id: user.tenant_id.clone(),
        event_type: event_types::PUBLISHABLE_KEY_CREATED,
        actor_id: Some(user.user_id.clone()),
        actor_email: None,
        target_type: Some("publishable_key"),
        target_id: Some(response.id.clone()),
        ip_address: None,
        user_agent: None,
        metadata: serde_json::json!({"environment": params.environment}),
    }).await;
    Ok(Json(response))
}

async fn revoke_publishable_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    state
        .publishable_key_service
        .revoke(&key_id, &user.tenant_id)
        .await?;
    state.audit_event_service.record(RecordEventParams {
        tenant_id: user.tenant_id.clone(),
        event_type: event_types::PUBLISHABLE_KEY_REVOKED,
        actor_id: Some(user.user_id.clone()),
        actor_email: None,
        target_type: Some("publishable_key"),
        target_id: Some(key_id.clone()),
        ip_address: None,
        user_agent: None,
        metadata: serde_json::json!({}),
    }).await;
    Ok(Json(serde_json::json!({ "revoked": true })))
}
