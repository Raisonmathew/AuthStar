use crate::middleware::AuthenticatedUser;
use crate::services::api_key_service::{ApiKeyListItem, CreateApiKeyParams, CreateApiKeyResponse};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use shared_types::Result;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_api_keys).post(create_api_key))
        .route("/:id", delete(revoke_api_key))
}

async fn list_api_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ApiKeyListItem>>> {
    let keys = state
        .api_key_service
        .list(user.user_id, user.tenant_id)
        .await?;
    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(params): Json<CreateApiKeyParams>,
) -> Result<Json<CreateApiKeyResponse>> {
    let response = state
        .api_key_service
        .create(user.user_id, user.tenant_id, &params)
        .await?;
    Ok(Json(response))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    state
        .api_key_service
        .revoke(key_id, user.user_id, user.tenant_id)
        .await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}
