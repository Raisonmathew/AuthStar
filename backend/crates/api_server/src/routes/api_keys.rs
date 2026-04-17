use crate::middleware::api_key_auth::ApiKeyScopes;
use crate::middleware::AuthenticatedUser;
use crate::services::api_key_service::{ApiKeyListItem, CreateApiKeyParams, CreateApiKeyResponse};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Extension, Json, Router,
};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_api_keys).post(create_api_key))
        .route("/:id", delete(revoke_api_key))
}

/// Enforce that an API key request carries the required scope.
/// JWT (human) sessions pass through unconditionally.
fn check_scope(scopes: &Option<ApiKeyScopes>, required: &str) -> Result<()> {
    if let Some(ApiKeyScopes(ref s)) = scopes {
        if !s.iter().any(|v| v == required || v == "*") {
            return Err(AppError::Forbidden(format!(
                "API key missing required scope: {required}"
            )));
        }
    }
    Ok(())
}

async fn list_api_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scopes: Option<Extension<ApiKeyScopes>>,
) -> Result<Json<Vec<ApiKeyListItem>>> {
    check_scope(&scopes.map(|Extension(s)| s), "keys:read")?;
    let keys = state
        .api_key_service
        .list(&user.user_id, &user.tenant_id)
        .await?;
    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scopes: Option<Extension<ApiKeyScopes>>,
    Json(params): Json<CreateApiKeyParams>,
) -> Result<Json<CreateApiKeyResponse>> {
    check_scope(&scopes.map(|Extension(s)| s), "keys:write")?;
    let response = state
        .api_key_service
        .create(&user.user_id, &user.tenant_id, &params)
        .await?;
    Ok(Json(response))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scopes: Option<Extension<ApiKeyScopes>>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    check_scope(&scopes.map(|Extension(s)| s), "keys:write")?;
    state
        .api_key_service
        .revoke(&key_id, &user.user_id, &user.tenant_id)
        .await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}
