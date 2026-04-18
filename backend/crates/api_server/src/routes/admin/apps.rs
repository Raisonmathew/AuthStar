use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use org_manager::models::{CreateAppRequest, UpdateAppRequest};
use serde::Serialize;
use shared_types::Result;

#[derive(Serialize)]
struct PublicApplication {
    id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    tenant_id: String,
    name: String,
    r#type: String,
    client_id: String,
    redirect_uris: serde_json::Value,
    allowed_flows: serde_json::Value,
    public_config: serde_json::Value,
    allowed_scopes: serde_json::Value,
    is_first_party: bool,
    token_lifetime_secs: i32,
    refresh_token_lifetime_secs: i32,
}

impl From<org_manager::models::Application> for PublicApplication {
    fn from(app: org_manager::models::Application) -> Self {
        Self {
            id: app.id,
            created_at: app.created_at,
            updated_at: app.updated_at,
            tenant_id: app.tenant_id,
            name: app.name,
            r#type: app.r#type,
            client_id: app.client_id,
            redirect_uris: app.redirect_uris,
            allowed_flows: app.allowed_flows,
            public_config: app.public_config,
            allowed_scopes: app.allowed_scopes,
            is_first_party: app.is_first_party,
            token_lifetime_secs: app.token_lifetime_secs,
            refresh_token_lifetime_secs: app.refresh_token_lifetime_secs,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_apps).post(create_app))
        .route("/:id", axum::routing::put(update_app).delete(delete_app))
        .route("/:id/rotate-secret", axum::routing::post(rotate_app_secret))
}

#[derive(Serialize)]
struct CreateAppResponse {
    app: PublicApplication,
    client_secret: String,
}

#[derive(Serialize)]
struct RotateSecretResponse {
    app: PublicApplication,
    client_secret: String,
}

// GAP-1 FIX: All handlers now use `Extension(claims)` injected by the
// `EiaaAuthzLayer` middleware. This works for both cookie-based browser
// sessions AND explicit `Authorization: Bearer <jwt>` headers.
//
// Previously, `extract_tenant_id` manually parsed the Authorization header,
// which meant browser-based admins (who authenticate via httpOnly cookies)
// were rejected with 401 — rendering the entire Admin UI unusable.

async fn list_apps(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<PublicApplication>>> {
    let apps = state.app_service.list_apps(&claims.tenant_id).await?;
    Ok(Json(
        apps.into_iter().map(PublicApplication::from).collect(),
    ))
}

async fn create_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateAppRequest>,
) -> Result<Json<CreateAppResponse>> {
    let (app, client_secret) = state.app_service.create_app(&claims.tenant_id, req).await?;
    Ok(Json(CreateAppResponse {
        app: app.into(),
        client_secret,
    }))
}

async fn update_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAppRequest>,
) -> Result<Json<PublicApplication>> {
    let app = state
        .app_service
        .update_app(&claims.tenant_id, &id, req)
        .await?;
    Ok(Json(app.into()))
}

/// GAP-1 FIX (BUG-10 backend): Added DELETE endpoint for applications.
/// The frontend AppModal.tsx already calls `DELETE /api/admin/v1/apps/:id`
/// but the backend route was never registered.
async fn delete_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    state.app_service.delete_app(&claims.tenant_id, &id).await?;
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

async fn rotate_app_secret(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<RotateSecretResponse>> {
    let (app, client_secret) = state
        .app_service
        .rotate_secret(&claims.tenant_id, &id)
        .await?;
    Ok(Json(RotateSecretResponse {
        app: app.into(),
        client_secret,
    }))
}
