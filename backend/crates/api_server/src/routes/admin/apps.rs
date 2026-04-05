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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_apps).post(create_app))
        .route("/:id", axum::routing::put(update_app).delete(delete_app))
}

#[derive(Serialize)]
struct CreateAppResponse {
    app: org_manager::models::Application,
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
) -> Result<Json<Vec<org_manager::models::Application>>> {
    let apps = state.app_service.list_apps(&claims.tenant_id).await?;
    Ok(Json(apps))
}

async fn create_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateAppRequest>,
) -> Result<Json<CreateAppResponse>> {
    let (app, client_secret) = state.app_service.create_app(&claims.tenant_id, req).await?;
    Ok(Json(CreateAppResponse { app, client_secret }))
}

async fn update_app(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAppRequest>,
) -> Result<Json<org_manager::models::Application>> {
    let app = state
        .app_service
        .update_app(&claims.tenant_id, &id, req)
        .await?;
    Ok(Json(app))
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
