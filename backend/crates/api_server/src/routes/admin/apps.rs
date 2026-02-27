use axum::{
    Router, 
    routing::get, 
    extract::State, 
    Json,
    http::HeaderMap,
};
use crate::state::AppState;
use org_manager::models::CreateAppRequest;
use serde::Serialize;
use shared_types::{Result, AppError};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_apps).post(create_app))
        .route("/:id", axum::routing::put(update_app))
}

use org_manager::models::UpdateAppRequest; 

#[derive(Serialize)]
struct CreateAppResponse {
    app: org_manager::models::Application,
    client_secret: String,
}

/// Extract tenant_id from Authorization header
async fn extract_tenant_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".into()))?;

    let claims = state.jwt_service.verify_token(token)?;
    Ok(claims.tenant_id)
}

async fn list_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<org_manager::models::Application>>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;
    let apps = state.app_service.list_apps(&tenant_id).await?;
    Ok(Json(apps))
}

async fn create_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppRequest>,
) -> Result<Json<CreateAppResponse>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;
    let (app, client_secret) = state.app_service.create_app(&tenant_id, req).await?;
    Ok(Json(CreateAppResponse { app, client_secret }))
}

async fn update_app(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateAppRequest>,
) -> Result<Json<org_manager::models::Application>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;
    let app = state.app_service.update_app(&tenant_id, &id, req).await?;
    Ok(Json(app))
}
