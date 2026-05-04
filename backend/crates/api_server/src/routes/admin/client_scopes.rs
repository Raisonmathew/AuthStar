use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_scopes).post(create_scope))
        .route("/:name", delete(delete_scope))
        .route(
            "/clients/:client_id/:kind/:scope_name",
            post(assign_scope).delete(unassign_scope),
        )
}

#[derive(Debug, Deserialize)]
struct CreateScopeRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_protocol")]
    protocol: String,
    #[serde(default)]
    include_in_new_clients: bool,
}

fn default_protocol() -> String {
    "oauth2".to_string()
}

async fn list_scopes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::services::ClientScope>>> {
    let scopes = state
        .client_scope_service
        .list_scopes(&claims.tenant_id)
        .await?;
    Ok(Json(scopes))
}

async fn create_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateScopeRequest>,
) -> Result<Json<crate::services::ClientScope>> {
    if req.protocol != "oauth2" {
        return Err(AppError::BadRequest(
            "Only oauth2 client scopes are supported".into(),
        ));
    }
    let scope = state
        .client_scope_service
        .create_scope(
            &claims.tenant_id,
            &req.name,
            req.description.as_deref(),
            req.include_in_new_clients,
        )
        .await?;
    Ok(Json(scope))
}

async fn delete_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    state
        .client_scope_service
        .delete_scope(&claims.tenant_id, &name)
        .await?;
    Ok(Json(serde_json::json!({"status": "deleted"})))
}

async fn assign_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((client_id, kind, scope_name)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let kind = parse_kind(&kind)?;
    state
        .client_scope_service
        .assign(&claims.tenant_id, &client_id, &scope_name, kind)
        .await?;
    Ok(Json(serde_json::json!({"status": "assigned"})))
}

async fn unassign_scope(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((client_id, _kind, scope_name)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    state
        .client_scope_service
        .unassign(&claims.tenant_id, &client_id, &scope_name)
        .await?;
    Ok(Json(serde_json::json!({"status": "unassigned"})))
}

fn parse_kind(kind: &str) -> Result<crate::services::ScopeKind> {
    match kind {
        "default" => Ok(crate::services::ScopeKind::Default),
        "optional" => Ok(crate::services::ScopeKind::Optional),
        other => Err(AppError::BadRequest(format!(
            "Invalid client-scope mapping kind: {other}"
        ))),
    }
}
