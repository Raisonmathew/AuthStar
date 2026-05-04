use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_required_actions))
        .route("/:code/challenge", get(challenge_required_action))
        .route("/:code/complete", post(complete_required_action))
}

#[derive(Debug, Deserialize)]
struct CompleteRequiredActionRequest {
    #[serde(default)]
    payload: serde_json::Value,
}

async fn list_required_actions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::services::RequiredActionRecord>>> {
    let pending = state
        .required_action_service
        .pending_for_user(&claims.tenant_id, &claims.sub)
        .await?;
    Ok(Json(pending))
}

async fn challenge_required_action(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(code): Path<String>,
) -> Result<Json<crate::services::required_actions::ChallengeResponse>> {
    let challenge = state
        .required_action_service
        .challenge(&claims.tenant_id, &claims.sub, &code)
        .await?;
    Ok(Json(challenge))
}

async fn complete_required_action(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(code): Path<String>,
    Json(req): Json<CompleteRequiredActionRequest>,
) -> Result<Json<serde_json::Value>> {
    state
        .required_action_service
        .complete(&claims.tenant_id, &claims.sub, &code, req.payload)
        .await?;
    Ok(Json(serde_json::json!({"status": "completed"})))
}
