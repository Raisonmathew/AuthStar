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
    let mut challenge = state
        .required_action_service
        .challenge(&claims.tenant_id, &claims.sub, &code)
        .await?;
    if code == "verify_email" {
        if let (Some(email), Some(delivery_code)) = (
            challenge
                .metadata
                .get("rawIdentifier")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            challenge
                .metadata
                .get("deliveryCode")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        ) {
            let sent = state
                .verification_service
                .send_verification_email(&email, &delivery_code)
                .await
                .is_ok();
            challenge.metadata["sent"] = serde_json::json!(sent);
        }
    }
    if let Some(metadata) = challenge.metadata.as_object_mut() {
        metadata.remove("deliveryCode");
        metadata.remove("rawIdentifier");
    }
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
