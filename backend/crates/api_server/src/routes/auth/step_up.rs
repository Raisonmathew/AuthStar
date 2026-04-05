use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::extract::Extension;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::Deserialize;
use shared_types::AssuranceLevel;

#[derive(Deserialize)]
pub struct StepUpRequest {
    pub factor_id: String,
    pub code: String,
}

/// Step-up authentication router
/// This route allows provisional sessions to verify a factor and upgrade to full session
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/step-up", post(step_up_session))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth::require_auth_allow_provisional,
        ))
        .with_state(state)
}

async fn step_up_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<StepUpRequest>,
) -> impl IntoResponse {
    // claims.sid is the session_id
    let session_id = &claims.sid;
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    match state
        .user_factor_service
        .verify_factor_for_session(
            user_id.as_str(),
            tenant_id.as_str(),
            session_id.as_str(),
            &payload.factor_id,
            &payload.code,
        )
        .await
    {
        Ok(valid) => {
            if valid {
                // Risk Stabilization: Successful Step-Up (AAL2) clears sticky risks like Phishing
                state
                    .risk_engine
                    .on_successful_auth(user_id.as_str(), AssuranceLevel::AAL2)
                    .await;

                (StatusCode::OK, "Session stepped up").into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "Invalid code or factor").into_response()
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
