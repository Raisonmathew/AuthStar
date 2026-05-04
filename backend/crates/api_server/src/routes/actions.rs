//! Action token consumption route (T1.4).
//!
//! Single endpoint: `POST /api/v1/actions/consume` with body
//! `{ "token": "<jwt>" }`.
//!
//! ## Flow
//!
//! 1. Decode + verify token via `auth_core::verify_action_token`.
//! 2. Replay-check the `jti` via `NonceStore::check_and_mark`.
//! 3. Look up handler in `state.action_handlers`.
//! 4. Dispatch — handler does its own DB work and returns an `ActionOutcome`.
//!
//! ## Rate limiting
//!
//! This endpoint is public (no auth) — apply `rate_limit_public` at the
//! router-mount site to defend against token-bruteforce attempts.
//!
//! ## Security
//!
//! - Token signature, expiry, and audience are validated by `verify_action_token`.
//! - Replay protection is enforced *here* (before handler dispatch).
//! - Errors are deliberately unspecific (no distinguishing "expired" from
//!   "tampered" in the response body) to avoid oracle attacks. Detailed
//!   reasons are still logged.

use auth_core::verify_action_token;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::Deserialize;

use crate::services::action_handlers::ActionContext;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ConsumeActionRequest {
    pub token: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/actions/consume", post(consume_action))
}

async fn consume_action(
    State(state): State<AppState>,
    Json(body): Json<ConsumeActionRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // 1. Crypto-verify (signature, exp, nbf, aud).
    let claims = verify_action_token(&state.jwt_service, &body.token, None).map_err(|e| {
        tracing::warn!(error = %e, "action token verification failed");
        bad_request("invalid_or_expired_token")
    })?;

    // 2. Replay protection — nonce store returns true on first use, false on replay.
    let fresh = state
        .nonce_store
        .check_and_mark(&claims.jti)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "nonce store check failed");
            internal("nonce_store_unavailable")
        })?;
    if !fresh {
        tracing::warn!(jti = %claims.jti, action = claims.act.as_str(), "action token replay detected");
        return Err(bad_request("token_already_used"));
    }

    // 3. Dispatch to registered handler.
    let handler = state.action_handlers.get(claims.act).map_err(|e| {
        tracing::error!(action = claims.act.as_str(), "no handler registered: {e}");
        internal("action_unsupported")
    })?;

    let ctx = ActionContext {
        db: state.db.clone(),
        request_ip: None,
        user_agent: None,
    };
    let outcome = handler.execute(&claims, &ctx).await.map_err(|e| {
        tracing::warn!(action = claims.act.as_str(), error = %e, "action handler failed");
        bad_request("action_failed")
    })?;

    Ok((StatusCode::OK, Json(serde_json::to_value(outcome).unwrap())))
}

fn bad_request(code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": code })),
    )
}

fn internal(code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code })),
    )
}
