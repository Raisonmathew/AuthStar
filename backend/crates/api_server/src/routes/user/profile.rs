//! User profile management routes
//!
//! Provides endpoints for authenticated users to manage their own profile:
//! - PATCH /api/v1/user — update display name / profile image
//! - POST  /api/v1/user/change-password — change password (requires current password)

use axum::{Router, routing::{patch, post}, extract::{State, Extension}, Json};
use crate::state::AppState;
use auth_core::jwt::Claims;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

/// Handlers are wired individually in router.rs via `crate::routes::user::profile::*`.
#[allow(dead_code)]
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", patch(update_profile))
        .route("/change-password", post(change_password))
}

// ─── Request / Response Types ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub profile_image_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// PATCH /api/v1/user
///
/// Update the authenticated user's display name and/or profile image.
/// Only fields provided in the request body are updated (COALESCE semantics).
pub async fn update_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<SuccessResponse>> {
    // Delegate to UserService which uses COALESCE for partial updates
    state.user_service
        .update_user(
            &claims.sub,
            req.first_name.as_deref(),
            req.last_name.as_deref(),
            req.profile_image_url.as_deref(),
        )
        .await?;

    tracing::info!(user_id = %claims.sub, "Profile updated");

    Ok(Json(SuccessResponse {
        success: true,
        message: "Profile updated successfully".into(),
    }))
}

/// POST /api/v1/user/change-password
///
/// Change the authenticated user's password.
/// Delegates to UserService.change_password which:
///   1. Validates new password complexity
///   2. Verifies current password (re-authentication guard)
///   3. Checks password history (last 10 passwords cannot be reused)
///   4. Atomically updates passwords table + inserts into password_history
///
/// After a successful change, all other sessions are invalidated to force
/// re-login on other devices — security best practice.
pub async fn change_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<SuccessResponse>> {
    // Delegate all validation, verification, and persistence to UserService
    state.user_service
        .change_password(&claims.sub, &req.current_password, &req.new_password)
        .await
        .map_err(|e| match e {
            // Surface validation and auth errors directly to the client
            AppError::Validation(_) | AppError::Unauthorized(_) | AppError::BadRequest(_) => e,
            // Wrap unexpected errors
            other => AppError::Internal(format!("Password change failed: {other}")),
        })?;

    // Invalidate all other sessions after a password change.
    // This forces re-login on other devices — prevents a compromised session
    // from remaining valid after the user secures their account.
    let invalidated = state.user_service
        .invalidate_other_sessions(&claims.sub, &claims.sid)
        .await
        .unwrap_or(0);

    tracing::info!(
        user_id = %claims.sub,
        session_id = %claims.sid,
        other_sessions_invalidated = invalidated,
        "Password changed — other sessions invalidated"
    );

    Ok(Json(SuccessResponse {
        success: true,
        message: "Password changed successfully".into(),
    }))
}