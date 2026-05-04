//! User profile management routes
//!
//! Provides endpoints for authenticated users to manage their own profile:
//! - PATCH /api/v1/user — update display name / profile image
//! - POST  /api/v1/user/change-password — change password (requires current password)

use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, State},
    Json,
};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

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
    state
        .user_service
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
    state
        .user_service
        .change_password(&claims.sub, &req.current_password, &req.new_password)
        .await
        .map_err(|e| match e {
            // Surface validation and auth errors directly to the client
            AppError::Validation(_) | AppError::Unauthorized(_) | AppError::BadRequest(_) => e,
            // Wrap unexpected errors
            other => AppError::Internal(format!("Password change failed: {other}")),
        })?;

    // LDAP writeback: if the user is federated via a WRITABLE LDAP connection,
    // push the new password to LDAP. Errors are non-fatal (logged as warnings).
    {
        let fed = sqlx::query_as::<_, (String, String, String, String, bool, bool, i32, bool, i32, String)>(
            "SELECT lc.host, lc.bind_dn, lc.bind_password_ref, lfu.ldap_dn, \
                    lc.use_ssl, lc.start_tls, lc.connection_timeout_secs, lc.skip_tls_verify, \
                    lc.read_timeout_secs, lc.failover_hosts \
             FROM ldap_federated_users lfu \
             INNER JOIN ldap_connections lc ON lc.id = lfu.connection_id \
             WHERE lfu.user_id = $1 AND lc.enabled = true AND lc.edit_mode = 'WRITABLE' \
             LIMIT 1",
        )
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

        if let Some((host, bind_dn, enc_pw, user_dn, use_ssl, start_tls, timeout, skip_tls_verify, read_timeout, failover_str)) = fed {
            let port = if use_ssl { 636i32 } else { 389i32 };
            let fallback_hosts: Vec<&str> = failover_str
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            match state.ldap_encryption.decrypt(&enc_pw) {
                Ok(bind_pw) => {
                    match crate::services::ldap_client::write_user_password(
                        &host,
                        port,
                        use_ssl,
                        start_tls,
                        skip_tls_verify,
                        &bind_dn,
                        &bind_pw,
                        &user_dn,
                        &req.new_password,
                        timeout.max(3) as u64,
                        read_timeout.max(5) as u64,
                        &fallback_hosts,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!(user_id = %claims.sub, "LDAP password writeback succeeded");
                            state.audit_event_service.record(RecordEventParams {
                                tenant_id: claims.tenant_id.clone(),
                                event_type: event_types::LDAP_USER_IMPORTED,
                                actor_id: Some(claims.sub.clone()),
                                actor_email: None,
                                target_type: Some("user"),
                                target_id: Some(claims.sub.clone()),
                                ip_address: None,
                                user_agent: None,
                                metadata: serde_json::json!({"action": "password_writeback"}),
                            }).await;
                        }
                        Err(e) => {
                            tracing::warn!(user_id = %claims.sub, error = e, "LDAP password writeback failed (non-fatal)");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(user_id = %claims.sub, error = e, "LDAP writeback: failed to decrypt bind password");
                }
            }
        }
    }

    // Invalidate all other sessions after a password change.
    // This forces re-login on other devices — prevents a compromised session
    // from remaining valid after the user secures their account.
    let invalidated = state
        .user_service
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
