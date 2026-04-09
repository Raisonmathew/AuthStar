use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{extract::State, routing::post, Extension, Json, Router};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/totp/setup", post(setup_totp))
        .route("/totp/verify", post(verify_totp_setup))
        .route("/totp/challenge", post(challenge_totp))
        .route("/backup-codes", post(get_backup_codes))
        .route("/backup-codes/verify", post(verify_backup_code))
        .route("/status", axum::routing::get(mfa_status))
        .route("/disable", post(disable_mfa))
}

// --- Request/Response Types ---

#[derive(Deserialize)]
struct VerifyCodeRequest {
    code: String,
}

#[derive(Serialize)]
struct SetupResponse {
    secret: String,
    #[serde(rename = "qrCodeUri")]
    qr_code_uri: String,
    #[serde(rename = "manualEntryKey")]
    manual_entry_key: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct BackupCodesResponse {
    codes: Vec<String>,
    count: usize,
    #[serde(rename = "remainingCodes")]
    remaining_codes: i64,
}

#[derive(Serialize)]
struct MfaStatusResponse {
    #[serde(rename = "totpEnabled")]
    totp_enabled: bool,
    #[serde(rename = "backupCodesEnabled")]
    backup_codes_enabled: bool,
    #[serde(rename = "backupCodesRemaining")]
    backup_codes_remaining: i64,
}

// --- Route Handlers ---

/// Setup TOTP - Returns secret and QR code for authenticator app
async fn setup_totp(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<SetupResponse>> {
    // NEW-5 FIX: Fetch the user's email from the identities table.
    //
    // The `User` model has no `email` field — email is stored in the `identities`
    // table (type = 'email'). We query it directly rather than calling
    // `to_user_response()` which would run 3 extra queries (phone, MFA status)
    // that we don't need here.
    //
    // This email is used as the account label in the TOTP QR code URI
    // (e.g., "otpauth://totp/IDaaS:user@example.com?secret=...").
    // The old code incorrectly used `user.first_name`, which displayed the
    // user's name instead of their email in authenticator apps.
    let email: Option<String> = sqlx::query_scalar(
        "SELECT identifier FROM identities WHERE user_id = $1 AND type = 'email' LIMIT 1",
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch user email: {e}")))?;

    let account_label = email.unwrap_or_else(|| claims.sub.clone());

    let result = state
        .mfa_service
        .setup_totp(&claims.sub, &account_label)
        .await?;

    Ok(Json(SetupResponse {
        secret: result.secret,
        qr_code_uri: result.qr_code_uri,
        manual_entry_key: result.manual_entry_key,
    }))
}

/// Verify TOTP setup - Validates first code and enables MFA
async fn verify_totp_setup(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<VerifyResponse>> {
    let is_valid = state
        .mfa_service
        .verify_and_enable_totp(&claims.sub, &req.code)
        .await?;

    if is_valid {
        Ok(Json(VerifyResponse {
            success: true,
            message: "TOTP successfully enabled. Backup codes have been generated.".to_string(),
        }))
    } else {
        Err(AppError::Unauthorized("Invalid TOTP code".to_string()))
    }
}

/// Challenge TOTP during login
async fn challenge_totp(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<VerifyResponse>> {
    let is_valid = state
        .mfa_service
        .verify_totp(&claims.sub, &req.code)
        .await?;

    if is_valid {
        Ok(Json(VerifyResponse {
            success: true,
            message: "TOTP verified successfully".to_string(),
        }))
    } else {
        Err(AppError::Unauthorized("Invalid TOTP code".to_string()))
    }
}

/// Get backup codes (regenerates them)
async fn get_backup_codes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<BackupCodesResponse>> {
    let result = state.mfa_service.generate_backup_codes(&claims.sub).await?;

    Ok(Json(BackupCodesResponse {
        codes: result.codes,
        count: result.count,
        remaining_codes: result.count as i64,
    }))
}

/// Verify backup code
async fn verify_backup_code(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<VerifyResponse>> {
    let is_valid = state
        .mfa_service
        .verify_backup_code(&claims.sub, &req.code)
        .await?;

    if is_valid {
        Ok(Json(VerifyResponse {
            success: true,
            message: "Backup code verified and consumed".to_string(),
        }))
    } else {
        Err(AppError::Unauthorized("Invalid backup code".to_string()))
    }
}

/// Get MFA status
async fn mfa_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<MfaStatusResponse>> {
    let totp_enabled = state.mfa_service.is_mfa_enabled(&claims.sub).await?;

    // Get backup codes count
    // Cast to bigint because jsonb_array_length returns int4 but we need i64 on the Rust side.
    let backup_info: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT COALESCE(jsonb_array_length(backup_codes), 0)::bigint
        FROM mfa_factors 
        WHERE user_id = $1 AND type = 'backup_codes' AND enabled = true
        "#,
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await?;

    let backup_codes_remaining = backup_info.map(|(c,)| c).unwrap_or(0);

    Ok(Json(MfaStatusResponse {
        totp_enabled,
        backup_codes_enabled: backup_codes_remaining > 0,
        backup_codes_remaining,
    }))
}

/// Disable MFA
async fn disable_mfa(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<VerifyCodeRequest>,
) -> Result<Json<VerifyResponse>> {
    state
        .mfa_service
        .disable_mfa(&claims.sub, &req.code)
        .await?;

    Ok(Json(VerifyResponse {
        success: true,
        message: "MFA has been disabled".to_string(),
    }))
}
