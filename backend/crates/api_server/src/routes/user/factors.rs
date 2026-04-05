use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::AppError;

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub factor_type: String, // "totp" or "passkey"
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub factor_id: String,
    pub secret: String,          // For TOTP: secret key, For Passkey: challenge
    pub qr_code: Option<String>, // Base64 PNG for TOTP
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub factor_id: String,
    pub code: String, // TOTP code or Passkey signature
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/factors/enroll", post(start_enrollment))
        .route("/factors/verify", post(verify_enrollment))
        .route("/factors", get(list_factors))
        .route("/factors/:id", delete(delete_factor))
}

/// Start enrollment (Generate secret)
async fn start_enrollment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    if payload.factor_type == "passkey" {
        return Err(AppError::BadRequest(
            "Use /api/passkeys/register for passkey enrollment".into(),
        ));
    }

    let (factor_id, secret) = state
        .user_factor_service
        .initiate_enrollment(user_id, tenant_id, &payload.factor_type)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Generate real QR code for TOTP enrollment
    let qr_code = if payload.factor_type == "totp" {
        let totp_uri = format!(
            "otpauth://totp/IDaaS:{user_id}?secret={secret}&issuer=IDaaS&algorithm=SHA1&digits=6&period=30"
        );
        match generate_qr_code_base64(&totp_uri) {
            Ok(png_b64) => Some(format!("data:image/png;base64,{png_b64}")),
            Err(e) => {
                tracing::warn!("QR code generation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    Ok(Json(EnrollResponse {
        factor_id,
        secret,
        qr_code,
    }))
}

/// Verify enrollment (Activate factor)
async fn verify_enrollment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    if payload.code.is_empty() {
        return Err(AppError::BadRequest("Missing verification code".into()));
    }

    let valid = state
        .user_factor_service
        .verify_enrollment(user_id, tenant_id, &payload.factor_id, &payload.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    if valid {
        Ok(Json(serde_json::json!({ "status": "verified" })))
    } else {
        Err(AppError::BadRequest("Invalid code".into()))
    }
}

/// List enrolled factors
async fn list_factors(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    let factors = state
        .user_factor_service
        .list_factors(user_id, tenant_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(serde_json::to_value(factors).unwrap_or_default()))
}

/// Delete factor
async fn delete_factor(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(factor_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    state
        .user_factor_service
        .delete_factor(user_id, tenant_id, &factor_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

/// Generate a QR code as a base64-encoded PNG string
fn generate_qr_code_base64(data: &str) -> Result<String, String> {
    use base64::Engine;
    use image::ImageEncoder;
    use image::Luma;
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes()).map_err(|e| format!("QR encode error: {e}"))?;

    let image = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(200, 200)
        .build();

    let mut png_bytes: Vec<u8> = Vec::new();
    // image 0.25: PngEncoder::new() + ImageEncoder::write_image() — bring trait into scope
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::L8,
        )
        .map_err(|e| format!("PNG encode error: {e}"))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&png_bytes))
}
