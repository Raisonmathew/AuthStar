use axum::{
    routing::{get, post, delete},
    Router,
    Json,
    extract::{State, Path, Extension},
    http::StatusCode,
    response::IntoResponse,
};
use auth_core::jwt::Claims;
use crate::state::AppState;
use crate::services::user_factor_service::UserFactor;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub factor_type: String, // "totp" or "passkey"
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub factor_id: String,
    pub secret: String, // For TOTP: secret key, For Passkey: challenge
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
) -> impl IntoResponse {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    if payload.factor_type == "passkey" {
        return (StatusCode::BAD_REQUEST, "Use /api/passkeys/register for passkey enrollment").into_response();
    }

    match state.user_factor_service.initiate_enrollment(user_id, tenant_id, &payload.factor_type).await {
        Ok((factor_id, secret)) => {
            // Generate real QR code for TOTP enrollment
            let qr_code = if payload.factor_type == "totp" {
                let totp_uri = format!(
                    "otpauth://totp/IDaaS:{}?secret={}&issuer=IDaaS&algorithm=SHA1&digits=6&period=30",
                    user_id, secret
                );
                match generate_qr_code_base64(&totp_uri) {
                    Ok(png_b64) => Some(format!("data:image/png;base64,{}", png_b64)),
                    Err(e) => {
                        tracing::warn!("QR code generation failed: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            (StatusCode::OK, Json(EnrollResponse {
                factor_id,
                secret,
                qr_code,
            })).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}

/// Verify enrollment (Activate factor)
async fn verify_enrollment(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<VerifyRequest>,
) -> impl IntoResponse {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    if payload.code.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing verification code").into_response();
    }

    match state.user_factor_service.verify_enrollment(user_id, tenant_id, &payload.factor_id, &payload.code).await {
        Ok(valid) => {
            if valid {
                (StatusCode::OK, "Factor verified and activated").into_response()
            } else {
                (StatusCode::BAD_REQUEST, "Invalid code").into_response()
            }
        },
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response()
    }
}

/// List enrolled factors
async fn list_factors(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    match state.user_factor_service.list_factors(user_id, tenant_id).await {
        Ok(factors) => (StatusCode::OK, Json(factors)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}

/// Delete factor
async fn delete_factor(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(factor_id): Path<String>,
) -> impl IntoResponse {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    match state.user_factor_service.delete_factor(user_id, tenant_id, &factor_id).await {
        Ok(_) => (StatusCode::OK, "Factor deleted").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}

/// Generate a QR code as a base64-encoded PNG string
fn generate_qr_code_base64(data: &str) -> Result<String, String> {
    use qrcode::QrCode;
    use image::Luma;

    let code = QrCode::new(data.as_bytes())
        .map_err(|e| format!("QR encode error: {}", e))?;

    let image = code.render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(200, 200)
        .build();

    let mut png_bytes: Vec<u8> = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    image::ImageEncoder::write_image(
        encoder,
        image.as_raw(),
        image.width(),
        image.height(),
        image::ExtendedColorType::L8,
    ).map_err(|e| format!("PNG encode error: {}", e))?;

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&png_bytes))
}
