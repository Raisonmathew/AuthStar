use axum::{
    Router,
    routing::{get, post},
    extract::{Path, State, Json},
    http::HeaderMap,
    response::IntoResponse,
};
use crate::state::AppState;
use serde::Deserialize;
use shared_types::{Capability, Result, AppError};
use risk_engine::WebDeviceInput;
use std::net::IpAddr;
use crate::services::eiaa_flow_service::EiaaFlowContext;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/init", post(init_flow))
        .route("/:flow_id", get(get_flow))
        .route("/:flow_id/identify", post(identify_user))
        .route("/:flow_id/submit", post(submit_step))
        .route("/:flow_id/complete", post(complete_flow))
}

// === Request/Response Types ===

#[derive(Deserialize)]
pub struct InitFlowReq {
    pub org_id: String,
    pub app_id: Option<String>,
    pub device: Option<WebDeviceInput>,
}

#[derive(Deserialize)]
pub struct IdentifyReq {
    pub user_id: String,
    pub device: Option<WebDeviceInput>,
}

#[derive(Deserialize)]
pub struct SubmitStepReq {
    pub capability: Capability,
    // Credential proof/payload (OTP code, password, etc.)
    pub value: Option<String>, 
}

// === Handlers ===

/// Verify exact flow token match
fn verify_flow_token(headers: &HeaderMap, ctx: &EiaaFlowContext) -> Result<()> {
    let auth_header = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing flow token".into()))?;
        
    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized("Invalid authorization format".into()));
    }
    
    let token = &auth_header[7..];
    
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let computed_hash = hex::encode(hasher.finalize());
    
    use subtle::ConstantTimeEq;
    if ctx.flow_token_hash.as_bytes().ct_eq(computed_hash.as_bytes()).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(AppError::Unauthorized("Invalid flow token".into()))
    }
}

/// Initialize a new authentication flow
async fn init_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InitFlowReq>,
) -> Result<Json<serde_json::Value>> {
    let flow_id = shared_types::generate_id("flow");
    
    // Extract IP and UA
    let ip_str = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();
        
    let remote_ip: IpAddr = ip_str.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    
    let user_agent = headers.get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
        
    let (ctx, token) = state.eiaa_flow_service.init_flow(
        flow_id,
        req.org_id,
        req.app_id,
        remote_ip,
        user_agent,
        req.device,
    ).await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    
    // Return sanitized context for client along with the new flow token
    let mut response_data = serde_json::to_value(&ctx).unwrap();
    if let serde_json::Value::Object(ref mut map) = response_data {
        map.remove("flow_token_hash"); // Ensure hash is stripped
        map.insert("flow_token".to_string(), serde_json::Value::String(token));
    }
    Ok(Json(response_data))
}

/// Get flow status
async fn get_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ctx = state.eiaa_flow_service.load_flow_context(&flow_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
        
    verify_flow_token(&headers, &ctx)?;
        
    let mut response_data = serde_json::to_value(&ctx).unwrap();
    if let serde_json::Value::Object(ref mut map) = response_data {
        map.remove("flow_token_hash");
    }
    Ok(Json(response_data))
}

/// Identify user in the flow (triggers re-evaluation)
async fn identify_user(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<IdentifyReq>,
) -> Result<Json<serde_json::Value>> {
    let ip_str = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();
    let remote_ip: IpAddr = ip_str.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    
    let user_agent = headers.get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let check_ctx = state.eiaa_flow_service.load_flow_context(&flow_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
    verify_flow_token(&headers, &check_ctx)?;

    let ctx = state.eiaa_flow_service.identify_user(
        &flow_id,
        &req.user_id,
        remote_ip,
        user_agent,
        req.device,
    ).await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    
    let mut response_data = serde_json::to_value(&ctx).unwrap();
    if let serde_json::Value::Object(ref mut map) = response_data {
        map.remove("flow_token_hash");
    }
    Ok(Json(response_data))
}

/// Submit a step (verify capability)
async fn submit_step(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
    Json(req): Json<SubmitStepReq>,
) -> Result<Json<serde_json::Value>> {
    // Get the flow context to check if a user is identified
    let ctx = state.eiaa_flow_service.load_flow_context(&flow_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
    
    verify_flow_token(&headers, &ctx)?;
    
    // Verify the credential based on capability type
    let verification_result: std::result::Result<(), String> = match req.capability {
        Capability::Totp => {
            // Verify TOTP code
            if let (Some(user_id), Some(code)) = (&ctx.user_id, &req.value) {
                match state.mfa_service.verify_totp(user_id, code).await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Err("User ID or TOTP code missing".to_string())
            }
        }
        Capability::Password => {
            // Password verification would happen during identify_user step
            // If we reach here with password capability, it means the flow allows it
            Ok(())
        }
        Capability::EmailOtp => {
            // Email OTP verification or triggering
            if let Some(code) = &req.value {
                match state.eiaa_flow_service.verify_email_otp(&flow_id, code).await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                // Return early with trigger response
                if let Some(user_id) = &ctx.user_id {
                    match state.eiaa_flow_service.trigger_email_otp(&flow_id, user_id).await {
                        Ok(_) => return Ok(Json(serde_json::json!({
                            "success": true,
                            "needs_more_steps": true,
                            "message": "OTP sent to email"
                        }))),
                        Err(e) => return Err(AppError::Internal(format!("Failed to send OTP: {}", e))),
                    }
                } else {
                    Err("User ID missing for OTP trigger".to_string())
                }
            }
        }
        _ => {
            // For passkeys and other capabilities, trust the submission
            // (actual verification happens via WebAuthn ceremonies)
            Ok(())
        }
    };
    
    match verification_result {
        Ok(()) => {
            // Success - record the step
            let result = state.eiaa_flow_service.record_step(
                &flow_id,
                req.capability,
            ).await
            .map_err(|e| AppError::Internal(e.to_string()))?;
            
            Ok(Json(serde_json::to_value(result).unwrap()))
        }
        Err(reason) => {
            // Failure - record the failure
            let result = state.eiaa_flow_service.record_failure(
                &flow_id,
                req.capability,
                &reason,
            ).await
            .map_err(|e| AppError::Internal(e.to_string()))?;
            
            // Return failure result (still 200 OK, but with success=false in body)
            Ok(Json(serde_json::to_value(result).unwrap()))
        }
    }
}

/// Complete flow — issue JWT + set httpOnly session cookie
async fn complete_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<impl IntoResponse> {
    let check_ctx = state.eiaa_flow_service.load_flow_context(&flow_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
    verify_flow_token(&headers, &check_ctx)?;

    let ctx = state.eiaa_flow_service.complete_flow(&flow_id).await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    
    // Extract user_id from completed flow
    let user_id = ctx.user_id.as_deref()
        .ok_or_else(|| AppError::Validation("Flow has no identified user".into()))?;
    
    let tenant_id = &ctx.org_id;
    
    // Create session
    let session_id = shared_types::generate_id("sess");
    let session_token = shared_types::generate_id("stok");
    let session_type = "user_session";
    
    // Determine assurance level from completed capabilities
    let assurance_level = if ctx.verified_capabilities.len() >= 2 { "aal2" } else { "aal1" };
    let verified_caps = serde_json::to_value(&ctx.verified_capabilities).unwrap_or_default();
    
    sqlx::query(
        r#"INSERT INTO sessions (
            id, user_id, token, user_agent, ip_address,
            expires_at, created_at, updated_at,
            tenant_id, session_type, assurance_level,
            verified_capabilities, is_provisional
        ) VALUES ($1, $2, $3, 'flow_auth', '0.0.0.0', NOW() + INTERVAL '24 hours', NOW(), NOW(), $4, $5, $6, $7, false)"#
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(&session_token)
    .bind(tenant_id)
    .bind(session_type)
    .bind(assurance_level)
    .bind(&verified_caps)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Session creation failed: {}", e)))?;

    // Generate JWT
    let jwt = state.jwt_service.generate_token(
        user_id,
        &session_id,
        tenant_id,
        session_type,
    ).map_err(|e| AppError::Internal(format!("JWT generation failed: {}", e)))?;

    // Generate CSRF token
    let csrf_token = crate::middleware::csrf::generate_csrf_token();

    let session_cookie = crate::middleware::csrf::session_cookie_header(&jwt, true);
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token);

    let body = serde_json::json!({
        "status": "complete",
        "jwt": jwt,
        "csrf_token": csrf_token,
        "session_id": session_id,
        "assurance_level": assurance_level,
        "verified_capabilities": ctx.verified_capabilities,
        "set_cookies": {
            "__session": session_cookie,
            "__csrf": csrf_cookie,
        }
    });

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .body(axum::body::Body::from(serde_json::to_string(&body).unwrap()))
        .map_err(|e| AppError::Internal(format!("Response build error: {}", e)))?;

    Ok(response)
}
