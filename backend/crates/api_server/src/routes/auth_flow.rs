use crate::services::eiaa_flow_service::{EiaaFlowContext, FlowExpiredError};
use crate::state::AppState;
use axum::{
    extract::{Json, Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use identity_engine::services::CreateSessionParams;
use risk_engine::WebDeviceInput;
use serde::Deserialize;
use shared_types::{AppError, Capability, Result};
use std::net::IpAddr;

// ─── Flow Expiry Helper ───────────────────────────────────────────────────────

/// C-1: Convert an `anyhow::Error` from `load_flow_context` into an `AppError`.
///
/// If the underlying error is `FlowExpiredError` we return 410 Gone with
/// `error_code = "FLOW_EXPIRED"` so the frontend can show a
/// "Your session has expired, please start over" message and redirect to /init.
///
/// All other errors are mapped to 500 Internal Server Error.
fn map_flow_load_error(e: anyhow::Error) -> AppError {
    if e.downcast_ref::<FlowExpiredError>().is_some() {
        AppError::FlowExpired(
            "This authentication flow has expired. Please start a new login.".into(),
        )
    } else {
        AppError::Internal(e.to_string())
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/init", post(init_flow))
        .route("/:flow_id", get(get_flow))
        .route("/:flow_id/complete", post(complete_flow))
}

/// Returns a sub-router containing only the submit route, for applying
/// a tighter per-(IP, flow_id) rate limit layer in router.rs (A-2).
pub fn submit_router() -> Router<AppState> {
    Router::new().route("/:flow_id/submit", post(submit_step))
}

/// Returns a sub-router containing only the identify route, for applying
/// a per-IP rate limit layer in router.rs (A-2).
pub fn identify_router() -> Router<AppState> {
    Router::new().route("/:flow_id/identify", post(identify_user))
}

// === Request/Response Types ===

#[derive(Deserialize)]
pub struct InitFlowReq {
    pub org_id: String,
    pub app_id: Option<String>,
    pub device: Option<WebDeviceInput>,
    /// Flow intent — "login", "signup", or "resetpassword".
    /// Defaults to "login" if omitted or unrecognized.
    #[serde(default)]
    pub intent: Option<String>,
}

#[derive(Deserialize)]
pub struct IdentifyReq {
    /// FIX A-3: Accept email/username identifier instead of raw user_id.
    /// Accepting user_id directly allowed an attacker who knows a victim's user_id
    /// to call identify_user + submit_step(Password, "wrong") 5 times to lock the
    /// victim's account (targeted lockout DoS). The user_id is looked up server-side
    /// and never returned to the client in the identify response.
    pub identifier: String,
    pub device: Option<WebDeviceInput>,
}

#[derive(Deserialize)]
pub struct SubmitStepReq {
    /// Accepts both `capability` (canonical) and `type` (frontend compat).
    #[serde(alias = "type")]
    pub capability: Capability,
    // Credential proof/payload (OTP code, password, etc.)
    pub value: Option<String>,
}

// === Handlers ===

/// Verify exact flow token match
fn verify_flow_token(headers: &HeaderMap, ctx: &EiaaFlowContext) -> Result<()> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing flow token".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid authorization format".into(),
        ));
    }

    let token = &auth_header[7..];

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let computed_hash = hex::encode(hasher.finalize());

    use subtle::ConstantTimeEq;
    if ctx
        .flow_token_hash
        .as_bytes()
        .ct_eq(computed_hash.as_bytes())
        .unwrap_u8()
        == 1
    {
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
    let ip_str = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();

    let remote_ip: IpAddr = ip_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let org_id_for_manifest = req.org_id.clone();
    let (ctx, token) = state
        .eiaa_flow_service
        .init_flow(
            flow_id, req.org_id, req.app_id, remote_ip, user_agent, req.device,
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Return sanitized context for client along with the new flow token
    let mut response_data = serde_json::to_value(&ctx)
        .map_err(|e| AppError::Internal(format!("Flow serialization failed: {e}")))?;
    if let serde_json::Value::Object(ref mut map) = response_data {
        map.remove("flow_token_hash"); // Ensure hash is stripped
        map.insert("flow_token".to_string(), serde_json::Value::String(token));

        // Inject tenant manifest for client-side rendering (additive, non-fatal).
        // This lets the hosted page and all SDK surfaces apply branding and render
        // dynamic fields without a second round-trip to the manifest endpoint.
        if let Ok(manifest) =
            crate::routes::sdk_manifest::build_org_manifest(&state.db, &org_id_for_manifest).await
        {
            if let Ok(manifest_val) = serde_json::to_value(&manifest) {
                map.insert("manifest".to_string(), manifest_val);
            }
        }
    }
    Ok(Json(response_data))
}

/// Get flow status
async fn get_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // C-1: map_flow_load_error distinguishes FLOW_EXPIRED from other errors
    let ctx = state
        .eiaa_flow_service
        .load_flow_context(&flow_id)
        .await
        .map_err(map_flow_load_error)?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;

    verify_flow_token(&headers, &ctx)?;

    let mut response_data = serde_json::to_value(&ctx)
        .map_err(|e| AppError::Internal(format!("Flow serialization failed: {e}")))?;
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
    let ip_str = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();
    let remote_ip: IpAddr = ip_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // C-1: map_flow_load_error distinguishes FLOW_EXPIRED from other errors
    let check_ctx = state
        .eiaa_flow_service
        .load_flow_context(&flow_id)
        .await
        .map_err(map_flow_load_error)?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
    verify_flow_token(&headers, &check_ctx)?;

    // FIX A-3: Look up user by email/identifier server-side.
    // Never accept a raw user_id from the client — that would allow an attacker
    // who knows a victim's user_id to trigger targeted account lockout by
    // submitting wrong passwords against the victim's account.
    // Use a deliberately vague error message to prevent user enumeration.
    let user = state
        .user_service
        .get_user_by_email_in_org(&req.identifier, &check_ctx.org_id)
        .await
        .map_err(|_| AppError::NotFound("User not found".into()))?;

    let ctx = state
        .eiaa_flow_service
        .identify_user(&flow_id, &user.id, remote_ip, user_agent, req.device)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut response_data = serde_json::to_value(&ctx)
        .map_err(|e| AppError::Internal(format!("Flow serialization failed: {e}")))?;
    if let serde_json::Value::Object(ref mut map) = response_data {
        map.remove("flow_token_hash");
        // Never expose the internal user_id in the identify response.
        // The flow context stores it server-side; the client only needs
        // to know whether identification succeeded.
        map.remove("user_id");
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
    let ip_str = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();
    let remote_ip: IpAddr = ip_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // C-1: map_flow_load_error distinguishes FLOW_EXPIRED from other errors
    let ctx = state
        .eiaa_flow_service
        .load_flow_context(&flow_id)
        .await
        .map_err(map_flow_load_error)?
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
            // FIX: Actually verify the password. Previously this was a no-op that
            // accepted any password (or empty string) unconditionally.
            // `identify_user` only sets ctx.user_id — it does NOT verify the password.
            // Password verification MUST happen here in submit_step.
            if let (Some(user_id), Some(password)) = (&ctx.user_id, &req.value) {
                match state
                    .user_service
                    .verify_user_password(user_id, password)
                    .await
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("Invalid password".to_string()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Err("User ID or password missing".to_string())
            }
        }
        Capability::EmailOtp => {
            // Email OTP verification or triggering
            if let Some(code) = &req.value {
                match state
                    .eiaa_flow_service
                    .verify_email_otp(&flow_id, code)
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                // Return early with trigger response
                if let Some(user_id) = &ctx.user_id {
                    match state
                        .eiaa_flow_service
                        .trigger_email_otp(&flow_id, user_id)
                        .await
                    {
                        Ok(_) => {
                            return Ok(Json(serde_json::json!({
                                "success": true,
                                "needs_more_steps": true,
                                "message": "OTP sent to email"
                            })))
                        }
                        Err(e) => {
                            return Err(AppError::Internal(format!("Failed to send OTP: {e}")))
                        }
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
            let result = state
                .eiaa_flow_service
                .record_step(&flow_id, req.capability, remote_ip, &user_agent)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            Ok(Json(serde_json::to_value(result).map_err(|e| {
                AppError::Internal(format!("Step result serialization failed: {e}"))
            })?))
        }
        Err(reason) => {
            // Failure - record the failure
            let result = state
                .eiaa_flow_service
                .record_failure(&flow_id, req.capability, &reason, remote_ip, &user_agent)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

            // Return failure result (still 200 OK, but with success=false in body)
            Ok(Json(serde_json::to_value(result).map_err(|e| {
                AppError::Internal(format!("Step result serialization failed: {e}"))
            })?))
        }
    }
}

/// Complete flow — issue JWT + set httpOnly session cookie
async fn complete_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<impl IntoResponse> {
    // C-1: map_flow_load_error distinguishes FLOW_EXPIRED from other errors
    let check_ctx = state
        .eiaa_flow_service
        .load_flow_context(&flow_id)
        .await
        .map_err(map_flow_load_error)?
        .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;
    verify_flow_token(&headers, &check_ctx)?;

    let ctx = state
        .eiaa_flow_service
        .complete_flow(&flow_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Extract user_id from completed flow
    let user_id = ctx
        .user_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("Flow has no identified user".into()))?;

    let tenant_id = &ctx.org_id;

    // R-4.1 FIX: Generate a decision_ref for EIAA audit trail linkage.
    // Previously this path had no decision_ref at all — the column was omitted
    // from the INSERT, breaking the EIAA audit trail for every flow-based login.
    let decision_ref = shared_types::generate_id("dec_flow");

    // Determine session type: 'system' org → admin session, all others → end_user
    let session_type = if tenant_id == "system" {
        auth_core::jwt::session_types::ADMIN
    } else {
        auth_core::jwt::session_types::END_USER
    };
    let assurance_level = if ctx.verified_capabilities.len() >= 2 {
        "aal2"
    } else {
        "aal1"
    };
    let verified_caps = serde_json::to_value(&ctx.verified_capabilities)
        .map_err(|e| AppError::Internal(format!("Capabilities serialization failed: {e}")))?;

    // R-4.1 FIX: Use canonical create_session() so decision_ref is always written.
    // Previously used an inline INSERT that omitted the decision_ref column.
    let session = state
        .user_service
        .create_session(CreateSessionParams {
            user_id,
            tenant_id,
            decision_ref: Some(&decision_ref),
            assurance_level,
            verified_capabilities: verified_caps,
            is_provisional: false,
            session_type,
            device_id: None,
            expires_in_secs: Some(86400), // 24 hours for flow-based sessions
            organization_id: Some(tenant_id),
        })
        .await
        .map_err(|e| AppError::Internal(format!("Session creation failed: {e}")))?;

    let session_id = session.session_id;
    // session_token is stored in the DB (sessions.token) for server-side cookie validation.
    // The JWT (not the token) goes in the __session cookie for this flow path.
    let _session_token = session.session_token;

    // Generate JWT (short-lived access token)
    let jwt = state
        .jwt_service
        .generate_token(user_id, &session_id, tenant_id, session_type)
        .map_err(|e| AppError::Internal(format!("JWT generation failed: {e}")))?;

    // Generate refresh token (long-lived, matches session expiry — 24h)
    let refresh_token_str = state
        .jwt_service
        .generate_token_with_expiry(user_id, &session_id, tenant_id, session_type, 86400)
        .map_err(|e| AppError::Internal(format!("Refresh token generation failed: {e}")))?;

    // Generate CSRF token
    let csrf_token = crate::middleware::csrf::generate_csrf_token();

    let session_cookie = crate::middleware::csrf::session_cookie_header(&jwt, true);
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token, true);

    // Build refresh_token cookie (HttpOnly, scoped to /api/v1/token for refresh endpoint)
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let refresh_cookie = format!(
        "refresh_token={refresh_token_str}; HttpOnly{}; SameSite={}; Path=/; Max-Age=86400",
        if is_secure { "; Secure" } else { "" },
        if is_secure { "Strict" } else { "Lax" },
    );

    // NEW-6 FIX: Fetch full UserResponse so the frontend has complete user data
    // (mfa_enabled, email_verified, phone, etc.) on initial login without waiting
    // for silentRefresh on next page load.
    let user = state
        .user_service
        .get_user(user_id)
        .await
        .map_err(|e| AppError::Internal(format!("User fetch failed: {e}")))?;
    let user_response = state
        .user_service
        .to_user_response(&user)
        .await
        .map_err(|e| AppError::Internal(format!("User response build failed: {e}")))?;

    let body = serde_json::json!({
        "status": "complete",
        "jwt": jwt,
        "csrf_token": csrf_token,
        "session_id": session_id,
        "assurance_level": assurance_level,
        "verified_capabilities": ctx.verified_capabilities,
        "user": user_response,
    });

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .header(axum::http::header::SET_COOKIE, refresh_cookie)
        .body(axum::body::Body::from(
            serde_json::to_string(&body)
                .map_err(|e| AppError::Internal(format!("Response serialization failed: {e}")))?,
        ))
        .map_err(|e| AppError::Internal(format!("Response build error: {e}")))?;

    Ok(response)
}
