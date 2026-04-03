//! Passkey (WebAuthn) API Routes
//!
//! Provides endpoints for passkey registration and authentication.

use axum::{
    Router,
    routing::{post, get, delete},
    extract::{State, Json, Path, Extension},
    response::IntoResponse,
};
use crate::state::AppState;
use auth_core::jwt::Claims;
use shared_types::Result;
use webauthn_rs::prelude::{RegisterPublicKeyCredential, PublicKeyCredential};
use serde::Deserialize;

// Public authentication routes (no auth required)
pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/start", post(authentication_start))
        .route("/finish", post(authentication_finish))
}

// Protected management routes (requires auth + EIAA)
pub fn management_routes() -> Router<AppState> {
    Router::new()
        .route("/register/start", post(registration_start))
        .route("/register/finish", post(registration_finish))
        .route("/", get(list_passkeys))
        .route("/:credential_id", delete(delete_passkey))
}

// === Request/Response Types ===

#[derive(Deserialize)]
pub struct StartRegistrationRequest {
    /// User's email for display
    pub email: String,
}

#[derive(Deserialize)]
pub struct FinishRegistrationRequest {
    /// Session ID from start_registration
    pub session_id: String,
    /// WebAuthn registration response from client
    pub response: RegisterPublicKeyCredential,
    /// Optional friendly name for the passkey
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct StartAuthenticationRequest {
    /// User's email to authenticate
    pub email: String,
    /// Organization ID for tenant-scoped lookup
    pub org_id: Option<String>,
}

#[derive(Deserialize)]
pub struct FinishAuthenticationRequest {
    /// User ID (from start_authentication response)
    pub user_id: String,
    /// Session ID from start_authentication
    pub session_id: String,
    /// WebAuthn authentication response from client
    pub response: PublicKeyCredential,
}

// === Handlers ===

/// Start passkey registration (requires authentication)
async fn registration_start(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<StartRegistrationRequest>,
) -> Result<impl IntoResponse> {
    let result = state.passkey_service
        .start_registration(&claims.sub, &payload.email)
        .await?;
    
    Ok(Json(result))
}

/// Complete passkey registration (requires authentication)
async fn registration_finish(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<FinishRegistrationRequest>,
) -> Result<impl IntoResponse> {
    let credential_id = state.passkey_service
        .finish_registration(
            &claims.sub,
            &payload.session_id,
            &payload.response,
            payload.name,
        )
        .await?;
    
    Ok(Json(serde_json::json!({
        "status": "ok",
        "credential_id": credential_id
    })))
}

/// Start passkey authentication (no auth required - this IS the login)
async fn authentication_start(
    State(state): State<AppState>,
    Json(payload): Json<StartAuthenticationRequest>,
) -> Result<impl IntoResponse> {
    // Look up user by email (org-scoped when org_id is provided)
    let user = if let Some(ref org_id) = payload.org_id {
        state.user_service.get_user_by_email_in_org(&payload.email, org_id).await?
    } else {
        state.user_service.get_user_by_email(&payload.email).await?
    };
    
    let result = state.passkey_service
        .start_authentication(&user.id)
        .await?;
    
    Ok(Json(serde_json::json!({
        "session_id": result.session_id,
        "options": result.options,
        "user_id": user.id
    })))
}

/// Complete passkey authentication - EIAA COMPLIANT
/// 
/// IMPORTANT: This endpoint returns verification RESULT only, NOT a JWT.
/// The result must be fed into the flow engine's login capsule to make
/// the authorization decision. JWTs are issued only after capsule approval.
/// 
/// Response includes AAL (Authenticator Assurance Level) data for policy evaluation.
async fn authentication_finish(
    State(state): State<AppState>,
    Json(payload): Json<FinishAuthenticationRequest>,
) -> Result<impl IntoResponse> {
    let verification = state.passkey_service
        .finish_authentication(&payload.user_id, &payload.session_id, &payload.response)
        .await?;
    
    // Get user info for verification result
    let user = state.user_service
        .get_user(&payload.user_id)
        .await?;
    
    let user_response = state.user_service
        .to_user_response(&user)
        .await?;
    
    // Return verification result with REAL AAL data for capsule evaluation
    // NO JWT ISSUANCE - that happens after capsule authorization
    Ok(Json(serde_json::json!({
        "status": "verified",
        "verification_result": {
            "user_id": user.id,
            "credential_id": verification.credential_id,
            "factor": "passkey",
            "aal": verification.aal,           // Dynamic AAL (AAL2 or AAL3)
            "uv": verification.user_verified,   // Actual UV flag from authenticator
            "counter": verification.counter
        },
        "user": user_response,
        // NOTE: No JWT! Frontend must submit this to flow engine
        "next_action": "submit_to_flow_engine"
    })))
}

/// List user's passkeys (requires authentication)
async fn list_passkeys(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse> {
    let passkeys = state.passkey_service
        .list_passkeys(&claims.sub)
        .await?;
    
    Ok(Json(passkeys))
}

/// Delete a passkey (requires authentication)
async fn delete_passkey(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(credential_id): Path<String>,
) -> Result<impl IntoResponse> {
    state.passkey_service
        .delete_passkey(&claims.sub, &credential_id)
        .await?;
    
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}
