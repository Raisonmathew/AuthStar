//! OAuth 2.0 Authorization Server routes.
//!
//! Implements RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7009 (Revocation),
//! RFC 7662 (Introspection), and OIDC Discovery.
//!
//! ## Endpoints
//! - `GET  /oauth/authorize`        — Authorization endpoint (§3.1)
//! - `POST /oauth/token`            — Token endpoint (§3.2)
//! - `GET  /oauth/userinfo`         — OIDC UserInfo
//! - `POST /oauth/revoke`           — Token revocation (RFC 7009)
//! - `POST /oauth/introspect`       — Token introspection (RFC 7662)
//! - `GET  /oauth/consent`          — Consent check (internal, called after EIAA auth)
//! - `POST /oauth/consent`          — Consent grant (internal)
//! - `GET  /.well-known/openid-configuration` — OIDC Discovery
//! - `GET  /.well-known/jwks.json`  — JSON Web Key Set

use crate::services::oauth_as_service::{AuthorizationCodeContext, AuthorizationContext, OAuthAsService};
use crate::state::AppState;
use auth_core::jwt::Claims;
use auth_core::{
    oauth_error_codes, IntrospectionResponse, OAuthAccessTokenClaims, OAuthErrorResponse,
    OAuthTokenResponse,
};
use axum::{
    extract::{Extension, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

// ─── Routes ────────────────────────────────────────────────────────────────────

/// Public OAuth routes (no EIAA middleware — OAuth clients are external).
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/introspect", post(introspect))
        // Userinfo verifies OAuth access tokens internally (OIDC Core §5.3)
        .route("/userinfo", get(userinfo))
}

/// Protected OAuth routes (require authentication via JWT).
pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/consent", get(check_consent).post(grant_consent))
}

/// Discovery routes (public, cacheable).
pub fn discovery_router() -> Router<AppState> {
    Router::new()
        .route("/openid-configuration", get(openid_configuration))
        .route("/jwks.json", get(jwks))
}

// ─── Request Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    /// Tenant context (usually from subdomain or query param in hosted mode)
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Tenant context for token endpoint
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: Option<String>,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsentCheckParams {
    pub oauth_flow_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentGrantRequest {
    pub oauth_flow_id: String,
    pub grant: bool,
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Build an OAuth error redirect URL.
fn oauth_error_redirect(redirect_uri: &str, error: &str, description: &str, state: Option<&str>) -> String {
    let mut url = format!("{redirect_uri}?error={error}&error_description={}", urlencoding::encode(description));
    if let Some(s) = state {
        url.push_str(&format!("&state={s}"));
    }
    url
}

/// Build an OAuth JSON error response with headers per RFC.
fn oauth_error_json(status: StatusCode, error: &'static str, description: impl Into<String>) -> Response {
    let body = OAuthErrorResponse {
        error,
        error_description: Some(description.into()),
    };
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

/// Extract tenant_id from request params, defaulting to "default".
fn resolve_tenant(tenant_id: Option<&str>) -> &str {
    tenant_id.filter(|s| !s.is_empty()).unwrap_or("default")
}

/// Extract client IP from proxy headers or return None.
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Extract User-Agent header or return None.
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /oauth/authorize — Authorization Endpoint (RFC 6749 §3.1)
// ═══════════════════════════════════════════════════════════════════════════════

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, Response> {
    let tenant_id = resolve_tenant(params.tenant_id.as_deref());

    // Validate required parameters
    let client_id = params.client_id.as_deref().ok_or_else(|| {
        oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id")
    })?;

    let redirect_uri = params.redirect_uri.as_deref().ok_or_else(|| {
        oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing redirect_uri")
    })?;

    let response_type = params.response_type.as_deref().ok_or_else(|| {
        oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing response_type")
    })?;

    if response_type != "code" {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Only response_type=code is supported",
        ));
    }

    // Look up the client application
    let app = state
        .oauth_as_service
        .get_client_by_client_id(client_id, tenant_id)
        .await
        .map_err(|_| {
            oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Unknown client_id")
        })?;

    // Validate redirect_uri exactly matches a registered URI (RFC §3.1.2.3)
    if !OAuthAsService::validate_redirect_uri(&app, redirect_uri) {
        // SECURITY: Do NOT redirect on invalid redirect_uri
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "redirect_uri does not match any registered URI",
        ));
    }

    // Validate grant type is allowed
    if !OAuthAsService::is_flow_allowed(&app, "authorization_code") {
        return Err(Redirect::to(&oauth_error_redirect(
            redirect_uri,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "authorization_code grant not allowed for this client",
            params.state.as_deref(),
        )).into_response());
    }

    // PKCE validation
    if OAuthAsService::is_pkce_required(&app) {
        if params.code_challenge.is_none() {
            return Err(Redirect::to(&oauth_error_redirect(
                redirect_uri,
                oauth_error_codes::INVALID_REQUEST,
                "PKCE code_challenge required for this client",
                params.state.as_deref(),
            )).into_response());
        }
        if params.code_challenge_method.as_deref() != Some("S256") {
            return Err(Redirect::to(&oauth_error_redirect(
                redirect_uri,
                oauth_error_codes::INVALID_REQUEST,
                "Only code_challenge_method=S256 is supported",
                params.state.as_deref(),
            )).into_response());
        }
    }

    // Resolve scopes
    let scope = OAuthAsService::resolve_scopes(&app, params.scope.as_deref().unwrap_or(""));
    if scope.is_empty() {
        return Err(Redirect::to(&oauth_error_redirect(
            redirect_uri,
            oauth_error_codes::INVALID_SCOPE,
            "No valid scopes requested",
            params.state.as_deref(),
        )).into_response());
    }

    // Store authorization context in Redis (10-min TTL)
    let ctx = AuthorizationContext {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        tenant_id: tenant_id.to_string(),
        nonce: params.nonce,
    };

    let flow_id = state
        .oauth_as_service
        .start_authorization(ctx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to start OAuth authorization");
            oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
        })?;

    // Redirect to EIAA login UI with the OAuth flow context
    let login_url = format!(
        "{}/u/{}?oauth_flow_id={}",
        state.config.frontend_url, tenant_id, flow_id
    );

    Ok(Redirect::to(&login_url).into_response())
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/token — Token Endpoint (RFC 6749 §3.2)
// ═══════════════════════════════════════════════════════════════════════════════

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<TokenRequest>,
) -> Response {
    let grant_type = match req.grant_type.as_deref() {
        Some(gt) => gt,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing grant_type",
            );
        }
    };

    match grant_type {
        "authorization_code" => handle_authorization_code_grant(&state, &req, &headers).await,
        "refresh_token" => handle_refresh_token_grant(&state, &req, &headers).await,
        "client_credentials" => handle_client_credentials_grant(&state, &req).await,
        _ => oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNSUPPORTED_GRANT_TYPE,
            format!("Unsupported grant_type: {grant_type}"),
        ),
    }
}

/// Handle authorization_code grant (RFC 6749 §4.1.3)
async fn handle_authorization_code_grant(state: &AppState, req: &TokenRequest, headers: &HeaderMap) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Required parameters
    let code = match req.code.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing code");
        }
    };

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id");
        }
    };

    // Authenticate client — support both confidential (with secret) and public (PKCE-only) clients.
    let app = if let Some(secret) = req.client_secret.as_deref() {
        // Confidential client: authenticate with client_secret
        match state.oauth_as_service.authenticate_client(client_id, secret, tenant_id).await {
            Ok(app) => app,
            Err(_) => {
                return oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_CLIENT, "Client authentication failed");
            }
        }
    } else {
        // Public client: look up by client_id only (PKCE is required below)
        match state.oauth_as_service.get_client_by_client_id(client_id, tenant_id).await {
            Ok(app) => app,
            Err(_) => {
                return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Unknown client_id");
            }
        }
    };

    // Consume authorization code (single-use)
    let code_ctx = match state.oauth_as_service.consume_authorization_code(code).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "Invalid or expired authorization code");
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to consume authorization code");
            return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error");
        }
    };

    // Validate code binding
    if code_ctx.client_id != client_id {
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "Code was not issued to this client");
    }

    // RFC 6749 §4.1.3: redirect_uri is REQUIRED if it was included in the authorization request.
    // Since /authorize always requires redirect_uri, we always require it here too.
    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(uri) => uri,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing redirect_uri");
        }
    };
    if code_ctx.redirect_uri != redirect_uri {
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "redirect_uri does not match");
    }

    // Validate PKCE if code_challenge was used
    if let Some(ref challenge) = code_ctx.code_challenge {
        let verifier = match req.code_verifier.as_deref() {
            Some(v) => v,
            None => {
                return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "Missing code_verifier");
            }
        };
        if !OAuthAsService::validate_pkce(verifier, challenge) {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "PKCE verification failed");
        }
    } else if req.client_secret.is_none() {
        // Public client WITHOUT PKCE — reject (RFC 7636 §4.4.1: PKCE required for public clients)
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "PKCE is required for public clients");
    }

    // Issue tokens
    let token_lifetime = app.token_lifetime_secs as i64;
    let access_token = match state.oauth_as_service.issue_access_token(
        &code_ctx.user_id,
        &code_ctx.session_id,
        &code_ctx.tenant_id,
        client_id,
        &code_ctx.scope,
        token_lifetime,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue access token");
            return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Token generation failed");
        }
    };

    // Issue refresh token if the app allows it AND the user requested offline_access scope
    let scope_has_offline = code_ctx.scope.split_whitespace().any(|s| s == "offline_access");
    let refresh_token = if OAuthAsService::is_flow_allowed(&app, "refresh_token") && scope_has_offline {
        let ip_addr = extract_client_ip(headers);
        let user_agent = extract_user_agent(headers);
        match state.oauth_as_service.create_refresh_token(
            client_id,
            &code_ctx.user_id,
            &code_ctx.session_id,
            &code_ctx.tenant_id,
            &code_ctx.scope,
            app.refresh_token_lifetime_secs as i64,
            code_ctx.decision_ref.as_deref(),
            ip_addr.as_deref(),
            user_agent.as_deref(),
        ).await {
            Ok(rt) => Some(rt),
            Err(e) => {
                tracing::error!(error = %e, "Failed to create refresh token");
                None
            }
        }
    } else {
        None
    };

    // Issue OIDC id_token when scope includes "openid" (OIDC Core §3.1.3.3)
    let id_token = if code_ctx.scope.split_whitespace().any(|s| s == "openid") {
        match state.oauth_as_service.issue_id_token(
            &code_ctx.user_id,
            client_id,
            code_ctx.nonce.as_deref(),
            &access_token,
            &code_ctx.scope,
            token_lifetime,
        ).await {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = %e, "Failed to issue id_token");
                return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "ID token generation failed");
            }
        }
    } else {
        None
    };

    let resp = OAuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: token_lifetime,
        refresh_token,
        scope: Some(code_ctx.scope),
        id_token,
    };

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(resp),
    )
        .into_response()
}

/// Handle refresh_token grant (RFC 6749 §6)
async fn handle_refresh_token_grant(state: &AppState, req: &TokenRequest, headers: &HeaderMap) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    let refresh_token = match req.refresh_token.as_deref() {
        Some(rt) => rt,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing refresh_token");
        }
    };

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id");
        }
    };

    let client_secret = match req.client_secret.as_deref() {
        Some(s) => s,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Missing client_secret");
        }
    };

    // Authenticate client
    let app = match state.oauth_as_service.authenticate_client(client_id, client_secret, tenant_id).await {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_CLIENT, "Client authentication failed");
        }
    };

    // Consume refresh token (one-time use with rotation)
    let old_rt = match state.oauth_as_service.consume_refresh_token(refresh_token).await {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "Invalid or expired refresh token");
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to consume refresh token");
            return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error");
        }
    };

    // Validate token belongs to this client
    if old_rt.client_id != client_id {
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_GRANT, "Refresh token was not issued to this client");
    }

    // Allow scope narrowing per RFC §6
    let scope = if let Some(requested) = req.scope.as_deref() {
        let original: std::collections::HashSet<&str> = old_rt.scope.split_whitespace().collect();
        let requested_scopes: Vec<&str> = requested.split_whitespace().collect();
        let narrowed: Vec<&str> = requested_scopes.into_iter().filter(|s| original.contains(s)).collect();
        if narrowed.is_empty() {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_SCOPE, "Requested scopes are not a subset of the original grant");
        }
        narrowed.join(" ")
    } else {
        old_rt.scope.clone()
    };

    // Issue new access token
    let token_lifetime = app.token_lifetime_secs as i64;
    let access_token = match state.oauth_as_service.issue_access_token(
        &old_rt.user_id,
        &old_rt.session_id,
        &old_rt.tenant_id,
        client_id,
        &scope,
        token_lifetime,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue access token");
            return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Token generation failed");
        }
    };

    // Issue new refresh token (rotation)
    let ip_addr = extract_client_ip(headers);
    let user_agent = extract_user_agent(headers);
    let new_refresh_token = match state.oauth_as_service.create_refresh_token(
        client_id,
        &old_rt.user_id,
        &old_rt.session_id,
        &old_rt.tenant_id,
        &scope,
        app.refresh_token_lifetime_secs as i64,
        None,
        ip_addr.as_deref(),
        user_agent.as_deref(),
    ).await {
        Ok(rt) => Some(rt),
        Err(e) => {
            tracing::error!(error = %e, "Failed to rotate refresh token");
            None
        }
    };

    // Issue OIDC id_token on refresh when scope includes "openid" (OIDC Core §12.2)
    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        match state.oauth_as_service.issue_id_token(
            &old_rt.user_id,
            client_id,
            None, // nonce is single-use; not replayed on refresh
            &access_token,
            &scope,
            token_lifetime,
        ).await {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = %e, "Failed to issue id_token on refresh");
                return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "ID token generation failed");
            }
        }
    } else {
        None
    };

    let resp = OAuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: token_lifetime,
        refresh_token: new_refresh_token,
        scope: Some(scope),
        id_token,
    };

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(resp),
    )
        .into_response()
}

/// Handle client_credentials grant (RFC 6749 §4.4)
async fn handle_client_credentials_grant(state: &AppState, req: &TokenRequest) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id");
        }
    };

    let client_secret = match req.client_secret.as_deref() {
        Some(s) => s,
        None => {
            return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Missing client_secret");
        }
    };

    // Authenticate client
    let app = match state.oauth_as_service.authenticate_client(client_id, client_secret, tenant_id).await {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_CLIENT, "Client authentication failed");
        }
    };

    // Validate grant type is allowed
    if !OAuthAsService::is_flow_allowed(&app, "client_credentials") {
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::UNAUTHORIZED_CLIENT, "client_credentials grant not allowed for this client");
    }

    // Resolve scopes
    let scope = OAuthAsService::resolve_scopes(&app, req.scope.as_deref().unwrap_or(""));
    if scope.is_empty() {
        return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_SCOPE, "No valid scopes");
    }

    // Issue access token (no user, no refresh token per RFC §4.4.3)
    let token_lifetime = app.token_lifetime_secs as i64;
    let access_token = match state.oauth_as_service.issue_client_token(
        tenant_id,
        client_id,
        &scope,
        token_lifetime,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue client token");
            return oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Token generation failed");
        }
    };

    let resp = OAuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: token_lifetime,
        refresh_token: None, // Never issue refresh tokens for client_credentials
        scope: Some(scope),
        id_token: None, // No id_token for M2M client_credentials grant
    };

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(resp),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /oauth/userinfo — UserInfo Endpoint (OIDC Core §5.3)
// ═══════════════════════════════════════════════════════════════════════════════

async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    // Extract and verify OAuth access token from Authorization header.
    // Userinfo MUST accept OAuth access tokens (OIDC Core §5.3.1).
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_REQUEST, "Missing Bearer token")
        })?;

    let oauth_claims: OAuthAccessTokenClaims = state
        .jwt_service
        .verify_token_as(token)
        .map_err(|_| {
            oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_REQUEST, "Invalid or expired access token")
        })?;

    // Scope enforcement: only return claims matching granted scopes (OIDC Core §5.3.2)
    let scopes: std::collections::HashSet<&str> = oauth_claims.scope.split_whitespace().collect();

    let mut info = serde_json::json!({
        "sub": oauth_claims.sub,
    });

    // Profile claims — only if "profile" scope was granted
    if scopes.contains("profile") {
        let user = state
            .user_service
            .get_user(&oauth_claims.sub)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch user for userinfo");
                oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
            })?;

        if let Some(ref first) = user.first_name {
            info["given_name"] = serde_json::json!(first);
        }
        if let Some(ref last) = user.last_name {
            info["family_name"] = serde_json::json!(last);
        }
        if user.first_name.is_some() || user.last_name.is_some() {
            let name = format!(
                "{} {}",
                user.first_name.as_deref().unwrap_or(""),
                user.last_name.as_deref().unwrap_or("")
            ).trim().to_string();
            if !name.is_empty() {
                info["name"] = serde_json::json!(name);
            }
        }
        if let Some(ref picture) = user.profile_image_url {
            info["picture"] = serde_json::json!(picture);
        }
    }

    // Email claims — only if "email" scope was granted
    if scopes.contains("email") {
        let email_row: Option<(String, bool)> = sqlx::query_as(
            "SELECT identifier, verified FROM identities WHERE user_id = $1 AND type = 'email' LIMIT 1",
        )
        .bind(&oauth_claims.sub)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

        if let Some((email, verified)) = email_row {
            info["email"] = serde_json::json!(email);
            info["email_verified"] = serde_json::json!(verified);
        }
    }

    Ok(Json(info))
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/revoke — Token Revocation (RFC 7009)
// ═══════════════════════════════════════════════════════════════════════════════

async fn revoke(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<RevokeRequest>,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Authenticate client (required for revocation)
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id"),
    };
    let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Missing client_secret"),
    };
    let _app = match state.oauth_as_service.authenticate_client(client_id, client_secret, tenant_id).await {
        Ok(app) => app,
        Err(_) => return oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_CLIENT, "Client authentication failed"),
    };

    let token = match req.token.as_deref() {
        Some(t) => t,
        None => {
            // Per RFC 7009 §2.1: "The authorization server responds with HTTP status code 200"
            // even if the token doesn't exist
            return StatusCode::OK.into_response();
        }
    };

    // Try to revoke as refresh token
    let _ = state.oauth_as_service.revoke_token(token).await;

    // Per RFC 7009: always return 200 OK regardless of whether token was found
    StatusCode::OK.into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/introspect — Token Introspection (RFC 7662)
// ═══════════════════════════════════════════════════════════════════════════════

async fn introspect(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<IntrospectRequest>,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Authenticate requesting client -- derive tenant from the authenticated app
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "Missing client_id"),
    };
    let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Missing client_secret"),
    };
    let app = match state.oauth_as_service.authenticate_client(client_id, client_secret, tenant_id).await {
        Ok(app) => app,
        Err(_) => return oauth_error_json(StatusCode::UNAUTHORIZED, oauth_error_codes::INVALID_CLIENT, "Client authentication failed"),
    };
    // Use the authenticated app's tenant_id for tenant isolation (not the user-supplied one)
    let verified_tenant = &app.tenant_id;

    let token = match req.token.as_deref() {
        Some(t) => t,
        None => {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
    };

    // Try to verify as JWT access token.
    // First try to decode as OAuthAccessTokenClaims (has client_id + scope),
    // then fall back to internal Claims.
    if let Ok(oauth_claims) = state.jwt_service.verify_token_as::<auth_core::OAuthAccessTokenClaims>(token) {
        // Tenant isolation: token must belong to the same tenant as the requesting client
        if oauth_claims.tenant_id != *verified_tenant {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
        let resp = IntrospectionResponse {
            active: true,
            sub: Some(oauth_claims.sub),
            client_id: Some(oauth_claims.client_id),
            scope: Some(oauth_claims.scope),
            exp: Some(oauth_claims.exp),
            iat: Some(oauth_claims.iat),
            token_type: Some("Bearer".to_string()),
            tenant_id: Some(oauth_claims.tenant_id),
        };
        return (StatusCode::OK, Json(resp)).into_response();
    } else if let Ok(claims) = state.jwt_service.verify_token(token) {
        // Internal platform JWT (no client_id/scope)
        if claims.tenant_id != *verified_tenant {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
        let resp = IntrospectionResponse {
            active: true,
            sub: Some(claims.sub),
            client_id: None,
            scope: None,
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            token_type: Some("Bearer".to_string()),
            tenant_id: Some(claims.tenant_id),
        };
        return (StatusCode::OK, Json(resp)).into_response();
    }

    // Not a valid JWT — return inactive
    (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /oauth/consent — Check if consent exists (called after EIAA auth)
// ═══════════════════════════════════════════════════════════════════════════════

async fn check_consent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ConsentCheckParams>,
) -> Result<Json<serde_json::Value>, Response> {
    // Load the OAuth authorization context
    let ctx = state
        .oauth_as_service
        .load_authorization_context(&params.oauth_flow_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load OAuth context");
            oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "OAuth flow not found or expired")
        })?;

    // Tenant isolation: the logged-in user must belong to the same tenant as the OAuth flow
    if ctx.tenant_id != claims.tenant_id {
        return Err(oauth_error_json(StatusCode::FORBIDDEN, oauth_error_codes::ACCESS_DENIED, "Tenant mismatch"));
    }

    // Check if the app is first-party (skip consent)
    let app = state
        .oauth_as_service
        .get_client_by_client_id(&ctx.client_id, &ctx.tenant_id)
        .await
        .map_err(|_| {
            oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_CLIENT, "Unknown client")
        })?;

    let has_consent = if app.is_first_party {
        true // First-party apps skip consent
    } else {
        state
            .oauth_as_service
            .check_consent(&claims.sub, &ctx.client_id, &ctx.tenant_id, &ctx.scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check consent");
                oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
            })?
    };

    Ok(Json(serde_json::json!({
        "consent_required": !has_consent,
        "client_name": app.name,
        "scopes": ctx.scope.split_whitespace().collect::<Vec<&str>>(),
        "redirect_uri": ctx.redirect_uri,
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/consent — Grant or deny consent, then issue code
// ═══════════════════════════════════════════════════════════════════════════════

async fn grant_consent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ConsentGrantRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Load the OAuth authorization context
    let ctx = state
        .oauth_as_service
        .load_authorization_context(&req.oauth_flow_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load OAuth context");
            oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
        })?
        .ok_or_else(|| {
            oauth_error_json(StatusCode::BAD_REQUEST, oauth_error_codes::INVALID_REQUEST, "OAuth flow not found or expired")
        })?;

    // Tenant isolation: the logged-in user must belong to the same tenant as the OAuth flow
    if ctx.tenant_id != claims.tenant_id {
        return Err(oauth_error_json(StatusCode::FORBIDDEN, oauth_error_codes::ACCESS_DENIED, "Tenant mismatch"));
    }

    if !req.grant {
        // User denied consent — redirect with access_denied error
        let redirect_url = oauth_error_redirect(
            &ctx.redirect_uri,
            oauth_error_codes::ACCESS_DENIED,
            "User denied consent",
            ctx.state.as_deref(),
        );

        // Clean up the authorization context
        let _ = state.oauth_as_service.consume_authorization_context(&req.oauth_flow_id).await;

        return Ok(Json(serde_json::json!({
            "redirect_uri": redirect_url,
        })));
    }

    // Record consent
    let decision_ref = shared_types::generate_id("dec_oauth");
    state
        .oauth_as_service
        .grant_consent(
            &claims.sub,
            &ctx.client_id,
            &ctx.tenant_id,
            &ctx.scope,
            Some(&decision_ref),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to record consent");
            oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
        })?;

    // Generate authorization code
    let code_ctx = AuthorizationCodeContext {
        client_id: ctx.client_id.clone(),
        redirect_uri: ctx.redirect_uri.clone(),
        scope: ctx.scope.clone(),
        user_id: claims.sub.clone(),
        session_id: claims.sid.clone(),
        tenant_id: ctx.tenant_id.clone(),
        code_challenge: ctx.code_challenge.clone(),
        code_challenge_method: ctx.code_challenge_method.clone(),
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: Some(decision_ref),
        nonce: ctx.nonce.clone(),
    };

    let code = state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create authorization code");
            oauth_error_json(StatusCode::INTERNAL_SERVER_ERROR, oauth_error_codes::SERVER_ERROR, "Internal error")
        })?;

    // Consume the authorization context (single-use)
    let _ = state.oauth_as_service.consume_authorization_context(&req.oauth_flow_id).await;

    // Build redirect URL with code
    let mut redirect_url = format!("{}?code={}", ctx.redirect_uri, urlencoding::encode(&code));
    if let Some(ref s) = ctx.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }

    Ok(Json(serde_json::json!({
        "redirect_uri": redirect_url,
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /.well-known/openid-configuration — OIDC Discovery
// ═══════════════════════════════════════════════════════════════════════════════

async fn openid_configuration(
    State(state): State<AppState>,
) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], Json<serde_json::Value>) {
    let issuer = &state.config.jwt.issuer;
    let base_url = issuer.trim_end_matches('/');

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "public, max-age=86400")],
        Json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base_url}/oauth/authorize"),
            "token_endpoint": format!("{base_url}/oauth/token"),
            "userinfo_endpoint": format!("{base_url}/oauth/userinfo"),
            "revocation_endpoint": format!("{base_url}/oauth/revoke"),
            "introspection_endpoint": format!("{base_url}/oauth/introspect"),
            "jwks_uri": format!("{base_url}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "name", "given_name", "family_name", "email", "email_verified", "picture"],
        })),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /.well-known/jwks.json — JSON Web Key Set
// ═══════════════════════════════════════════════════════════════════════════════

async fn jwks(
    State(state): State<AppState>,
) -> (StatusCode, [(axum::http::HeaderName, &'static str); 1], Json<serde_json::Value>) {
    let kid = state.jwt_service.get_key_id();
    let public_key_pem = state.jwt_service.get_public_key_pem();

    let jwk = match parse_ec_public_key_to_jwk(public_key_pem, kid) {
        Ok(jwk) => jwk,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse public key for JWKS");
            return (
                StatusCode::OK,
                [(header::CACHE_CONTROL, "public, max-age=3600")],
                Json(serde_json::json!({ "keys": [] })),
            );
        }
    };

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(serde_json::json!({
            "keys": [jwk]
        })),
    )
}

/// Parse an EC public key PEM to JWK format (kty=EC, crv=P-256).
fn parse_ec_public_key_to_jwk(pem: &str, kid: &str) -> Result<serde_json::Value, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Normalize PEM
    let pem = pem.replace("\\n", "\n").replace("\r", "");
    let pem = pem.trim();

    // Extract base64 content between PEM markers
    let b64_content: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64_content)
        .map_err(|e| format!("Base64 decode: {e}"))?;

    // EC P-256 SubjectPublicKeyInfo DER is exactly 91 bytes:
    //   SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 04 || x(32) || y(32) } }
    // The uncompressed EC point (65 bytes) is always at the END of the DER.
    // Using a fixed tail offset avoids false-matching 0x04 inside coordinate data.
    if der.len() < 65 {
        return Err("DER too short for EC public key".into());
    }

    let point_start = der.len() - 65;

    // Validate uncompressed point marker
    if der[point_start] != 0x04 {
        return Err(format!(
            "Expected uncompressed point marker 0x04 at offset {}, found 0x{:02x}",
            point_start, der[point_start]
        ));
    }

    let x = &der[point_start + 1..point_start + 33];
    let y = &der[point_start + 33..point_start + 65];

    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    }))
}
