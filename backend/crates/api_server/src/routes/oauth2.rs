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
//! - `GET  /api/oauth/consent`     — Consent check (internal, called after EIAA auth)
//! - `POST /api/oauth/consent`     — Consent grant (internal)
//! - `GET  /.well-known/openid-configuration` — OIDC Discovery
//! - `GET  /.well-known/jwks.json`  — JSON Web Key Set

use crate::services::oauth_as_service::{
    AuthorizationCodeContext, AuthorizationContext, OAuthAsService,
};
use crate::state::AppState;
use auth_core::jwt::Claims;
use auth_core::{
    oauth_error_codes, IntrospectionResponse, OAuthAccessTokenClaims, OAuthErrorResponse,
    OAuthTokenResponse,
};
use axum::{
    extract::{Extension, Query, State},
    http::{header, HeaderMap, StatusCode, Uri},
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
        .route("/revoke", post(revoke))
        .route("/introspect", post(introspect))
        // T2.2 — Pushed Authorization Requests (RFC 9126)
        .route("/par", post(pushed_authorization_request))
        // T2.6 — Device Authorization Grant (RFC 8628)
        .route("/device_authorization", post(device_authorization))
        // Userinfo verifies OAuth access tokens internally (OIDC Core §5.3)
        .route("/userinfo", get(userinfo))
}

/// Token endpoint — separated for a stricter rate limit (brute-force protection).
pub fn token_router() -> Router<AppState> {
    Router::new().route("/token", post(token))
}

/// Protected OAuth routes (require authentication via JWT).
pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/consent", get(check_consent).post(grant_consent))
        // T2.6 — device approval (called by the SPA after the user types
        // their user_code and the EIAA capsule decides).
        .route("/device/approve", post(approve_device))
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
    /// T2.2 — RFC 9126 PAR. When present, ALL other params are loaded from
    /// the pushed request and any duplicates here are ignored except `client_id`.
    pub request_uri: Option<String>,
}

/// T2.2 — RFC 9126 §2.1 request body. All authorization parameters posted
/// out-of-band, plus optional client authentication credentials. Confidential
/// clients authenticate with `client_id` + `client_secret`; public clients
/// present only `client_id` and MUST include a PKCE `code_challenge`
/// (RFC 9126 §2 + RFC 7636), which binds the pushed request to the eventual
/// token-endpoint exchange.
#[derive(Debug, Deserialize)]
pub struct PushedAuthorizationRequestBody {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PushedAuthorizationResponse {
    request_uri: String,
    expires_in: i64,
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
    // T2.6 — Device Authorization Grant (RFC 8628)
    pub device_code: Option<String>,
    // T2.4 — Token Exchange (RFC 8693)
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: Option<String>,
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
fn oauth_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> String {
    let mut url = format!(
        "{redirect_uri}?error={error}&error_description={}",
        urlencoding::encode(description)
    );
    if let Some(s) = state {
        url.push_str(&format!("&state={s}"));
    }
    url
}

/// Build an OAuth JSON error response with headers per RFC.
fn oauth_error_json(
    status: StatusCode,
    error: &'static str,
    description: impl Into<String>,
) -> Response {
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
    // T4.4 — Track whether the request arrived via PAR before consuming it.
    // FAPI 2.0 §5.2.2: PAR is mandatory for FAPI clients.
    let was_par = params.request_uri.is_some();

    // T2.2 — If the client used PAR, swap in the pushed parameters now.
    // RFC 9126 §4: when `request_uri` is present, the AS MUST treat the
    // pushed request as authoritative; query parameters other than `client_id`
    // (used to scope the lookup) are ignored.
    let params = if let Some(req_uri) = params.request_uri.as_deref() {
        let par_ctx = state
            .oauth_as_service
            .consume_par(req_uri)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "PAR consume failed");
                oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "Internal error",
                )
            })?
            .ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_REQUEST,
                    "request_uri is unknown, expired, or already consumed",
                )
            })?;
        // Bind: client_id on the URL MUST match the one inside the PAR.
        if let Some(qc) = params.client_id.as_deref() {
            if qc != par_ctx.client_id {
                return Err(oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_REQUEST,
                    "client_id does not match the pushed request",
                ));
            }
        }
        AuthorizeParams {
            response_type: Some("code".to_string()),
            client_id: Some(par_ctx.client_id.clone()),
            redirect_uri: Some(par_ctx.redirect_uri.clone()),
            scope: Some(par_ctx.scope.clone()),
            state: par_ctx.state.clone(),
            code_challenge: par_ctx.code_challenge.clone(),
            code_challenge_method: par_ctx.code_challenge_method.clone(),
            nonce: par_ctx.nonce.clone(),
            tenant_id: Some(par_ctx.tenant_id.clone()),
            request_uri: None,
        }
    } else {
        params
    };

    let tenant_id = resolve_tenant(params.tenant_id.as_deref());

    // Validate required parameters
    let client_id = params.client_id.as_deref().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Missing client_id",
        )
    })?;

    let redirect_uri = params.redirect_uri.as_deref().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Missing redirect_uri",
        )
    })?;

    let response_type = params.response_type.as_deref().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Missing response_type",
        )
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
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Unknown client_id",
            )
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

    // T4.4 — FAPI 2.0 Security Profile: PAR is mandatory (FAPI 2.0 §5.2.2).
    // Direct /authorize requests (non-PAR) are rejected for FAPI clients.
    if OAuthAsService::is_fapi(&app) && !was_par {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "FAPI 2.0 requires Pushed Authorization Requests (PAR); use /oauth/par first",
        ));
    }

    // Validate grant type is allowed
    if !OAuthAsService::is_flow_allowed(&app, "authorization_code") {
        return Err(Redirect::to(&oauth_error_redirect(
            redirect_uri,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "authorization_code grant not allowed for this client",
            params.state.as_deref(),
        ))
        .into_response());
    }

    // PKCE validation — T2.1 hardening (RFC 7636 + OAuth 2.1).
    // T4.4: FAPI 2.0 always requires PKCE S256 regardless of app config.
    let pkce_required = OAuthAsService::is_pkce_required(&app) || OAuthAsService::is_fapi(&app);
    if pkce_required && params.code_challenge.is_none() {
        return Err(Redirect::to(&oauth_error_redirect(
            redirect_uri,
            oauth_error_codes::INVALID_REQUEST,
            "PKCE code_challenge required for this client",
            params.state.as_deref(),
        ))
        .into_response());
    }
    if let Some(ref challenge) = params.code_challenge {
        // Method: only S256 (reject "plain" and unsupported variants).
        // Default-to-plain (RFC 7636 §4.3) is explicitly disallowed by OAuth 2.1.
        match params.code_challenge_method.as_deref() {
            Some("S256") => {}
            _ => {
                return Err(Redirect::to(&oauth_error_redirect(
                    redirect_uri,
                    oauth_error_codes::INVALID_REQUEST,
                    "code_challenge_method must be S256 (plain disallowed)",
                    params.state.as_deref(),
                ))
                .into_response());
            }
        }
        if !OAuthAsService::validate_s256_challenge_format(challenge) {
            return Err(Redirect::to(&oauth_error_redirect(
                redirect_uri,
                oauth_error_codes::INVALID_REQUEST,
                "code_challenge must be 43 chars base64url-no-pad of SHA-256",
                params.state.as_deref(),
            ))
            .into_response());
        }
    }

    // Resolve scopes — first the legacy app-level allow-list, then layer in
    // T2.8 client-scope defaults (always granted) + optional (granted only
    // when the request asked for them).
    let requested = params.scope.as_deref().unwrap_or("");
    let app_allowed = OAuthAsService::resolve_scopes(&app, requested);
    let scope = state
        .client_scope_service
        .resolve_with_mappings(&tenant_id, &client_id, requested, &app_allowed)
        .await
        .unwrap_or(app_allowed);
    if scope.is_empty() {
        return Err(Redirect::to(&oauth_error_redirect(
            redirect_uri,
            oauth_error_codes::INVALID_SCOPE,
            "No valid scopes requested",
            params.state.as_deref(),
        ))
        .into_response());
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
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        })?;

    // Redirect to EIAA login UI with the OAuth flow context
    let login_url = format!(
        "{}/u/{}?oauth_flow_id={}",
        state.config.frontend_url, tenant_id, flow_id
    );

    Ok(Redirect::to(&login_url).into_response())
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/par — Pushed Authorization Requests (RFC 9126) — T2.2
//
// Confidential clients post all `/authorize` parameters out-of-band and receive
// a single-use `request_uri`. The browser is then redirected to
// `/authorize?request_uri=...&client_id=...`. Eliminates request-tampering and
// keeps long parameters off the front channel.
// ═══════════════════════════════════════════════════════════════════════════════

async fn pushed_authorization_request(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<PushedAuthorizationRequestBody>,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // RFC 9126 §2: client_id is always required.
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };

    // Resolve the client first so we know whether it is confidential or public.
    // RFC 9126 §2 requires AS to accept PAR from public clients (no secret),
    // provided the request is otherwise valid (PKCE will bind it).
    let app = match state
        .oauth_as_service
        .get_client_by_client_id(client_id, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Unknown client_id",
            )
        }
    };

    // Branch on client type.
    //   * Confidential clients MUST present client_secret and pass authenticate_client.
    //   * Public clients MUST NOT present a secret and MUST present a PKCE
    //     code_challenge — without that, there is nothing binding the pushed
    //     request to the eventual token exchange.
    if OAuthAsService::is_public_client(&app) {
        if req.client_secret.as_deref().is_some_and(|s| !s.is_empty()) {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Public client must not present client_secret",
            );
        }
        if req
            .code_challenge
            .as_deref()
            .is_none_or(|s| s.is_empty())
        {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Public clients must include a PKCE code_challenge in PAR",
            );
        }
    } else {
        // Confidential client path — re-authenticate with the supplied secret
        // (constant-time hash compare inside authenticate_client).
        let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => s,
            None => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Missing client_secret",
                )
            }
        };
        if state
            .oauth_as_service
            .authenticate_client(client_id, client_secret, tenant_id)
            .await
            .is_err()
        {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            );
        }
    }

    // Mandatory request validation — same shape as /authorize so we can fail
    // fast and not store malformed contexts in Redis.
    let response_type = match req.response_type.as_deref() {
        Some("code") => "code",
        Some(_) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Only response_type=code is supported",
            )
        }
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing response_type",
            )
        }
    };
    let _ = response_type; // keep for future expansion

    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(u) => u,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing redirect_uri",
            )
        }
    };
    if !OAuthAsService::validate_redirect_uri(&app, redirect_uri) {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "redirect_uri does not match any registered URI",
        );
    }
    if !OAuthAsService::is_flow_allowed(&app, "authorization_code") {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "authorization_code grant not allowed for this client",
        );
    }

    // PKCE — same rules as /authorize (T2.1).
    if OAuthAsService::is_pkce_required(&app) && req.code_challenge.is_none() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "PKCE code_challenge required for this client",
        );
    }
    if let Some(ref challenge) = req.code_challenge {
        match req.code_challenge_method.as_deref() {
            Some("S256") => {}
            _ => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_REQUEST,
                    "code_challenge_method must be S256 (plain disallowed)",
                )
            }
        }
        if !OAuthAsService::validate_s256_challenge_format(challenge) {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "code_challenge must be 43 chars base64url-no-pad of SHA-256",
            );
        }
    }

    let scope = OAuthAsService::resolve_scopes(&app, req.scope.as_deref().unwrap_or(""));
    if scope.is_empty() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_SCOPE,
            "No valid scopes requested",
        );
    }

    let ctx = AuthorizationContext {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope,
        state: req.state,
        code_challenge: req.code_challenge,
        code_challenge_method: req.code_challenge_method,
        tenant_id: tenant_id.to_string(),
        nonce: req.nonce,
    };
    let (request_uri, expires_in) = match state.oauth_as_service.store_par(ctx).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "PAR store failed");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // RFC 9126 \u00a72.2: HTTP 201 Created with JSON body.
    (
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(PushedAuthorizationResponse {
            request_uri,
            expires_in,
        }),
    )
        .into_response()
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
        "client_credentials" => handle_client_credentials_grant(&state, &req, &headers).await,
        // T2.6 — Device Authorization Grant
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code_grant(&state, &req, &headers).await
        }
        // T2.4 — Token Exchange (RFC 8693)
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            handle_token_exchange_grant(&state, &req, &headers).await
        }
        _ => oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNSUPPORTED_GRANT_TYPE,
            format!("Unsupported grant_type: {grant_type}"),
        ),
    }
}

/// Handle authorization_code grant (RFC 6749 §4.1.3)
async fn handle_authorization_code_grant(
    state: &AppState,
    req: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Required parameters
    let code = match req.code.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing code",
            );
        }
    };

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            );
        }
    };

    // Authenticate client — support both confidential (with secret) and public (PKCE-only) clients.
    let app = if let Some(secret) = req.client_secret.as_deref() {
        // Confidential client: authenticate with client_secret
        match state
            .oauth_as_service
            .authenticate_client(client_id, secret, tenant_id)
            .await
        {
            Ok(app) => app,
            Err(_) => {
                return oauth_error_json(
                    StatusCode::UNAUTHORIZED,
                    oauth_error_codes::INVALID_CLIENT,
                    "Client authentication failed",
                );
            }
        }
    } else {
        // Public client: look up by client_id only (PKCE is required below)
        match state
            .oauth_as_service
            .get_client_by_client_id(client_id, tenant_id)
            .await
        {
            Ok(app) => app,
            Err(_) => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Unknown client_id",
                );
            }
        }
    };

    // Consume authorization code (single-use)
    let code_ctx = match state
        .oauth_as_service
        .consume_authorization_code(code)
        .await
    {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_GRANT,
                "Invalid or expired authorization code",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to consume authorization code");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // Validate code binding
    if code_ctx.client_id != client_id {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_GRANT,
            "Code was not issued to this client",
        );
    }

    // RFC 6749 §4.1.3: redirect_uri is REQUIRED if it was included in the authorization request.
    // Since /authorize always requires redirect_uri, we always require it here too.
    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(uri) => uri,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing redirect_uri",
            );
        }
    };
    if code_ctx.redirect_uri != redirect_uri {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_GRANT,
            "redirect_uri does not match",
        );
    }

    // Validate PKCE if code_challenge was used
    if let Some(ref challenge) = code_ctx.code_challenge {
        let verifier = match req.code_verifier.as_deref() {
            Some(v) => v,
            None => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_GRANT,
                    "Missing code_verifier",
                );
            }
        };
        if !OAuthAsService::validate_pkce(verifier, challenge) {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_GRANT,
                "PKCE verification failed",
            );
        }
    } else if req.client_secret.is_none() {
        // Public client WITHOUT PKCE — reject (RFC 7636 §4.4.1: PKCE required for public clients)
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_GRANT,
            "PKCE is required for public clients",
        );
    }

    // Issue tokens.
    // T4.4 — FAPI 2.0 caps access-token lifetime at 300 s (FAPI 2.0 §5.2.2).
    let token_lifetime = {
        let base = app.token_lifetime_secs as i64;
        if OAuthAsService::is_fapi(&app) {
            base.min(300)
        } else {
            base
        }
    };
    let confirmation = match crate::services::token_binding::confirmation_from_headers(headers) {
        Ok(cnf) => cnf,
        Err(e) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                format!("Invalid token binding proof: {e}"),
            )
        }
    };
    // T4.4 — FAPI 2.0: DPoP is required (FAPI 2.0 §5.2.2).
    // The confirmation's `jkt` field is set iff a DPoP header was present.
    if OAuthAsService::is_fapi(&app)
        && !confirmation.as_ref().map(|c| c.jkt.is_some()).unwrap_or(false)
    {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "FAPI 2.0 requires DPoP proof-of-possession; include a DPoP header",
        );
    }
    let access_token = match state.oauth_as_service.issue_access_token_with_confirmation(
        &code_ctx.user_id,
        &code_ctx.session_id,
        &code_ctx.tenant_id,
        client_id,
        &code_ctx.scope,
        token_lifetime,
        confirmation,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue access token");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Token generation failed",
            );
        }
    };

    // Issue refresh token if the app allows it AND the user requested offline_access scope
    let scope_has_offline = code_ctx
        .scope
        .split_whitespace()
        .any(|s| s == "offline_access");
    let refresh_token =
        if OAuthAsService::is_flow_allowed(&app, "refresh_token") && scope_has_offline {
            let ip_addr = extract_client_ip(headers);
            let user_agent = extract_user_agent(headers);
            match state
                .oauth_as_service
                .create_refresh_token(
                    client_id,
                    &code_ctx.user_id,
                    &code_ctx.session_id,
                    &code_ctx.tenant_id,
                    &code_ctx.scope,
                    app.refresh_token_lifetime_secs as i64,
                    code_ctx.decision_ref.as_deref(),
                    ip_addr.as_deref(),
                    user_agent.as_deref(),
                )
                .await
            {
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
        match state
            .oauth_as_service
            .issue_id_token(
                &code_ctx.user_id,
                &code_ctx.tenant_id,
                client_id,
                code_ctx.nonce.as_deref(),
                &access_token,
                &code_ctx.scope,
                token_lifetime,
                code_ctx.state.as_deref(),
            )
            .await
        {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = %e, "Failed to issue id_token");
                return oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "ID token generation failed",
                );
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
async fn handle_refresh_token_grant(
    state: &AppState,
    req: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    let refresh_token = match req.refresh_token.as_deref() {
        Some(rt) => rt,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing refresh_token",
            );
        }
    };

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            );
        }
    };

    let client_secret = match req.client_secret.as_deref() {
        Some(s) => s,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Missing client_secret",
            );
        }
    };

    // Authenticate client
    let app = match state
        .oauth_as_service
        .authenticate_client(client_id, client_secret, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            );
        }
    };

    // Consume refresh token (one-time use with rotation)
    let old_rt = match state
        .oauth_as_service
        .consume_refresh_token(refresh_token)
        .await
    {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_GRANT,
                "Invalid or expired refresh token",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to consume refresh token");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // Validate token belongs to this client
    if old_rt.client_id != client_id {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_GRANT,
            "Refresh token was not issued to this client",
        );
    }

    // Allow scope narrowing per RFC §6
    let scope = if let Some(requested) = req.scope.as_deref() {
        let original: std::collections::HashSet<&str> = old_rt.scope.split_whitespace().collect();
        let requested_scopes: Vec<&str> = requested.split_whitespace().collect();
        let narrowed: Vec<&str> = requested_scopes
            .into_iter()
            .filter(|s| original.contains(s))
            .collect();
        if narrowed.is_empty() {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_SCOPE,
                "Requested scopes are not a subset of the original grant",
            );
        }
        narrowed.join(" ")
    } else {
        old_rt.scope.clone()
    };

    // Issue new access token
    let token_lifetime = app.token_lifetime_secs as i64;
    let confirmation = match crate::services::token_binding::confirmation_from_headers(headers) {
        Ok(cnf) => cnf,
        Err(e) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                format!("Invalid token binding proof: {e}"),
            )
        }
    };
    let access_token = match state.oauth_as_service.issue_access_token_with_confirmation(
        &old_rt.user_id,
        &old_rt.session_id,
        &old_rt.tenant_id,
        client_id,
        &scope,
        token_lifetime,
        confirmation,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue access token");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Token generation failed",
            );
        }
    };

    // Issue new refresh token via atomic rotation (T1.3 — preserves family lineage,
    // populates replaced_by, enforced single-active-per-family by partial UNIQUE index).
    let ip_addr = extract_client_ip(headers);
    let user_agent = extract_user_agent(headers);
    let new_refresh_token = match state
        .oauth_as_service
        .rotate_refresh_token(
            &old_rt,
            &scope,
            app.refresh_token_lifetime_secs as i64,
            old_rt.decision_ref.as_deref(),
            ip_addr.as_deref(),
            user_agent.as_deref(),
        )
        .await
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            tracing::error!(error = %e, "Failed to rotate refresh token");
            None
        }
    };

    // Issue OIDC id_token on refresh when scope includes "openid" (OIDC Core §12.2)
    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        match state
            .oauth_as_service
            .issue_id_token(
                &old_rt.user_id,
                &old_rt.tenant_id,
                client_id,
                None, // nonce is single-use; not replayed on refresh
                &access_token,
                &scope,
                token_lifetime,
                None, // no state on refresh grant
            )
            .await
        {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = %e, "Failed to issue id_token on refresh");
                return oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "ID token generation failed",
                );
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
async fn handle_client_credentials_grant(
    state: &AppState,
    req: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    let client_id = match req.client_id.as_deref() {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            );
        }
    };

    let client_secret = match req.client_secret.as_deref() {
        Some(s) => s,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Missing client_secret",
            );
        }
    };

    // Authenticate client
    let app = match state
        .oauth_as_service
        .authenticate_client(client_id, client_secret, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            );
        }
    };

    // Validate grant type is allowed
    if !OAuthAsService::is_flow_allowed(&app, "client_credentials") {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "client_credentials grant not allowed for this client",
        );
    }

    // Resolve scopes
    let scope = OAuthAsService::resolve_scopes(&app, req.scope.as_deref().unwrap_or(""));
    if scope.is_empty() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_SCOPE,
            "No valid scopes",
        );
    }

    // Issue access token (no user, no refresh token per RFC §4.4.3)
    let token_lifetime = app.token_lifetime_secs as i64;
    let confirmation = match crate::services::token_binding::confirmation_from_headers(headers) {
        Ok(cnf) => cnf,
        Err(e) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                format!("Invalid token binding proof: {e}"),
            )
        }
    };
    let access_token = match state.oauth_as_service.issue_client_token_with_confirmation(
        tenant_id,
        client_id,
        &scope,
        token_lifetime,
        confirmation,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue client token");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Token generation failed",
            );
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
// T2.6 — POST /oauth/device_authorization (RFC 8628 §3.1)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub tenant_id: Option<String>,
}

async fn device_authorization(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<DeviceAuthorizationRequest>,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let app = match state
        .oauth_as_service
        .get_client_by_client_id(client_id, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Unknown client_id",
            )
        }
    };
    if !OAuthAsService::is_flow_allowed(&app, "urn:ietf:params:oauth:grant-type:device_code") {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "device_code grant not allowed for this client",
        );
    }
    let scope = OAuthAsService::resolve_scopes(&app, req.scope.as_deref().unwrap_or(""));
    if scope.is_empty() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_SCOPE,
            "No valid scopes requested",
        );
    }

    let dev = match state
        .oauth_as_service
        .start_device_authorization(client_id, tenant_id, &scope)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Failed to start device authorization");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // verification_uri: hosted device-approval page (frontend route).
    let base = state.config.frontend_url.trim_end_matches('/');
    let verification_uri = format!("{base}/device");
    let verification_uri_complete = format!(
        "{base}/device?user_code={}",
        urlencoding::encode(&dev.user_code)
    );

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "device_code": dev.device_code,
            "user_code": dev.user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": dev.expires_in,
            "interval": dev.interval,
        })),
    )
        .into_response()
}

/// T2.6 — Device Authorization Grant token branch (RFC 8628 §3.4-3.5).
async fn handle_device_code_grant(
    state: &AppState,
    req: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let device_code = match req.device_code.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing device_code",
            )
        }
    };

    let app = match state
        .oauth_as_service
        .get_client_by_client_id(client_id, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Unknown client_id",
            )
        }
    };
    // Confidential clients still authenticate with their secret on the token endpoint.
    if !OAuthAsService::is_public_client(&app) {
        let secret = req.client_secret.as_deref().unwrap_or("");
        if state
            .oauth_as_service
            .authenticate_client(client_id, secret, tenant_id)
            .await
            .is_err()
        {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            );
        }
    }

    let dev = match state
        .oauth_as_service
        .get_device_authorization(device_code)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            // RFC 8628 §3.5: expired_token or unknown.
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code is unknown or expired",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Device lookup failed");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    if dev.client_id != client_id || dev.tenant_id != tenant_id {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_GRANT,
            "device_code does not belong to this client",
        );
    }

    use crate::services::oauth_as_service::DeviceAuthState;
    match dev.state {
        DeviceAuthState::Pending => oauth_error_json(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "User has not yet completed the device authorization",
        ),
        DeviceAuthState::Denied => {
            let _ = state
                .oauth_as_service
                .consume_device_authorization(device_code, &dev.user_code)
                .await;
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "User denied the device authorization",
            )
        }
        DeviceAuthState::Approved => {
            let user_id = match dev.user_id.as_deref() {
                Some(u) => u,
                None => {
                    return oauth_error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        oauth_error_codes::SERVER_ERROR,
                        "Approved device has no user_id",
                    )
                }
            };
            let session_id = dev.session_id.as_deref().unwrap_or("");
            let token_lifetime = app.token_lifetime_secs as i64;
            let confirmation =
                match crate::services::token_binding::confirmation_from_headers(headers) {
                    Ok(cnf) => cnf,
                    Err(e) => {
                        return oauth_error_json(
                            StatusCode::BAD_REQUEST,
                            oauth_error_codes::INVALID_REQUEST,
                            format!("Invalid token binding proof: {e}"),
                        )
                    }
                };
            let access_token = match state.oauth_as_service.issue_access_token_with_confirmation(
                user_id,
                session_id,
                tenant_id,
                client_id,
                &dev.scope,
                token_lifetime,
                confirmation,
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to issue device access token");
                    return oauth_error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        oauth_error_codes::SERVER_ERROR,
                        "Token generation failed",
                    );
                }
            };
            // One-shot — burn the device record.
            let _ = state
                .oauth_as_service
                .consume_device_authorization(device_code, &dev.user_code)
                .await;
            let resp = OAuthTokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: token_lifetime,
                refresh_token: None,
                scope: Some(dev.scope.clone()),
                id_token: None,
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
    }
}

/// T2.4 — Token Exchange (RFC 8693). Strategy pattern per `requested_token_type`.
///
/// Current scope: minimal `urn:ietf:params:oauth:token-type:access_token`
/// re-issuance for the same subject with the requesting client as the new
/// `client_id`. Service-to-service delegation (with `actor_token`) and AI-agent
/// identity exchange ride on top of this scaffold; both will be activated by
/// dedicated capsules per the EIAA roadmap (`action="token:exchange"`).
async fn handle_token_exchange_grant(
    state: &AppState,
    req: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Confidential client auth required by RFC 8693 §2.1.
    let client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Missing client_secret",
            )
        }
    };
    let app = match state
        .oauth_as_service
        .authenticate_client(client_id, client_secret, tenant_id)
        .await
    {
        Ok(a) => a,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            )
        }
    };
    if !OAuthAsService::is_flow_allowed(&app, "urn:ietf:params:oauth:grant-type:token-exchange") {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::UNAUTHORIZED_CLIENT,
            "token-exchange grant not allowed for this client",
        );
    }

    let requested_token_type = req
        .requested_token_type
        .as_deref()
        .unwrap_or("urn:ietf:params:oauth:token-type:access_token");
    if requested_token_type != "urn:ietf:params:oauth:token-type:access_token" {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Only requested_token_type=access_token is supported",
        );
    }
    if let Some(audience) = req.audience.as_deref().filter(|s| !s.is_empty()) {
        if audience != client_id {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "audience must match the authenticated client_id",
            );
        }
    }
    if req.resource.as_deref().filter(|s| !s.is_empty()).is_some() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "resource indicators are not supported for token exchange yet",
        );
    }

    let subject_token = match req.subject_token.as_deref().filter(|s| !s.is_empty()) {
        Some(t) => t,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing subject_token",
            )
        }
    };
    let subject_token_type = req
        .subject_token_type
        .as_deref()
        .unwrap_or("urn:ietf:params:oauth:token-type:access_token");
    if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Only subject_token_type=access_token is supported in this scaffold",
        );
    }
    let actor_claims = if let Some(actor_token) = req.actor_token.as_deref() {
        let actor_token_type = req
            .actor_token_type
            .as_deref()
            .unwrap_or("urn:ietf:params:oauth:token-type:access_token");
        if actor_token_type != "urn:ietf:params:oauth:token-type:access_token" {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Only actor_token_type=access_token is supported",
            );
        }
        match state
            .jwt_service
            .verify_token_as::<auth_core::OAuthAccessTokenClaims>(actor_token)
        {
            Ok(c) if c.tenant_id == tenant_id => {
                if state
                    .oauth_as_service
                    .is_access_token_blocklisted(actor_token)
                    .await
                {
                    return oauth_error_json(
                        StatusCode::BAD_REQUEST,
                        oauth_error_codes::INVALID_GRANT,
                        "actor_token has been revoked",
                    );
                }
                Some(c)
            }
            Ok(_) => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_GRANT,
                    "actor_token tenant mismatch",
                )
            }
            Err(_) => {
                return oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_GRANT,
                    "actor_token is not a valid access token",
                )
            }
        }
    } else {
        None
    };

    // Verify the inbound subject token.
    let subject_claims = match state
        .jwt_service
        .verify_token_as::<auth_core::OAuthAccessTokenClaims>(subject_token)
    {
        Ok(c) if c.tenant_id == tenant_id => c,
        Ok(_) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_GRANT,
                "subject_token tenant mismatch",
            )
        }
        Err(_) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_GRANT,
                "subject_token is not a valid access token",
            )
        }
    };

    // Constrain new scope to the intersection of requested-scope and the
    // client's allowed scopes (never broaden vs. the inbound subject_token
    // scope either — fail-closed).
    let requested = req.scope.as_deref().unwrap_or(&subject_claims.scope);
    let allowed = OAuthAsService::resolve_scopes(&app, requested);
    let intersected: String = allowed
        .split_whitespace()
        .filter(|s| subject_claims.scope.split_whitespace().any(|x| x == *s))
        .filter(|s| {
            actor_claims
                .as_ref()
                .map(|actor| actor.scope.split_whitespace().any(|x| x == *s))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>()
        .join(" ");
    if intersected.is_empty() {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_SCOPE,
            "No allowed scopes after intersection with subject_token",
        );
    }

    let token_lifetime = app.token_lifetime_secs as i64;
    let confirmation = match crate::services::token_binding::confirmation_from_headers(headers) {
        Ok(cnf) => cnf,
        Err(e) => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                format!("Invalid token binding proof: {e}"),
            )
        }
    };
    let access_token = match state.oauth_as_service.issue_access_token_with_confirmation(
        &subject_claims.sub,
        "exchange",
        tenant_id,
        client_id,
        &intersected,
        token_lifetime,
        confirmation,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to issue exchanged access token");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Token generation failed",
            );
        }
    };
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": token_lifetime,
            "scope": intersected,
            "actor_sub": actor_claims.as_ref().map(|c| c.sub.clone()),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /oauth/userinfo — UserInfo Endpoint (OIDC Core §5.3)
// ═══════════════════════════════════════════════════════════════════════════════

async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<serde_json::Value>, Response> {
    // Extract and verify OAuth access token from Authorization header.
    // Userinfo MUST accept OAuth access tokens (OIDC Core §5.3.1).
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_REQUEST,
                "Missing Bearer token",
            )
        })?;

    let oauth_claims: OAuthAccessTokenClaims =
        state.jwt_service.verify_token_as(token).map_err(|_| {
            oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_REQUEST,
                "Invalid or expired access token",
            )
        })?;

    if oauth_claims.cnf.is_some() {
        let http_uri = absolute_htu(&headers, &uri);
        let cert_pem = decoded_header(&headers, "x-ssl-client-cert")
            .or_else(|| decoded_header(&headers, "x-client-cert"));
        let chain = crate::services::TokenBindingChain::new(
            std::sync::Arc::new(crate::services::DpopBinding::new(state.nonce_store.clone())),
            std::sync::Arc::new(crate::services::MtlsBinding),
        );
        let binding_req = crate::services::BindingRequest {
            http_method: "GET",
            http_uri: &http_uri,
            dpop_header: headers.get("dpop").and_then(|v| v.to_str().ok()),
            access_token: Some(token),
            client_cert_pem: cert_pem.as_deref(),
        };
        chain
            .verify(&oauth_claims, &binding_req)
            .await
            .map_err(|e| {
                oauth_error_json(
                    StatusCode::UNAUTHORIZED,
                    oauth_error_codes::INVALID_REQUEST,
                    format!("Token binding verification failed: {e}"),
                )
            })?;
    }

    // Check if the access token has been revoked
    if state
        .oauth_as_service
        .is_access_token_blocklisted(token)
        .await
    {
        return Err(oauth_error_json(
            StatusCode::UNAUTHORIZED,
            oauth_error_codes::INVALID_REQUEST,
            "Access token has been revoked",
        ));
    }

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
                oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "Internal error",
                )
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
            )
            .trim()
            .to_string();
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

fn absolute_htu(headers: &HeaderMap, uri: &Uri) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{}://{}{}", scheme, host, uri.path())
}

fn decoded_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| urlencoding::decode(v).ok().map(|s| s.into_owned()))
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
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Missing client_secret",
            )
        }
    };
    let _app = match state
        .oauth_as_service
        .authenticate_client(client_id, client_secret, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            )
        }
    };

    let token = match req.token.as_deref() {
        Some(t) => t,
        None => {
            // Per RFC 7009 §2.1: "The authorization server responds with HTTP status code 200"
            // even if the token doesn't exist
            return StatusCode::OK.into_response();
        }
    };

    let hint = req.token_type_hint.as_deref();

    // Use token_type_hint to optimise check order (RFC 7009 §2.1).
    // If the hint says "access_token", try JWT blocklisting first.
    // If the hint says "refresh_token" (or absent), try refresh token revocation first.
    match hint {
        Some("access_token") => {
            // Try as JWT access token first
            if let Ok(claims) = state
                .jwt_service
                .verify_token_as::<auth_core::OAuthAccessTokenClaims>(token)
            {
                let _ = state
                    .oauth_as_service
                    .blocklist_access_token(token, claims.exp)
                    .await;
            } else {
                // Hint may be wrong — fall back to refresh token
                let _ = state.oauth_as_service.revoke_token(token).await;
            }
        }
        _ => {
            // Default: try as refresh token first (most common case)
            let revoked = state
                .oauth_as_service
                .revoke_token(token)
                .await
                .unwrap_or(false);
            if !revoked {
                // Not a refresh token — try as JWT access token
                if let Ok(claims) = state
                    .jwt_service
                    .verify_token_as::<auth_core::OAuthAccessTokenClaims>(token)
                {
                    let _ = state
                        .oauth_as_service
                        .blocklist_access_token(token, claims.exp)
                        .await;
                }
            }
        }
    }

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
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let client_secret = match req.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Missing client_secret",
            )
        }
    };
    let app = match state
        .oauth_as_service
        .authenticate_client(client_id, client_secret, tenant_id)
        .await
    {
        Ok(app) => app,
        Err(_) => {
            return oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            )
        }
    };
    // Use the authenticated app's tenant_id for tenant isolation (not the user-supplied one)
    let verified_tenant = &app.tenant_id;

    // token_type_hint is accepted per RFC 7662 but introspection only handles
    // JWT access tokens so there is no branch to optimise.
    let _hint = req.token_type_hint;

    let token = match req.token.as_deref() {
        Some(t) => t,
        None => {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
    };

    // Try to verify as JWT access token.
    // First try to decode as OAuthAccessTokenClaims (has client_id + scope),
    // then fall back to internal Claims.
    if let Ok(oauth_claims) = state
        .jwt_service
        .verify_token_as::<auth_core::OAuthAccessTokenClaims>(token)
    {
        // Tenant isolation: token must belong to the same tenant as the requesting client
        if oauth_claims.tenant_id != *verified_tenant {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
        // Check if the token has been revoked (blocklisted)
        if state
            .oauth_as_service
            .is_access_token_blocklisted(token)
            .await
        {
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
// GET /api/oauth/consent — Check if consent exists (called after EIAA auth)
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
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        })?
        .ok_or_else(|| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "OAuth flow not found or expired",
            )
        })?;

    // Tenant isolation: the logged-in user must belong to the same tenant as the OAuth flow
    if ctx.tenant_id != claims.tenant_id {
        return Err(oauth_error_json(
            StatusCode::FORBIDDEN,
            oauth_error_codes::ACCESS_DENIED,
            "Tenant mismatch",
        ));
    }

    // Check if the app is first-party (skip consent)
    let app = state
        .oauth_as_service
        .get_client_by_client_id(&ctx.client_id, &ctx.tenant_id)
        .await
        .map_err(|_| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Unknown client",
            )
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
                oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "Internal error",
                )
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
// T2.6 — POST /api/oauth/device/approve — User-facing device approval
// (called by the SPA after the user enters their user_code and EIAA decides).
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct DeviceApproveRequest {
    pub user_code: String,
    pub approve: bool,
}

async fn approve_device(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<DeviceApproveRequest>,
) -> Result<Json<serde_json::Value>, Response> {
    // Look up first so we can fail-fast on tenant mismatch and surface a
    // 404-style response rather than leaking codes across tenants.
    let dev = state
        .oauth_as_service
        .get_device_by_user_code(&req.user_code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "device lookup failed");
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        })?
        .ok_or_else(|| {
            oauth_error_json(
                StatusCode::NOT_FOUND,
                oauth_error_codes::INVALID_REQUEST,
                "Unknown or expired user_code",
            )
        })?;
    if dev.tenant_id != claims.tenant_id {
        return Err(oauth_error_json(
            StatusCode::FORBIDDEN,
            oauth_error_codes::INVALID_REQUEST,
            "user_code is not for your tenant",
        ));
    }

    state
        .oauth_as_service
        .finalize_device_authorization(
            &req.user_code,
            req.approve,
            Some(&claims.sub),
            Some(&claims.sid),
            None,
        )
        .await
        .map_err(|e| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                e.to_string(),
            )
        })?;

    Ok(Json(serde_json::json!({
        "user_code": req.user_code,
        "state": if req.approve { "approved" } else { "denied" },
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /api/oauth/consent — Grant or deny consent, then issue code
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
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        })?
        .ok_or_else(|| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "OAuth flow not found or expired",
            )
        })?;

    // Tenant isolation: the logged-in user must belong to the same tenant as the OAuth flow
    if ctx.tenant_id != claims.tenant_id {
        return Err(oauth_error_json(
            StatusCode::FORBIDDEN,
            oauth_error_codes::ACCESS_DENIED,
            "Tenant mismatch",
        ));
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
        let _ = state
            .oauth_as_service
            .consume_authorization_context(&req.oauth_flow_id)
            .await;

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
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
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
        state: ctx.state.clone(),
    };

    let code = state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create authorization code");
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        })?;

    // Consume the authorization context (single-use)
    let _ = state
        .oauth_as_service
        .consume_authorization_context(&req.oauth_flow_id)
        .await;

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
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
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
            "pushed_authorization_request_endpoint": format!("{base_url}/oauth/par"),
            "require_pushed_authorization_requests": false,
            "device_authorization_endpoint": format!("{base_url}/oauth/device_authorization"),
            "jwks_uri": format!("{base_url}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "scopes_supported": org_manager::KNOWN_SCOPES,
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
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
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
