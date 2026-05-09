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

use crate::middleware::{
    evaluate_oauth_action, Action, EiaaDecisionArtifact, OAuthEiaaNetwork, OAuthEiaaRequest,
};
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
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use serde::Deserialize;
use shared_types::AppError;

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
        // Migration 070 — Dynamic Client Registration (RFC 7591)
        .route("/register", post(dynamic_client_registration))
        .route(
            "/register/:client_id",
            get(get_client_registration)
                .put(update_client_registration)
                .delete(delete_client_registration),
        )
}

/// OAuth UserInfo resource endpoint, protected by bearer-token EIAA middleware.
pub fn userinfo_router() -> Router<AppState> {
    Router::new().route("/userinfo", get(userinfo))
}

/// Token endpoint — separated for a stricter rate limit (brute-force protection).
pub fn token_router() -> Router<AppState> {
    Router::new().route("/token", post(token))
}

pub fn protected_read_router() -> Router<AppState> {
    Router::new().route("/consent", get(check_consent))
}

pub fn protected_consent_router() -> Router<AppState> {
    Router::new().route("/consent", post(grant_consent))
}

pub fn protected_device_router() -> Router<AppState> {
    Router::new().route("/device/approve", post(approve_device))
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
    /// Migration 070: response_mode (query | fragment | form_post | jwt | query.jwt | fragment.jwt | form_post.jwt)
    pub response_mode: Option<String>,
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
    /// Migration 070: response_mode
    pub response_mode: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PushedAuthorizationResponse {
    request_uri: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<serde_json::Value>,
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
    // Migration 070 — JWT Client Authentication (RFC 7523)
    /// Must be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" when using JWT auth.
    pub client_assertion_type: Option<String>,
    /// The signed client assertion JWT for private_key_jwt or client_secret_jwt.
    pub client_assertion: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
    // Migration 070 — JWT Client Authentication
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
    // Migration 070 — JWT Client Authentication
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
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

fn eiaa_oauth_error(error: AppError) -> Response {
    let status = error.status_code();
    // RFC 6749 §5.2 / RFC 9126 §2.3: OAuth protocol endpoints (token, PAR,
    // device_authorization, token_exchange) report capsule denials using the
    // grant/client error codes — never `invalid_token`, which is reserved
    // for bearer-token resource access (RFC 6750 §3.1) and is emitted by
    // `bearer_token_authz` instead.
    let code = match status {
        StatusCode::UNAUTHORIZED => oauth_error_codes::INVALID_CLIENT,
        StatusCode::FORBIDDEN => oauth_error_codes::INVALID_GRANT,
        StatusCode::BAD_REQUEST => oauth_error_codes::INVALID_REQUEST,
        _ => oauth_error_codes::SERVER_ERROR,
    };
    oauth_error_json(status, code, error.to_string())
}

fn eiaa_attestation_json(artifact: &EiaaDecisionArtifact) -> Option<serde_json::Value> {
    artifact
        .attestation
        .as_ref()
        .and_then(|attestation| serde_json::to_value(attestation).ok())
}

async fn stamp_session_decision_ref(
    state: &AppState,
    tenant_id: &str,
    session_id: &str,
    decision_ref: &str,
) {
    if session_id.is_empty() {
        return;
    }
    if let Err(error) = sqlx::query(
        "UPDATE sessions SET decision_ref = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(decision_ref)
    .bind(session_id)
    .bind(tenant_id)
    .execute(&state.db)
    .await
    {
        tracing::warn!(
            error = %error,
            session_id = %session_id,
            decision_ref = %decision_ref,
            "Failed to stamp OAuth EIAA decision_ref onto session"
        );
    }
}

// ─── Migration 070: JWT Client Authentication (RFC 7523) ──────────────────────

/// The URN for the JWT bearer client assertion type (RFC 7523 §2.2).
const JWT_BEARER_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Authenticate a client from a token-endpoint request, supporting three methods:
///   1. `client_secret_post` — `client_id` + `client_secret` in form body (default)
///   2. `private_key_jwt` — `client_assertion_type` = JWT_BEARER + `client_assertion` signed with client private key
///   3. `client_secret_jwt` — same assertion type but HMAC-signed with the client's raw symmetric key
///
/// Returns the authenticated `Application` or an error response.
async fn authenticate_client_from_request(
    state: &AppState,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    tenant_id: &str,
    token_endpoint_url: &str,
) -> Result<org_manager::Application, Response> {
    // JWT client authentication path
    if assertion_type == Some(JWT_BEARER_ASSERTION_TYPE) {
        let jwt = assertion.ok_or_else(|| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "client_assertion is required when client_assertion_type is jwt-bearer",
            )
        })?;

        return verify_client_assertion(state, jwt, client_id, tenant_id, token_endpoint_url)
            .await
            .map_err(|e| e);
    }

    // client_secret_post path (default)
    let cid = client_id.ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "Missing client_id",
        )
    })?;
    let secret = client_secret.ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "Missing client_secret",
        )
    })?;

    state
        .oauth_as_service
        .authenticate_client(cid, secret, tenant_id)
        .await
        .map_err(|_| {
            oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "Client authentication failed",
            )
        })
}

/// Verify a client assertion JWT for `private_key_jwt` or `client_secret_jwt`.
///
/// RFC 7523 §3 requirements validated:
///   - `iss` and `sub` both equal the client_id
///   - `aud` contains the token endpoint URL
///   - `exp` is present and not expired
///   - `jti` is unique (anti-replay via Redis)
///   - Signature verified with the appropriate key
async fn verify_client_assertion(
    state: &AppState,
    jwt: &str,
    client_id_hint: Option<&str>,
    tenant_id: &str,
    token_endpoint_url: &str,
) -> Result<org_manager::Application, Response> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    // Decode header to determine algorithm and kid
    let header = decode_header(jwt).map_err(|_| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "Invalid client_assertion JWT header",
        )
    })?;

    // Decode the payload WITHOUT signature verification first to extract `iss`/`sub`.
    // This is safe because we re-verify with the proper key below.
    #[derive(serde::Deserialize)]
    struct AssertionClaims {
        iss: Option<String>,
        sub: Option<String>,
        aud: Option<serde_json::Value>,
        exp: Option<i64>,
        jti: Option<String>,
    }
    let mut insecure_validation = Validation::new(header.alg);
    insecure_validation.insecure_disable_signature_validation();
    insecure_validation.validate_exp = false;
    insecure_validation.validate_aud = false;
    insecure_validation.validate_nbf = false;

    let payload: AssertionClaims =
        decode::<AssertionClaims>(jwt, &DecodingKey::from_secret(b""), &insecure_validation)
            .map_err(|_| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Malformed client_assertion JWT payload",
                )
            })?
            .claims;

    let iss = payload.iss.as_deref().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion missing iss claim",
        )
    })?;
    let sub = payload.sub.as_deref().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion missing sub claim",
        )
    })?;

    // RFC 7523 §3: iss == sub == client_id
    if iss != sub {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion iss and sub must both equal client_id",
        ));
    }
    if let Some(hint) = client_id_hint {
        if iss != hint {
            return Err(oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "client_assertion iss does not match client_id parameter",
            ));
        }
    }
    let client_id = iss;

    // Validate aud contains the token endpoint
    let aud_ok = match &payload.aud {
        Some(serde_json::Value::String(s)) => s == token_endpoint_url,
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .any(|v| v.as_str().map_or(false, |s| s == token_endpoint_url)),
        _ => false,
    };
    if !aud_ok {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion aud must contain the token endpoint URL",
        ));
    }

    // Validate exp
    let exp = payload.exp.ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion missing exp claim",
        )
    })?;
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err(oauth_error_json(
            StatusCode::UNAUTHORIZED,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion has expired",
        ));
    }
    // Cap assertion lifetime at 5 minutes (RFC 7523 §4 RECOMMENDS short-lived)
    if exp > now + 300 {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "client_assertion exp too far in the future (max 5 minutes)",
        ));
    }

    // NOTE: JTI anti-replay is intentionally deferred until AFTER signature
    // verification below. Consuming the JTI before verifying the signature would
    // let an unauthenticated attacker burn legitimate clients' JTIs in Redis,
    // causing a denial-of-service when the real client later submits the same
    // assertion (rejected as "replay detected").

    // Look up the application to determine auth method and retrieve keys
    let app = sqlx::query_as::<_, org_manager::Application>(
        "SELECT * FROM applications WHERE client_id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB lookup for client assertion");
        oauth_error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            oauth_error_codes::SERVER_ERROR,
            "Internal error",
        )
    })?
    .ok_or_else(|| {
        oauth_error_json(
            StatusCode::UNAUTHORIZED,
            oauth_error_codes::INVALID_CLIENT,
            "Unknown client_id",
        )
    })?;

    match app.token_endpoint_auth_method.as_str() {
        "private_key_jwt" => {
            // Fetch JWKS from the registered URI and verify signature
            let jwks_uri = app.jwks_uri.as_deref().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Client is not configured with a jwks_uri for private_key_jwt",
                )
            })?;

            let decoding_key =
                fetch_jwk_for_assertion(jwks_uri, header.kid.as_deref(), header.alg).await?;

            let mut validation = Validation::new(header.alg);
            validation.set_audience(&[token_endpoint_url]);
            validation.set_issuer(&[client_id]);
            validation.validate_nbf = false;

            decode::<serde_json::Value>(jwt, &decoding_key, &validation).map_err(|e| {
                oauth_error_json(
                    StatusCode::UNAUTHORIZED,
                    oauth_error_codes::INVALID_CLIENT,
                    format!("private_key_jwt signature verification failed: {e}"),
                )
            })?;
        }
        "client_secret_jwt" => {
            // Verify HMAC signature using stored raw symmetric key
            let hmac_key = app.hmac_secret_b64.as_deref().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Client is not configured with an HMAC key for client_secret_jwt",
                )
            })?;
            let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(hmac_key)
                .map_err(|_| {
                    oauth_error_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        oauth_error_codes::SERVER_ERROR,
                        "Internal key configuration error",
                    )
                })?;

            let decoding_key = DecodingKey::from_secret(&key_bytes);
            let alg = match header.alg {
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => header.alg,
                _ => Algorithm::HS256,
            };
            let mut validation = Validation::new(alg);
            validation.set_audience(&[token_endpoint_url]);
            validation.set_issuer(&[client_id]);
            validation.validate_nbf = false;

            decode::<serde_json::Value>(jwt, &decoding_key, &validation).map_err(|e| {
                oauth_error_json(
                    StatusCode::UNAUTHORIZED,
                    oauth_error_codes::INVALID_CLIENT,
                    format!("client_secret_jwt signature verification failed: {e}"),
                )
            })?;
        }
        _ => {
            return Err(oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Client is not configured for JWT client authentication",
            ));
        }
    }

    // Anti-replay: consume jti AFTER signature verification (see note above).
    // RFC 7523 §3 item 7: only authenticated assertions may consume the JTI.
    if let Some(jti) = &payload.jti {
        let remaining = (exp - now).max(1);
        let first_use = state
            .oauth_as_service
            .consume_jti(jti, remaining)
            .await
            .map_err(|_| {
                oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "Internal error",
                )
            })?;
        if !first_use {
            return Err(oauth_error_json(
                StatusCode::UNAUTHORIZED,
                oauth_error_codes::INVALID_CLIENT,
                "client_assertion jti has already been used (replay detected)",
            ));
        }
    }

    Ok(app)
}

/// Returns `true` only for IP addresses that are safe to issue outbound HTTPS
/// requests to from a server context — i.e. globally routable unicast addresses.
/// Rejects loopback, link-local, private, multicast, broadcast, unspecified,
/// shared-address-space (CGN), benchmarking, documentation, and IPv6 ULAs to
/// prevent SSRF against cloud metadata endpoints and internal services.
fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
            {
                return false;
            }
            // 100.64.0.0/10 — RFC 6598 Carrier-Grade NAT
            if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
                return false;
            }
            // 169.254.0.0/16 covered by is_link_local; explicitly block AWS metadata
            if o == [169, 254, 169, 254] {
                return false;
            }
            // 198.18.0.0/15 — RFC 2544 benchmarking
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return false;
            }
            // 192.0.0.0/24 — IETF protocol assignments
            if o[0] == 192 && o[1] == 0 && o[2] == 0 {
                return false;
            }
            // 240.0.0.0/4 — reserved
            if o[0] >= 240 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg = v6.segments();
            // fc00::/7 — Unique Local Addresses
            if (seg[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // fe80::/10 — link-local
            if (seg[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // ::ffff:0:0/96 — IPv4-mapped: re-check as v4
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0xffff
            {
                let v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return is_public_ip(&IpAddr::V4(v4));
            }
            // 64:ff9b::/96 NAT64 — let through (translates to public v4 by design)
            // 2001::/23 IETF assignments — block 2001:db8::/32 (documentation)
            if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                return false;
            }
            true
        }
    }
}

/// Fetch a JWK from a JWKS URI and convert it to a `DecodingKey`.
/// Selects the key matching `kid` if provided; otherwise uses the first key.
async fn fetch_jwk_for_assertion(
    jwks_uri: &str,
    kid: Option<&str>,
    alg: jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, Response> {
    // Security: only allow HTTPS JWKS URIs (prevent SSRF via HTTP)
    if !jwks_uri.starts_with("https://") {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "jwks_uri must use HTTPS",
        ));
    }

    // Defence-in-depth SSRF guard: parse the URL, resolve the host, and reject
    // any address that points at private/loopback/link-local space (e.g.
    // 169.254.169.254 cloud metadata, 10.0.0.0/8, 127.0.0.0/8, ::1, fc00::/7).
    let after_scheme = &jwks_uri["https://".len()..];
    // Strip path/query/fragment
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo if present
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Split host:port (handle IPv6 brackets)
    let (host, port): (&str, u16) = if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 literal
        let end = rest.find(']').ok_or_else(|| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "jwks_uri has malformed IPv6 host",
            )
        })?;
        let h = &rest[..end];
        let p = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(443);
        (h, p)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(443))
    } else {
        (host_port, 443u16)
    };
    if host.is_empty() {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "jwks_uri must include a host",
        ));
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "JWKS host resolution failed for {host}");
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Failed to resolve jwks_uri host",
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "jwks_uri host did not resolve to any address",
        ));
    }
    for sa in &addrs {
        if !is_public_ip(&sa.ip()) {
            tracing::warn!(addr = %sa.ip(), "Refusing JWKS fetch to non-public address");
            return Err(oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "jwks_uri host resolves to a non-public address",
            ));
        }
    }

    let jwks: serde_json::Value = reqwest::get(jwks_uri)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to fetch JWKS from {jwks_uri}");
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Failed to fetch client JWKS",
            )
        })?
        .json()
        .await
        .map_err(|_| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "Invalid JWKS response",
            )
        })?;

    let keys = jwks["keys"].as_array().ok_or_else(|| {
        oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "JWKS missing keys array",
        )
    })?;

    // Select the key matching kid, or the first key if no kid
    let key = if let Some(kid) = kid {
        keys.iter()
            .find(|k| k["kid"].as_str().map_or(false, |k| k == kid))
            .ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "No JWK matching kid found",
                )
            })?
    } else {
        keys.first().ok_or_else(|| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_CLIENT,
                "JWKS contains no keys",
            )
        })?
    };

    use jsonwebtoken::{Algorithm, DecodingKey};
    match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let n = key["n"].as_str().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "JWK missing n",
                )
            })?;
            let e = key["e"].as_str().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "JWK missing e",
                )
            })?;
            DecodingKey::from_rsa_components(n, e).map_err(|_| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Invalid RSA JWK",
                )
            })
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let x = key["x"].as_str().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "JWK missing x",
                )
            })?;
            let y = key["y"].as_str().ok_or_else(|| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "JWK missing y",
                )
            })?;
            DecodingKey::from_ec_components(x, y).map_err(|_| {
                oauth_error_json(
                    StatusCode::BAD_REQUEST,
                    oauth_error_codes::INVALID_CLIENT,
                    "Invalid EC JWK",
                )
            })
        }
        _ => Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_CLIENT,
            "Unsupported algorithm in client JWKS",
        )),
    }
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
            response_mode: par_ctx.response_mode.clone(),
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

    // Validate response_mode (default = "query")
    let response_mode = params.response_mode.as_deref().unwrap_or("query");
    match response_mode {
        "query" | "fragment" | "form_post" | "jwt" | "query.jwt" | "fragment.jwt"
        | "form_post.jwt" => {}
        _ => {
            return Err(oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                format!("Unsupported response_mode: {response_mode}"),
            ));
        }
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
        response_mode: Some(response_mode.to_string()),
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
    headers: HeaderMap,
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
        if req.code_challenge.as_deref().is_none_or(|s| s.is_empty()) {
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

    let par_decision = match evaluate_oauth_action(
        &state,
        OAuthEiaaRequest {
            action: Action::OAuthPar.as_str(),
            subject_id: client_id,
            tenant_id,
            session_id: None,
            session_type: auth_core::jwt::session_types::SERVICE,
            client_id,
            scope: Some(&scope),
            grant_type: Some("pushed_authorization_request"),
            method: "POST",
            path: "/oauth/par",
            network: OAuthEiaaNetwork::from_headers(&headers),
            confirmation_jkt: None,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };

    let ctx = AuthorizationContext {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope,
        state: req.state,
        code_challenge: req.code_challenge,
        code_challenge_method: req.code_challenge_method,
        tenant_id: tenant_id.to_string(),
        nonce: req.nonce,
        response_mode: req.response_mode,
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
            decision_ref: Some(par_decision.decision_ref.clone()),
            attestation_ref: par_decision.attestation_ref.clone(),
            attestation: eiaa_attestation_json(&par_decision),
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

    // Authenticate client — support confidential (secret/JWT assertion) and public (PKCE-only).
    let token_endpoint_url = format!(
        "{}/oauth/token",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let app = if req.client_assertion_type.is_some() {
        // JWT client authentication (private_key_jwt or client_secret_jwt)
        match verify_client_assertion(
            state,
            req.client_assertion.as_deref().unwrap_or(""),
            req.client_id.as_deref(),
            tenant_id,
            &token_endpoint_url,
        )
        .await
        {
            Ok(app) => app,
            Err(e) => return e,
        }
    } else if let Some(secret) = req.client_secret.as_deref() {
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
        && !confirmation
            .as_ref()
            .map(|c| c.jkt.is_some())
            .unwrap_or(false)
    {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            oauth_error_codes::INVALID_REQUEST,
            "FAPI 2.0 requires DPoP proof-of-possession; include a DPoP header",
        );
    }
    let confirmation_jkt = confirmation.as_ref().and_then(|cnf| cnf.jkt.as_deref());
    let token_decision = match evaluate_oauth_action(
        state,
        OAuthEiaaRequest {
            action: Action::OAuthToken.as_str(),
            subject_id: &code_ctx.user_id,
            tenant_id: &code_ctx.tenant_id,
            session_id: Some(&code_ctx.session_id),
            session_type: auth_core::jwt::session_types::END_USER,
            client_id,
            scope: Some(&code_ctx.scope),
            grant_type: Some("authorization_code"),
            method: "POST",
            path: "/oauth/token",
            network: OAuthEiaaNetwork::from_headers(headers),
            confirmation_jkt,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };
    stamp_session_decision_ref(
        state,
        &code_ctx.tenant_id,
        &code_ctx.session_id,
        &token_decision.decision_ref,
    )
    .await;

    let access_token = match state
        .oauth_as_service
        .issue_access_token_with_confirmation_and_eiaa_refs(
            &code_ctx.user_id,
            &code_ctx.session_id,
            &code_ctx.tenant_id,
            client_id,
            &code_ctx.scope,
            token_lifetime,
            confirmation,
            Some(&token_decision.decision_ref),
            token_decision.attestation_ref.as_deref(),
            Some(&token_decision.action),
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
            // Migration 070: offline_access scope → long-lived "offline" token (30 days).
            // Regular tokens remain session-bound with the configured lifetime.
            let (kind, rt_lifetime) = if scope_has_offline {
                ("offline", 30 * 24 * 3600i64) // 30 days
            } else {
                ("online", app.refresh_token_lifetime_secs as i64)
            };
            match state
                .oauth_as_service
                .create_refresh_token(
                    client_id,
                    &code_ctx.user_id,
                    &code_ctx.session_id,
                    &code_ctx.tenant_id,
                    &code_ctx.scope,
                    rt_lifetime,
                    Some(&token_decision.decision_ref),
                    ip_addr.as_deref(),
                    user_agent.as_deref(),
                    kind,
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
            .issue_id_token_with_eiaa_refs(
                &code_ctx.user_id,
                &code_ctx.tenant_id,
                client_id,
                code_ctx.nonce.as_deref(),
                &access_token,
                &code_ctx.scope,
                token_lifetime,
                code_ctx.state.as_deref(),
                Some(&token_decision.decision_ref),
                token_decision.attestation_ref.as_deref(),
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
        decision_ref: Some(token_decision.decision_ref.clone()),
        attestation_ref: token_decision.attestation_ref.clone(),
        attestation: eiaa_attestation_json(&token_decision),
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

    // Authenticate client — support client_secret_post and JWT assertion methods
    let token_endpoint_url = format!(
        "{}/oauth/token",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let app = match authenticate_client_from_request(
        state,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion_type.as_deref(),
        req.client_assertion.as_deref(),
        tenant_id,
        &token_endpoint_url,
    )
    .await
    {
        Ok(app) => app,
        Err(e) => return e,
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
    let confirmation_jkt = confirmation.as_ref().and_then(|cnf| cnf.jkt.as_deref());
    let token_decision = match evaluate_oauth_action(
        state,
        OAuthEiaaRequest {
            action: Action::OAuthToken.as_str(),
            subject_id: &old_rt.user_id,
            tenant_id: &old_rt.tenant_id,
            session_id: Some(&old_rt.session_id),
            session_type: auth_core::jwt::session_types::END_USER,
            client_id,
            scope: Some(&scope),
            grant_type: Some("refresh_token"),
            method: "POST",
            path: "/oauth/token",
            network: OAuthEiaaNetwork::from_headers(headers),
            confirmation_jkt,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };
    stamp_session_decision_ref(
        state,
        &old_rt.tenant_id,
        &old_rt.session_id,
        &token_decision.decision_ref,
    )
    .await;

    let access_token = match state
        .oauth_as_service
        .issue_access_token_with_confirmation_and_eiaa_refs(
            &old_rt.user_id,
            &old_rt.session_id,
            &old_rt.tenant_id,
            client_id,
            &scope,
            token_lifetime,
            confirmation,
            Some(&token_decision.decision_ref),
            token_decision.attestation_ref.as_deref(),
            Some(&token_decision.action),
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
            Some(&token_decision.decision_ref),
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
            .issue_id_token_with_eiaa_refs(
                &old_rt.user_id,
                &old_rt.tenant_id,
                client_id,
                None, // nonce is single-use; not replayed on refresh
                &access_token,
                &scope,
                token_lifetime,
                None, // no state on refresh grant
                Some(&token_decision.decision_ref),
                token_decision.attestation_ref.as_deref(),
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
        decision_ref: Some(token_decision.decision_ref.clone()),
        attestation_ref: token_decision.attestation_ref.clone(),
        attestation: eiaa_attestation_json(&token_decision),
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

    // Authenticate client — supports client_secret_post and JWT assertion methods
    let token_endpoint_url = format!(
        "{}/oauth/token",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let app = match authenticate_client_from_request(
        state,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion_type.as_deref(),
        req.client_assertion.as_deref(),
        tenant_id,
        &token_endpoint_url,
    )
    .await
    {
        Ok(app) => app,
        Err(e) => return e,
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
    let confirmation_jkt = confirmation.as_ref().and_then(|cnf| cnf.jkt.as_deref());
    let token_decision = match evaluate_oauth_action(
        state,
        OAuthEiaaRequest {
            action: Action::OAuthClientCredentials.as_str(),
            subject_id: client_id,
            tenant_id,
            session_id: None,
            session_type: auth_core::jwt::session_types::SERVICE,
            client_id,
            scope: Some(&scope),
            grant_type: Some("client_credentials"),
            method: "POST",
            path: "/oauth/token",
            network: OAuthEiaaNetwork::from_headers(headers),
            confirmation_jkt,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };

    let access_token = match state
        .oauth_as_service
        .issue_client_token_with_confirmation_and_eiaa_refs(
            tenant_id,
            client_id,
            &scope,
            token_lifetime,
            confirmation,
            Some(&token_decision.decision_ref),
            token_decision.attestation_ref.as_deref(),
            Some(&token_decision.action),
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
        decision_ref: Some(token_decision.decision_ref.clone()),
        attestation_ref: token_decision.attestation_ref.clone(),
        attestation: eiaa_attestation_json(&token_decision),
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
    headers: HeaderMap,
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

    let device_decision = match evaluate_oauth_action(
        &state,
        OAuthEiaaRequest {
            action: Action::OAuthDeviceAuthorization.as_str(),
            subject_id: client_id,
            tenant_id,
            session_id: None,
            session_type: auth_core::jwt::session_types::SERVICE,
            client_id,
            scope: Some(&scope),
            grant_type: Some("device_authorization"),
            method: "POST",
            path: "/oauth/device_authorization",
            network: OAuthEiaaNetwork::from_headers(&headers),
            confirmation_jkt: None,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };

    let dev = match state
        .oauth_as_service
        .start_device_authorization(
            client_id,
            tenant_id,
            &scope,
            Some(&device_decision.decision_ref),
        )
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
            "decision_ref": device_decision.decision_ref,
            "attestation_ref": device_decision.attestation_ref,
            "attestation": eiaa_attestation_json(&device_decision),
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
            let confirmation_jkt = confirmation.as_ref().and_then(|cnf| cnf.jkt.as_deref());
            let token_decision = match evaluate_oauth_action(
                state,
                OAuthEiaaRequest {
                    action: Action::OAuthToken.as_str(),
                    subject_id: user_id,
                    tenant_id,
                    session_id: Some(session_id),
                    session_type: auth_core::jwt::session_types::END_USER,
                    client_id,
                    scope: Some(&dev.scope),
                    grant_type: Some("device_code"),
                    method: "POST",
                    path: "/oauth/token",
                    network: OAuthEiaaNetwork::from_headers(headers),
                    confirmation_jkt,
                },
            )
            .await
            {
                Ok(decision) => decision,
                Err(error) => return eiaa_oauth_error(error),
            };
            stamp_session_decision_ref(state, tenant_id, session_id, &token_decision.decision_ref)
                .await;

            let access_token = match state
                .oauth_as_service
                .issue_access_token_with_confirmation_and_eiaa_refs(
                    user_id,
                    session_id,
                    tenant_id,
                    client_id,
                    &dev.scope,
                    token_lifetime,
                    confirmation,
                    Some(&token_decision.decision_ref),
                    token_decision.attestation_ref.as_deref(),
                    Some(&token_decision.action),
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
                decision_ref: Some(token_decision.decision_ref.clone()),
                attestation_ref: token_decision.attestation_ref.clone(),
                attestation: eiaa_attestation_json(&token_decision),
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
    // Support client_secret_post and JWT assertion methods (RFC 8693 §2.1 requires confidential client)
    let token_endpoint_url = format!(
        "{}/oauth/token",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let app = match authenticate_client_from_request(
        state,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion_type.as_deref(),
        req.client_assertion.as_deref(),
        tenant_id,
        &token_endpoint_url,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return e,
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
    let confirmation_jkt = confirmation.as_ref().and_then(|cnf| cnf.jkt.as_deref());
    let token_decision = match evaluate_oauth_action(
        state,
        OAuthEiaaRequest {
            action: Action::OAuthToken.as_str(),
            subject_id: &subject_claims.sub,
            tenant_id,
            session_id: if subject_claims.sid.is_empty() {
                None
            } else {
                Some(subject_claims.sid.as_str())
            },
            session_type: if subject_claims.sid.is_empty() {
                auth_core::jwt::session_types::SERVICE
            } else {
                auth_core::jwt::session_types::END_USER
            },
            client_id,
            scope: Some(&intersected),
            grant_type: Some("token_exchange"),
            method: "POST",
            path: "/oauth/token",
            network: OAuthEiaaNetwork::from_headers(headers),
            confirmation_jkt,
        },
    )
    .await
    {
        Ok(decision) => decision,
        Err(error) => return eiaa_oauth_error(error),
    };
    if !subject_claims.sid.is_empty() {
        stamp_session_decision_ref(
            state,
            tenant_id,
            &subject_claims.sid,
            &token_decision.decision_ref,
        )
        .await;
    }

    let access_token = match state
        .oauth_as_service
        .issue_access_token_with_confirmation_and_eiaa_refs(
            &subject_claims.sub,
            "exchange",
            tenant_id,
            client_id,
            &intersected,
            token_lifetime,
            confirmation,
            Some(&token_decision.decision_ref),
            token_decision.attestation_ref.as_deref(),
            Some(&token_decision.action),
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
            "decision_ref": token_decision.decision_ref,
            "attestation_ref": token_decision.attestation_ref,
            "attestation": eiaa_attestation_json(&token_decision),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET /oauth/userinfo — UserInfo Endpoint (OIDC Core §5.3)
// ═══════════════════════════════════════════════════════════════════════════════

async fn userinfo(
    State(state): State<AppState>,
    Extension(oauth_claims): Extension<OAuthAccessTokenClaims>,
) -> Result<Json<serde_json::Value>, Response> {
    // The bearer_token_authz middleware has already verified the OAuth access
    // token, revocation state, token binding, and EIAA resource decision.
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

// ═══════════════════════════════════════════════════════════════════════════════
// POST /oauth/revoke — Token Revocation (RFC 7009)
// ═══════════════════════════════════════════════════════════════════════════════

async fn revoke(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<RevokeRequest>,
) -> Response {
    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Authenticate client (required for revocation) — supports JWT assertions
    let _client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let token_endpoint_url = format!(
        "{}/oauth/revoke",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let _app = match authenticate_client_from_request(
        &state,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion_type.as_deref(),
        req.client_assertion.as_deref(),
        tenant_id,
        &token_endpoint_url,
    )
    .await
    {
        Ok(app) => app,
        Err(e) => return e,
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

    // Authenticate requesting client — supports JWT assertions (RFC 7662 §2.1)
    let _client_id = match req.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => {
            return oauth_error_json(
                StatusCode::BAD_REQUEST,
                oauth_error_codes::INVALID_REQUEST,
                "Missing client_id",
            )
        }
    };
    let introspect_endpoint_url = format!(
        "{}/oauth/introspect",
        state.config.jwt.issuer.trim_end_matches('/')
    );
    let app = match authenticate_client_from_request(
        &state,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.client_assertion_type.as_deref(),
        req.client_assertion.as_deref(),
        tenant_id,
        &introspect_endpoint_url,
    )
    .await
    {
        Ok(app) => app,
        Err(e) => return e,
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
        // Client binding (RFC 7662 §2.2): token is only active if the introspecting
        // client is the token's intended audience (client_id match or aud match).
        // Exception: token.aud may contain the requesting client_id explicitly.
        let token_aud = &oauth_claims.aud;
        let requesting_client_id = &app.client_id;
        let audience_match = token_aud == requesting_client_id
            || token_aud
                .split(' ')
                .any(|a| a == requesting_client_id.as_str());
        let is_token_owner = oauth_claims.client_id == *requesting_client_id;
        if !is_token_owner && !audience_match {
            return (StatusCode::OK, Json(IntrospectionResponse::inactive())).into_response();
        }
        let eiaa_action = oauth_claims.eiaa_action.clone().or_else(|| {
            // Backwards-compat: tokens issued before the `eiaa_action` claim
            // existed don't carry the action explicitly. Fall back to the
            // structural inference (sid==empty ⇒ client_credentials).
            Some(if oauth_claims.sid.is_empty() {
                Action::OAuthClientCredentials.as_str().to_string()
            } else {
                Action::OAuthToken.as_str().to_string()
            })
        });
        let resp = IntrospectionResponse {
            active: true,
            sub: Some(oauth_claims.sub),
            client_id: Some(oauth_claims.client_id),
            scope: Some(oauth_claims.scope),
            exp: Some(oauth_claims.exp),
            iat: Some(oauth_claims.iat),
            token_type: Some("Bearer".to_string()),
            tenant_id: Some(oauth_claims.tenant_id),
            decision_ref: oauth_claims.decision_ref,
            attestation_ref: oauth_claims.attestation_ref,
            eiaa_action,
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
            decision_ref: None,
            attestation_ref: None,
            eiaa_action: None,
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
    eiaa: Option<Extension<EiaaDecisionArtifact>>,
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

    let eiaa_artifact = eiaa.map(|Extension(artifact)| artifact);
    state
        .oauth_as_service
        .finalize_device_authorization(
            &req.user_code,
            req.approve,
            Some(&claims.sub),
            Some(&claims.sid),
            eiaa_artifact
                .as_ref()
                .map(|artifact| artifact.decision_ref.as_str()),
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
        "decision_ref": eiaa_artifact.as_ref().map(|artifact| artifact.decision_ref.clone()),
        "attestation_ref": eiaa_artifact.as_ref().and_then(|artifact| artifact.attestation_ref.clone()),
        "attestation": eiaa_artifact.as_ref().and_then(eiaa_attestation_json),
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST /api/oauth/consent — Grant or deny consent, then issue code
// ═══════════════════════════════════════════════════════════════════════════════

async fn grant_consent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    eiaa: Option<Extension<EiaaDecisionArtifact>>,
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
        // User denied consent — honour the requested response_mode (query/fragment/
        // form_post and the JARM .jwt variants) so clients receive access_denied
        // through the channel they negotiated. Clean up first so a JARM build
        // failure still releases the authorization context.
        let _ = state
            .oauth_as_service
            .consume_authorization_context(&req.oauth_flow_id)
            .await;

        let mut params: Vec<(String, String)> = vec![
            (
                "error".to_string(),
                oauth_error_codes::ACCESS_DENIED.to_string(),
            ),
            (
                "error_description".to_string(),
                "User denied consent".to_string(),
            ),
        ];
        if let Some(ref s) = ctx.state {
            params.push(("state".to_string(), s.clone()));
        }
        return Ok(Json(build_authorize_response(
            &state.oauth_as_service,
            &ctx,
            params,
        )?));
    }

    // Record consent using the decision_ref produced by EIAA middleware.
    let eiaa_artifact = eiaa.map(|Extension(artifact)| artifact);
    let decision_ref = eiaa_artifact
        .as_ref()
        .map(|artifact| artifact.decision_ref.clone())
        .unwrap_or_else(|| shared_types::generate_id("dec_oauth"));
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
        decision_ref: Some(decision_ref.clone()),
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

    // Collect response parameters
    let mut params: Vec<(String, String)> = vec![("code".to_string(), code.clone())];
    if let Some(ref s) = ctx.state {
        params.push(("state".to_string(), s.clone()));
    }

    Ok(Json(build_authorize_response(
        &state.oauth_as_service,
        &ctx,
        params,
    )?))
}

/// Build a consent/authorization response honouring `ctx.response_mode`
/// (`query` | `fragment` | `form_post`, optionally with `.jwt` for JARM).
/// Used by both the grant and deny branches of [`grant_consent`] so that
/// `access_denied` errors are delivered through the same channel the client
/// negotiated.
fn build_authorize_response(
    oauth_as_service: &OAuthAsService,
    ctx: &AuthorizationContext,
    params: Vec<(String, String)>,
) -> Result<serde_json::Value, Response> {
    let response_mode = ctx.response_mode.as_deref().unwrap_or("query");

    let build_query = |params: &[(String, String)]| -> String {
        params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    };

    let is_jwt_mode = response_mode.ends_with(".jwt") || response_mode == "jwt";
    let (effective_mode, response_params): (String, Vec<(String, String)>) = if is_jwt_mode {
        let jwt_params: serde_json::Value =
            params
                .iter()
                .fold(serde_json::json!({}), |mut obj, (k, v)| {
                    obj[k] = serde_json::Value::String(v.clone());
                    obj
                });
        match oauth_as_service.build_jarm_jwt(&ctx.client_id, jwt_params) {
            Ok(jarm_jwt) => {
                let base_mode = if response_mode == "jwt" {
                    "query".to_string()
                } else {
                    response_mode
                        .strip_suffix(".jwt")
                        .unwrap_or("query")
                        .to_string()
                };
                (base_mode, vec![("response".to_string(), jarm_jwt)])
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to build JARM JWT");
                return Err(oauth_error_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth_error_codes::SERVER_ERROR,
                    "Failed to build JARM response",
                ));
            }
        }
    } else {
        (response_mode.to_string(), params)
    };

    Ok(match effective_mode.as_str() {
        "form_post" => {
            let form_params: serde_json::Value =
                response_params
                    .iter()
                    .fold(serde_json::json!({}), |mut obj, (k, v)| {
                        obj[k] = serde_json::Value::String(v.clone());
                        obj
                    });
            serde_json::json!({
                "response_mode": "form_post",
                "form_action": ctx.redirect_uri,
                "form_params": form_params,
            })
        }
        "fragment" => {
            let fragment = build_query(&response_params);
            serde_json::json!({
                "redirect_uri": format!("{}#{}", ctx.redirect_uri, fragment),
            })
        }
        _ => {
            let query = build_query(&response_params);
            serde_json::json!({
                "redirect_uri": format!("{}?{}", ctx.redirect_uri, query),
            })
        }
    })
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
            "registration_endpoint": format!("{base_url}/oauth/register"),
            "jwks_uri": format!("{base_url}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"],
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
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none", "private_key_jwt", "client_secret_jwt"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "name", "given_name", "family_name", "email", "email_verified", "picture", "eiaa_decision_ref", "eiaa_attestation_ref"],
            "eiaa_authorization_model": "capsule_attestation",
            "eiaa_actions_supported": [
                Action::OAuthConsent.as_str(),
                Action::OAuthToken.as_str(),
                Action::OAuthClientCredentials.as_str(),
                Action::OAuthPar.as_str(),
                Action::OAuthDeviceAuthorization.as_str(),
                Action::OAuthResource.as_str()
            ],
            "eiaa_token_response_fields_supported": ["decision_ref", "attestation_ref", "attestation"],
            "eiaa_introspection_fields_supported": ["decision_ref", "attestation_ref", "eiaa_action"],
            "eiaa_attestation_signing_alg_values_supported": ["EdDSA"],
            "eiaa_attestation_hash_alg_values_supported": ["BLAKE3", "SHA-256"],
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

// ═══════════════════════════════════════════════════════════════════════════════
// Dynamic Client Registration — RFC 7591 / RFC 7592
// POST   /oauth/register             — register new client (no auth required)
// GET    /oauth/register/:client_id  — read registration (requires RAT)
// PUT    /oauth/register/:client_id  — update registration (requires RAT)
// DELETE /oauth/register/:client_id  — delete registration (requires RAT)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, serde::Deserialize)]
struct DcrRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    scope: Option<String>,
    contacts: Option<Vec<String>>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
    token_endpoint_auth_method: Option<String>,
    tenant_id: Option<String>,
}

/// Helper: extract Bearer token from `Authorization: Bearer <token>` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// POST /oauth/register — RFC 7591 §3.1
async fn dynamic_client_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DcrRequest>,
) -> Response {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    // ── RFC 7591 §3 — Initial Access Token gate ─────────────────────────────
    // Without this, anyone on the internet could register OAuth clients into
    // any tenant, exhaust the database, and use jwks_uri as an SSRF amplifier.
    let configured_iat = match state.config.oauth_dcr_initial_access_token.as_deref() {
        Some(t) => t,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Dynamic Client Registration is disabled. \
                        Set OAUTH_DCR_INITIAL_ACCESS_TOKEN to enable.",
                })),
            )
                .into_response();
        }
    };
    let presented = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer realm=\"oauth-register\"")],
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Initial Access Token required",
                })),
            )
                .into_response();
        }
    };
    // Constant-time comparison to avoid timing oracle on the token.
    let presented_bytes = presented.as_bytes();
    let configured_bytes = configured_iat.as_bytes();
    let token_ok = presented_bytes.len() == configured_bytes.len()
        && presented_bytes
            .iter()
            .zip(configured_bytes.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !token_ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Bearer realm=\"oauth-register\", error=\"invalid_token\"",
            )],
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Invalid Initial Access Token",
            })),
        )
            .into_response();
    }

    let tenant_id = resolve_tenant(req.tenant_id.as_deref());

    // Validate required fields
    let redirect_uris = match req.redirect_uris {
        Some(ref uris) if !uris.is_empty() => uris.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": "redirect_uris is required and must not be empty",
                })),
            )
                .into_response();
        }
    };

    // Reject non-HTTPS redirect_uris for production (allow localhost for dev)
    for uri in &redirect_uris {
        let is_localhost =
            uri.starts_with("http://localhost") || uri.starts_with("http://127.0.0.1");
        let is_https = uri.starts_with("https://");
        if !is_localhost && !is_https {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uris must use HTTPS",
                })),
            )
                .into_response();
        }
    }

    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let supported_methods = [
        "client_secret_post",
        "client_secret_basic",
        "none",
        "private_key_jwt",
        "client_secret_jwt",
    ];
    if !supported_methods.contains(&token_endpoint_auth_method) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client_metadata",
                "error_description": "Unsupported token_endpoint_auth_method",
            })),
        )
            .into_response();
    }

    // private_key_jwt requires jwks_uri
    if token_endpoint_auth_method == "private_key_jwt" && req.jwks_uri.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client_metadata",
                "error_description": "jwks_uri is required for private_key_jwt",
            })),
        )
            .into_response();
    }

    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let allowed_flows_json =
        serde_json::to_value(&grant_types).unwrap_or(serde_json::json!(["authorization_code"]));
    let allowed_scopes_json = serde_json::to_value(
        req.scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .collect::<Vec<_>>(),
    )
    .unwrap_or(serde_json::json!(["openid"]));

    // Generate client credentials
    let client_id = shared_types::generate_id("dcr");
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let client_secret_raw = URL_SAFE_NO_PAD.encode(&secret_bytes);

    // Hash/wrap secret via the configured SecretStore so deployments using
    // AwsKmsSecretStore or HashiCorpVaultSecretStore stay consistent with the
    // verify_secret path used by the token endpoint.
    let secret_hash = match state
        .oauth_as_service
        .store_client_secret(&client_id, &client_secret_raw)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "SecretStore failed to store DCR client secret");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Failed to register client",
            );
        }
    };

    // For client_secret_jwt: also store raw b64 HMAC key
    let hmac_secret_b64: Option<String> = if token_endpoint_auth_method == "client_secret_jwt" {
        Some(client_secret_raw.clone())
    } else {
        None
    };

    // Generate registration access token (RAT)
    let mut rat_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rat_bytes);
    let rat_raw = URL_SAFE_NO_PAD.encode(&rat_bytes);
    let rat_hash = hex::encode(Sha256::digest(rat_raw.as_bytes()));

    let client_name = req.client_name.unwrap_or_else(|| client_id.clone());
    let scope_str = req.scope.as_deref().unwrap_or("openid");
    let issued_at = chrono::Utc::now().timestamp();
    let base_url = state.config.jwt.issuer.trim_end_matches('/');
    let registration_client_uri = format!("{base_url}/oauth/register/{client_id}");

    // Insert into applications
    let result = sqlx::query(
        r#"
        INSERT INTO applications (
            id, client_id, name, client_secret_hash, hmac_secret_b64, tenant_id,
            type, redirect_uris, allowed_scopes, allowed_flows,
            token_endpoint_auth_method, jwks_uri,
            is_dynamic, registration_access_token_hash,
            token_lifetime_secs, fapi_profile
        ) VALUES (
            generate_prefixed_id('app'), $1, $2, $3, $4, $5,
            'web', $6::jsonb, $7::jsonb, $8::jsonb,
            $9, $10,
            TRUE, $11,
            3600, 'none'
        )
        "#,
    )
    .bind(&client_id)
    .bind(&client_name)
    .bind(&secret_hash)
    .bind(&hmac_secret_b64)
    .bind(tenant_id)
    .bind(serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".to_string()))
    .bind(
        serde_json::to_string(&allowed_scopes_json).unwrap_or_else(|_| r#"["openid"]"#.to_string()),
    )
    .bind(
        serde_json::to_string(&allowed_flows_json)
            .unwrap_or_else(|_| r#"["authorization_code"]"#.to_string()),
    )
    .bind(token_endpoint_auth_method)
    .bind(&req.jwks_uri)
    .bind(&rat_hash)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        tracing::error!(error = %e, "Failed to register dynamic client");
        return oauth_error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            oauth_error_codes::SERVER_ERROR,
            "Failed to register client",
        );
    }

    // RFC 7591 §3.2.1 response
    let mut resp = serde_json::json!({
        "client_id": client_id,
        "client_secret": client_secret_raw,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "scope": scope_str,
        "registration_access_token": rat_raw,
        "registration_client_uri": registration_client_uri,
        "client_id_issued_at": issued_at,
    });
    if let Some(jwks_uri) = &req.jwks_uri {
        resp["jwks_uri"] = serde_json::Value::String(jwks_uri.clone());
    }
    if let Some(contacts) = &req.contacts {
        resp["contacts"] = serde_json::json!(contacts);
    }

    (StatusCode::CREATED, Json(resp)).into_response()
}

/// GET /oauth/register/:client_id — RFC 7592 §2.1
async fn get_client_registration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    use sha2::{Digest, Sha256};

    let rat = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing registration access token",
                })),
            )
                .into_response();
        }
    };

    let rat_hash = hex::encode(Sha256::digest(rat.as_bytes()));

    // Use runtime query to avoid compile-time DB check for migration-070 columns
    let row = sqlx::query(
        r#"
        SELECT client_id, name, redirect_uris, allowed_scopes, allowed_flows,
               token_endpoint_auth_method, jwks_uri, registration_access_token_hash,
               is_dynamic, tenant_id
        FROM applications
        WHERE client_id = $1
          AND is_dynamic = TRUE
          AND registration_access_token_hash = $2
        "#,
    )
    .bind(&client_id)
    .bind(&rat_hash)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(r)) => {
            use sqlx::Row as _;
            let base_url = state.config.jwt.issuer.trim_end_matches('/');
            let cid: String = r.try_get("client_id").unwrap_or_default();
            let name: String = r.try_get("name").unwrap_or_default();
            let redirect_uris: serde_json::Value =
                r.try_get("redirect_uris").unwrap_or(serde_json::json!([]));
            let scope: serde_json::Value =
                r.try_get("allowed_scopes").unwrap_or(serde_json::json!([]));
            let grant_types: serde_json::Value =
                r.try_get("allowed_flows").unwrap_or(serde_json::json!([]));
            let auth_method: String = r.try_get("token_endpoint_auth_method").unwrap_or_default();
            let jwks_uri: Option<String> = r.try_get("jwks_uri").unwrap_or(None);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "client_id": cid,
                    "client_name": name,
                    "redirect_uris": redirect_uris,
                    "scope": scope,
                    "grant_types": grant_types,
                    "token_endpoint_auth_method": auth_method,
                    "jwks_uri": jwks_uri,
                    "registration_client_uri": format!("{base_url}/oauth/register/{cid}"),
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Invalid registration access token or client not found",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch client registration");
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

/// PUT /oauth/register/:client_id — RFC 7592 §2.2 (update metadata)
async fn update_client_registration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<DcrRequest>,
) -> Response {
    use sha2::{Digest, Sha256};

    let rat = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing registration access token",
                })),
            )
                .into_response();
        }
    };

    let rat_hash = hex::encode(Sha256::digest(rat.as_bytes()));

    // Verify RAT using runtime query (migration-070 columns)
    let existing = sqlx::query(
        "SELECT id FROM applications WHERE client_id = $1 AND is_dynamic = TRUE AND registration_access_token_hash = $2",
    )
    .bind(&client_id)
    .bind(&rat_hash)
    .fetch_optional(&state.db)
    .await;

    let app_id: String = match existing {
        Ok(Some(r)) => {
            use sqlx::Row as _;
            r.try_get("id").unwrap_or_default()
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Invalid registration access token or client not found",
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to verify RAT");
            return oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            );
        }
    };

    // Update non-core fields (use allowed_flows for grant_types)
    let allowed_flows_json: Option<String> = req.grant_types.as_ref().map(|gt| {
        serde_json::to_string(gt).unwrap_or_else(|_| r#"["authorization_code"]"#.to_string())
    });
    let allowed_scopes_json: Option<String> = req.scope.as_deref().map(|s| {
        let scopes: Vec<&str> = s.split_whitespace().collect();
        serde_json::to_string(&scopes).unwrap_or_else(|_| r#"["openid"]"#.to_string())
    });
    let redirect_uris_json: Option<String> = req
        .redirect_uris
        .as_ref()
        .map(|uris| serde_json::to_string(uris).unwrap_or_else(|_| "[]".to_string()));

    let result = sqlx::query(
        r#"
        UPDATE applications SET
            name = COALESCE($2, name),
            redirect_uris = CASE WHEN $3::text IS NOT NULL THEN $3::jsonb ELSE redirect_uris END,
            allowed_scopes = CASE WHEN $4::text IS NOT NULL THEN $4::jsonb ELSE allowed_scopes END,
            allowed_flows = CASE WHEN $5::text IS NOT NULL THEN $5::jsonb ELSE allowed_flows END,
            token_endpoint_auth_method = COALESCE($6, token_endpoint_auth_method),
            jwks_uri = COALESCE($7, jwks_uri)
        WHERE id = $1
        "#,
    )
    .bind(&app_id)
    .bind(&req.client_name)
    .bind(&redirect_uris_json)
    .bind(&allowed_scopes_json)
    .bind(&allowed_flows_json)
    .bind(req.token_endpoint_auth_method.as_deref())
    .bind(req.jwks_uri.as_deref())
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "client_id": client_id, "updated": true })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update client registration");
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        }
    }
}

/// DELETE /oauth/register/:client_id — RFC 7592 §2.3 (deregister)
async fn delete_client_registration(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    use sha2::{Digest, Sha256};

    let rat = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing registration access token",
                })),
            )
                .into_response();
        }
    };

    let rat_hash = hex::encode(Sha256::digest(rat.as_bytes()));

    let result = sqlx::query(
        "DELETE FROM applications WHERE client_id = $1 AND is_dynamic = TRUE AND registration_access_token_hash = $2",
    )
    .bind(&client_id)
    .bind(&rat_hash)
    .execute(&state.db)
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Invalid registration access token or client not found",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete client registration");
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth_error_codes::SERVER_ERROR,
                "Internal error",
            )
        }
    }
}
