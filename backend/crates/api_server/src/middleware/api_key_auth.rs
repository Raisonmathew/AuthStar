//! API Key Authentication Middleware
//!
//! ## B-4 FIX: Transparent API key authentication alongside JWT auth.
//!
//! This middleware intercepts requests with `Authorization: Bearer ask_...` tokens
//! or `X-API-Key: ask_...` headers (used by official SDKs)
//! and resolves them to JWT-equivalent `Claims`, injecting them as an Extension
//! so all downstream route handlers work identically for both auth methods.
//!
//! ## Flow
//!
//! ```text
//! Request
//!   → api_key_auth_middleware
//!       → if Authorization header starts with "Bearer ask_"
//!         OR X-API-Key header starts with "ask_"
//!           → extract prefix from key
//!           → SELECT from api_keys WHERE key_prefix = ?
//!           → argon2id verify(full_key, stored_hash)
//!           → inject Claims extension (session_type = "service")
//!           → inject ApiKeyScopes extension
//!           → UPDATE last_used_at (fire-and-forget)
//!       → else: pass through (JWT auth handles it)
//!   → require_auth_ext (validates Claims extension exists)
//!   → route handler
//! ```
//!
//! ## Security Properties
//!
//! - Argon2id verification is constant-time against timing attacks
//! - Prefix lookup uses a partial index (WHERE revoked_at IS NULL) — fast
//! - Expired and revoked keys are rejected at the DB query level
//! - `last_used_at` update is fire-and-forget (non-blocking, best-effort)
//! - Invalid key format is rejected before any DB query
//! - API key scopes are stored in the `api_keys` table and injected as a
//!   request extension (`ApiKeyScopes`) for scope-aware route handlers.
//!   They are NOT placed in Claims (EIAA design: Claims = identity only).

use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

/// Scopes granted to an API key request.
/// Injected as an Extension alongside Claims for scope-aware handlers.
#[derive(Clone, Debug)]
pub struct ApiKeyScopes(#[allow(dead_code)] pub Vec<String>);

/// Axum middleware: authenticate API keys transparently alongside JWT.
///
/// If the `Authorization` header contains a `Bearer ask_...` token, this
/// middleware resolves it to `Claims` and injects them as an Extension.
/// If the header is absent or contains a JWT (not `ask_`), this middleware
/// is a no-op and passes the request through unchanged.
///
/// The downstream `require_auth_ext` middleware will reject requests that
/// have neither a valid JWT nor a valid API key.
pub async fn api_key_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Check for API key in two places:
    // 1. `Authorization: Bearer ask_...` (direct API usage)
    // 2. `X-API-Key: ask_...` (SDK usage — all official SDKs send this header)
    let full_key = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("Bearer ask_"))
        .map(|v| v.trim_start_matches("Bearer ").to_string())
        .or_else(|| {
            request
                .headers()
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.starts_with("ask_"))
                .map(|v| v.to_string())
        });

    if let Some(full_key) = full_key {
        match state.api_key_service.authenticate(&full_key).await {
            Ok(Some((user_id, tenant_id, scopes))) => {
                let now = chrono::Utc::now();

                // Build Claims equivalent to a JWT-authenticated request.
                // Claims = identity only (EIAA design — no scopes/roles in JWT).
                // API key scopes are injected separately as ApiKeyScopes extension.
                let claims = Claims {
                    sub: user_id.to_string(),
                    iss: state.config.jwt.issuer.clone(),
                    // aud is a single string in this Claims struct
                    aud: state.config.jwt.audience.clone(),
                    // exp: 1 hour from now (actual expiry enforced by DB expires_at)
                    exp: (now + chrono::Duration::hours(1)).timestamp(),
                    iat: now.timestamp(),
                    nbf: now.timestamp(),
                    // FLAW-C FIX: Use nil UUID as sentinel session ID.
                    //
                    // Previously: `format!("api_key:{}", user_id)` — a non-UUID string.
                    // Any code that binds claims.sid to a UUID column in PostgreSQL would
                    // get: ERROR: invalid input syntax for type uuid: "api_key:..."
                    // causing a 500 Internal Server Error.
                    //
                    // The nil UUID ("00000000-0000-0000-0000-000000000000") is a valid UUID
                    // that will never match a real session row. The session_type = "service"
                    // field is the authoritative signal that this is an API key session.
                    // verify_jwt_and_session() checks session_type and skips the DB lookup
                    // for service sessions, so the nil UUID is never queried.
                    sid: uuid::Uuid::nil().to_string(),
                    tenant_id: tenant_id.to_string(),
                    // "service" session type — API keys are machine-to-machine credentials
                    session_type: auth_core::jwt::session_types::SERVICE.to_string(),
                };

                tracing::debug!(
                    user_id = %user_id,
                    tenant_id = %tenant_id,
                    scopes = ?scopes,
                    "API key authentication successful"
                );

                // Inject Claims (identity) and ApiKeyScopes (authorization) separately
                request.extensions_mut().insert(claims);
                request.extensions_mut().insert(ApiKeyScopes(scopes));
            }
            Ok(None) => {
                // Invalid key — return 401 immediately, don't pass to JWT auth.
                // This prevents a timing oracle: attacker cannot distinguish
                // "wrong API key" from "not an API key" by observing which auth path ran.
                tracing::warn!("API key authentication failed: invalid or expired key");
                return axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Unauthorized","message":"Invalid API key"}"#,
                    ))
                    .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()));
            }
            Err(e) => {
                // DB error during key lookup — return 503
                tracing::error!(error = %e, "API key lookup failed due to DB error");
                return axum::response::Response::builder()
                    .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"ServiceUnavailable","message":"Authentication service temporarily unavailable"}"#,
                    ))
                    .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()));
            }
        }
    }

    next.run(request).await
}
