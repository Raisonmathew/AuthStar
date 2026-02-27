use axum::{
    extract::{Request, State, Extension},
    http::{StatusCode, header},
    middleware::Next,
    response::{Response, IntoResponse},
};
use crate::state::AppState;
use tracing::instrument;
use sqlx;

/// Strict authentication: Requires valid JWT AND active (non-provisional) session.
/// Reads token from httpOnly cookie first, then falls back to Authorization header.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = extract_token(&req);
    match verify_jwt_and_session(&state, token, false).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Lenient authentication: Requires valid JWT, but allows provisional sessions (for step-up)
pub async fn require_auth_allow_provisional(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = extract_token(&req);
    match verify_jwt_and_session(&state, token, true).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Extension-based strict authentication (for use with middleware::from_fn)
/// Requires AppState to be injected as Extension before this middleware runs
pub async fn require_auth_ext(
    mut req: Request,
    next: Next,
) -> Response {
    let state = match req.extensions().get::<AppState>().cloned() {
        Some(s) => s,
        None => {
            tracing::error!("AppState not found in request extensions");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    
    let token = extract_token(&req);
    match verify_jwt_and_session(&state, token, false).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Extension-based lenient authentication (for use with middleware::from_fn)
/// Requires AppState to be injected as Extension before this middleware runs
pub async fn require_auth_allow_provisional_ext(
    mut req: Request,
    next: Next,
) -> Response {
    let state = match req.extensions().get::<AppState>().cloned() {
        Some(s) => s,
        None => {
            tracing::error!("AppState not found in request extensions");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    
    let token = extract_token(&req);
    match verify_jwt_and_session(&state, token, true).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Extract bearer token from request — cookie-first, header fallback.
///
/// Priority order:
/// 1. `__session` httpOnly cookie (browser clients via G12)
/// 2. `Authorization: Bearer <token>` header (server SDKs, API keys)
fn extract_token(req: &Request) -> Option<String> {
    // 1. Try httpOnly cookie
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("__session=") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    // 2. Fall back to Authorization header (server SDK, API key mode)
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    None
}

pub async fn verify_jwt_and_session(
    state: &AppState,
    token: Option<String>,
    allow_provisional: bool,
) -> Result<auth_core::jwt::Claims, StatusCode> {
    let token = token.ok_or(StatusCode::UNAUTHORIZED)?;

    // 1. Verify JWT signature (fast, no DB hit)
    let claims = state.jwt_service.verify_token(&token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // 2. Verify session in DB — SCOPED TO TENANT to prevent cross-tenant hijack
    // Always fetch the session status to provide granular error responses.
    let session: Option<(bool, String)> = sqlx::query_as(
        r#"
        SELECT is_provisional, tenant_id
        FROM sessions
        WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()
        "#,
    )
    .bind(&claims.sid)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Session DB check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match session {
        Some((is_provisional, _tenant_id)) => {
            if !allow_provisional && is_provisional {
                tracing::warn!(
                    "Provisional session access attempted for strict route (session: {}, tenant: {})",
                    claims.sid, claims.tenant_id
                );
                Err(StatusCode::FORBIDDEN) // Step-up required
            } else {
                Ok(claims)
            }
        }
        None => {
            tracing::warn!(
                "Session not found, expired, or wrong tenant: session={}, tenant={}",
                claims.sid, claims.tenant_id
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
