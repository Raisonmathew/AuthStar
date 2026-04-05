use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx;

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

// Issue #2 fix: Use shared token extraction utility to avoid duplication
use crate::middleware::token_utils::extract_bearer_token as extract_token;

pub async fn verify_jwt_and_session(
    state: &AppState,
    token: Option<String>,
    allow_provisional: bool,
) -> Result<auth_core::jwt::Claims, StatusCode> {
    let token = token.ok_or(StatusCode::UNAUTHORIZED)?;

    // 1. Verify JWT signature (fast, no DB hit)
    let claims = state
        .jwt_service
        .verify_token(&token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // FLAW-C FIX: API key sessions have no DB row in the sessions table.
    // The sentinel sid is uuid::Uuid::nil() — a valid UUID that will never match
    // a real session. Attempting to query it would return None → 401.
    //
    // Instead, short-circuit here: service sessions are already fully validated
    // by api_key_auth_middleware (key hash verified, expiry checked, revocation
    // checked). No further session DB lookup is needed or meaningful.
    if claims.session_type == auth_core::jwt::session_types::SERVICE {
        tracing::debug!(
            user_id = %claims.sub,
            tenant_id = %claims.tenant_id,
            "verify_jwt_and_session: service session (API key) — skipping DB session check"
        );
        return Ok(claims);
    }

    // 2. Verify session in DB — SCOPED TO TENANT to prevent cross-tenant hijack
    // Always fetch the session status to provide granular error responses.
    let session: Option<(bool, String)> = sqlx::query_as(
        r#"
        SELECT is_provisional, tenant_id
        FROM sessions
        WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE
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
                claims.sid,
                claims.tenant_id
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
