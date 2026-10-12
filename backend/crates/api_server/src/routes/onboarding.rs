//! Onboarding status route (US-05).
//!
//! `GET /api/v1/onboarding/status` — polled by the Get Started wizard's live
//! first-call indicator.  Returns whether the tenant has received its first
//! `authorize()` call so the wizard UI can flip from "Waiting…" to "✅ Live".
//!
//! ## Auth
//! Protected by `EiaaAuthzLayer` with the `admin:manage` action — the same
//! action that wraps other admin reads.  The tenant is resolved from the JWT
//! `tenant_id` claim, so there is no way to query another tenant's status.

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{extract::State, routing::get, Extension, Json, Router};
use shared_types::{AppError, Result};

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route("/onboarding/status", get(get_onboarding_status))
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct OnboardingStatusResponse {
    /// True once at least one `authorize()` call has been executed for this tenant.
    pub first_call_received: bool,
    /// Details of the most recent decision, if any.
    pub last_decision: Option<LastDecision>,
}

#[derive(serde::Serialize)]
pub struct LastDecision {
    pub tool: String,
    pub allowed: bool,
    pub audit_id: String,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

/// `GET /api/v1/onboarding/status`
///
/// Polled every 3 seconds by the signup wizard's live first-call indicator.
/// Queries `eiaa_executions` for the most recent row belonging to this tenant.
/// Returns in < 10ms — simple index scan on `(tenant_id, created_at DESC)`.
async fn get_onboarding_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<OnboardingStatusResponse>> {
    let tenant_id = &claims.tenant_id;

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("DB acquire: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("RLS context: onboarding status".into()))?;

    // Fetch the most recent execution for this tenant (if any).
    let row: Option<(String, bool, String)> = sqlx::query_as(
        r#"
        SELECT action, allow, id
        FROM eiaa_executions
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(Json(OnboardingStatusResponse {
        first_call_received: row.is_some(),
        last_decision: row.map(|(action, allow, id)| LastDecision {
            tool: action,
            allowed: allow,
            audit_id: id,
        }),
    }))
}
