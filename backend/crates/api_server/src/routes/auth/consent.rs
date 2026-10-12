//! Agent Consent Flow handler (Gap 3-B).
//!
//! ## Endpoints
//!
//! - `GET  /consent/:flow_id`           — Hosted consent screen (public, served by frontend)
//! - `POST /api/auth/flow/:id/consent`  — User approves/denies agent delegation (this file)
//!
//! ## Route placement
//!
//! The approval handler is mounted at the final-router level alongside `step_up_routes`,
//! NOT inside `protected_routes` (no active-subscription check required — users must
//! always be able to revoke agent access regardless of plan status).

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::services::promote_session;
use crate::state::AppState;
use auth_core::{jwt::session_types, Claims};
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, AppError, Result};

// ─── Router ───────────────────────────────────────────────────────────────────

/// Consent approval route.  Protected by `EiaaAuthzLayer` for `user:consent`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/:flow_id/consent", post(approve_consent))
        .route("/:flow_id/consent", get(get_consent_info))
}

/// Revocation route — users revoke a previously granted delegation.
pub fn revocation_router() -> Router<AppState> {
    Router::new()
        .route("/delegations", get(list_delegations))
        .route("/delegations/:delegation_id/revoke", post(revoke_delegation))
}

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ConsentApprovalRequest {
    /// Tools the user is consenting to delegate (subset of what the agent requested).
    pub allowed_tools: Vec<String>,
    /// Agent identifier from the consent screen state.
    pub agent_id: String,
    /// Task identifier for this delegation session.
    pub task_id: String,
    /// TTL in seconds (e.g. 3600).  Capped at 86400 (24 h).
    pub ttl_seconds: i64,
    /// Human-readable agent name shown in the consent screen.
    #[serde(default)]
    pub agent_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsentApprovalResponse {
    /// Signed agent JWT to be returned to the requesting MCP client via OAuth redirect.
    pub agent_token: String,
    /// Stable delegation grant ID (can be used to revoke later).
    pub delegation_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct DelegationSummary {
    pub id: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub allowed_tools: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConsentInfoResponse {
    pub flow_id: String,
    /// Agent metadata pre-loaded for the consent UI.
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub requested_tools: Vec<String>,
    pub ttl_seconds: i64,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/auth/flow/:flow_id/consent`
///
/// Returns the pending consent info for a flow so the frontend consent page can
/// render the agent name, requested tools, and TTL.
pub async fn get_consent_info(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
) -> Result<Json<ConsentInfoResponse>> {
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
        Option<i64>,
    )> = sqlx::query_as(
        r#"
        SELECT
            meta->>'agent_id',
            meta->>'agent_name',
            meta->'requested_tools',
            (meta->>'ttl_seconds')::bigint
        FROM auth_flows
        WHERE id = $1
          AND state NOT IN ('completed', 'failed', 'expired')
        LIMIT 1
        "#,
    )
    .bind(&flow_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("consent info query: {e}")))?;

    let (agent_id, agent_name, tools_json, ttl) = row
        .ok_or_else(|| AppError::NotFound(format!("Consent flow not found: {flow_id}")))?;

    let requested_tools: Vec<String> = tools_json
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    Ok(Json(ConsentInfoResponse {
        flow_id,
        agent_id,
        agent_name,
        requested_tools,
        ttl_seconds: ttl.unwrap_or(3600),
    }))
}

/// `POST /api/auth/flow/:flow_id/consent`
///
/// The user approves the agent delegation.  This handler:
///   1. Validates the session is non-provisional (human, not agent/service).
///   2. Executes the `"user:consent"` EIAA capsule via the outer `EiaaAuthzLayer`
///      (the capsule runs before this handler is called — the layer has already
///      written the attestation and the decision is Allow by the time we get here).
///   3. Persists the delegation grant in `agent_delegations`.
///   4. Issues a signed agent JWT with `delegation_chain: [user_id]`.
///   5. Promotes the session to record the `"agent_consent"` capability.
pub async fn approve_consent(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Path(flow_id): Path<String>,
    Json(req): Json<ConsentApprovalRequest>,
) -> Result<Json<ConsentApprovalResponse>> {
    // ── Guard: only human sessions may grant delegation ──────────────────────
    if claims.session_type != session_types::ADMIN
        && claims.session_type != session_types::END_USER
    {
        return Err(AppError::Forbidden(
            "Only authenticated human sessions may grant agent delegation".into(),
        ));
    }

    // ── Guard: session must not be provisional ───────────────────────────────
    // (EiaaAuthzLayer already enforces this via AAL check, but belt-and-suspenders)
    if claims.sid.is_empty() {
        return Err(AppError::Forbidden(
            "Invalid session — cannot grant delegation without an active session".into(),
        ));
    }

    // ── Validate TTL ─────────────────────────────────────────────────────────
    let ttl = req.ttl_seconds.max(60).min(86400);

    // ── Verify the agent exists and is active for this tenant ─────────────────
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("consent: acquire conn: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("consent: RLS context: {e}")))?;

    let agent_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM agent_principals WHERE tenant_id = $1 AND agent_id = $2 AND active = TRUE)",
    )
    .bind(&claims.tenant_id)
    .bind(&req.agent_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("consent: agent lookup: {e}")))?;

    if !agent_exists {
        return Err(AppError::NotFound(format!(
            "Agent '{}' not found or inactive",
            req.agent_id
        )));
    }

    // ── Persist the delegation grant ─────────────────────────────────────────
    let delegation_id = generate_id("del");
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl);
    let tools_json = serde_json::to_value(&req.allowed_tools)
        .map_err(|e| AppError::Internal(format!("consent: tools serialization: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO agent_delegations
            (id, tenant_id, user_id, agent_id, allowed_tools, oauth_flow_id, expires_at,
             created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        "#,
    )
    .bind(&delegation_id)
    .bind(&claims.tenant_id)
    .bind(&claims.sub)
    .bind(&req.agent_id)
    .bind(&tools_json)
    .bind(&flow_id)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        // BUG 3 FIX: The partial-unique index on (tenant_id, user_id, agent_id)
        // WHERE revoked = FALSE prevents duplicate active delegations.
        // Convert the unique-violation to a user-facing 409 Conflict instead of 500.
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.code().as_deref() == Some("23505") {
                return AppError::Conflict(
                    "An active delegation already exists for this agent. \
                     Revoke the existing delegation before creating a new one."
                        .into(),
                );
            }
        }
        AppError::Internal(format!("consent: insert delegation: {e}"))
    })?;

    // ── Issue agent JWT ──────────────────────────────────────────────────────
    let now = chrono::Utc::now();
    let agent_claims = Claims {
        sub: req.agent_id.clone(),
        iss: state.config.jwt.issuer.clone(),
        aud: state.config.jwt.audience.clone(),
        exp: now.timestamp() + ttl,
        iat: now.timestamp(),
        nbf: now.timestamp(),
        // Agent tokens are not session-bound.
        sid: String::new(),
        tenant_id: claims.tenant_id.clone(),
        session_type: session_types::AGENT.to_string(),
        agent_id: Some(req.agent_id.clone()),
        model_id: None,
        model_version: None,
        task_id: Some(req.task_id.clone()),
        // delegation_chain records the granting user so audit can trace back to consent.
        delegation_chain: Some(vec![claims.sub.clone()]),
        allowed_tools: if req.allowed_tools.is_empty() {
            None
        } else {
            Some(req.allowed_tools.clone())
        },
        principal_source: Some("consent".to_string()),
    };

    let agent_token = state
        .jwt_service
        .sign_claims(&agent_claims)
        .map_err(|e| AppError::Internal(format!("consent: sign agent token: {e}")))?;

    // ── Promote session with agent_consent capability ────────────────────────
    let _ = promote_session(
        &state.db,
        &claims.sid,
        &claims.sub,
        &claims.tenant_id,
        1, // AAL1 minimum — the EiaaAuthzLayer already enforced the actual required AAL
        "agent_consent",
    )
    .await;
    // Non-fatal: session promotion failure does not invalidate the issued JWT.

    tracing::info!(
        tenant_id  = %claims.tenant_id,
        user_id    = %claims.sub,
        agent_id   = %req.agent_id,
        task_id    = %req.task_id,
        flow_id    = %flow_id,
        delegation_id = %delegation_id,
        ttl        = ttl,
        "Agent delegation granted via consent"
    );

    Ok(Json(ConsentApprovalResponse {
        agent_token,
        delegation_id,
        agent_id: req.agent_id,
        task_id: req.task_id,
        expires_in: ttl,
    }))
}

/// `POST /api/v1/user/delegations/:delegation_id/revoke`
///
/// Revokes a previously granted agent delegation.  Sets `revoked = TRUE` in
/// `agent_delegations` and writes the Redis blocklist key so `EiaaAuthzLayer`
/// denies the agent's token within 100ms.
pub async fn revoke_delegation(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Path(delegation_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("revoke: acquire conn: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("revoke: RLS context: {e}")))?;

    // Fetch the delegation to get the agent_id (needed for Redis blocklist key).
    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT agent_id, user_id
        FROM agent_delegations
        WHERE id = $1
          AND tenant_id = $2
          AND revoked = FALSE
        LIMIT 1
        "#,
    )
    .bind(&delegation_id)
    .bind(&claims.tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("revoke: fetch delegation: {e}")))?;

    let (agent_id, owner_user_id) = row.ok_or_else(|| {
        AppError::NotFound(format!(
            "Active delegation '{}' not found",
            delegation_id
        ))
    })?;

    // Only the granting user or an admin may revoke.
    if owner_user_id != claims.sub && claims.session_type != session_types::ADMIN {
        return Err(AppError::Forbidden(
            "You can only revoke your own delegations".into(),
        ));
    }

    // Mark revoked in DB.
    sqlx::query(
        r#"
        UPDATE agent_delegations
        SET revoked = TRUE,
            revoked_at = NOW(),
            revoked_by = $1,
            updated_at = NOW()
        WHERE id = $2
          AND tenant_id = $3
        "#,
    )
    .bind(&claims.sub)
    .bind(&delegation_id)
    .bind(&claims.tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("revoke: update delegation: {e}")))?;

    // Write Redis blocklist key — format matches EiaaAuthzLayer's check at
    // eiaa_authz.rs:436: `"agent_blocklist:{agent_id}"`.
    // TTL: 86400 s (max agent token lifetime) so the key outlives any outstanding token.
    let blocklist_key = format!("agent_blocklist:{agent_id}");
    let mut redis = state.redis.clone();
    if let Err(e) = redis::cmd("SET")
        .arg(&blocklist_key)
        .arg(1u8)
        .arg("EX")
        .arg(86400i64)
        .query_async::<_, ()>(&mut redis)
        .await
    {
        tracing::warn!(
            agent_id = %agent_id,
            error = %e,
            "Failed to write agent blocklist key to Redis — revocation may be delayed until next DB check"
        );
    }

    tracing::info!(
        tenant_id     = %claims.tenant_id,
        revoker_id    = %claims.sub,
        agent_id      = %agent_id,
        delegation_id = %delegation_id,
        "Agent delegation revoked"
    );

    Ok(Json(serde_json::json!({
        "revoked": true,
        "delegation_id": delegation_id,
        "agent_id": agent_id,
    })))
}

/// `GET /api/v1/user/delegations`
///
/// Returns the list of active (non-revoked, non-expired) agent delegations
/// for the authenticated user. Used by the frontend Delegations settings page
/// so users can see which agents they have authorized and revoke any of them.
pub async fn list_delegations(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> Result<Json<Vec<DelegationSummary>>> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("list_delegations: acquire conn: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|e| AppError::Internal(format!("list_delegations: RLS context: {e}")))?;

    let rows: Vec<(String, String, Option<String>, serde_json::Value, chrono::DateTime<Utc>, chrono::DateTime<Utc>)> =
        sqlx::query_as(
            r#"
            SELECT
                d.id,
                d.agent_id,
                ap.name,
                d.allowed_tools,
                d.expires_at,
                d.created_at
            FROM agent_delegations d
            LEFT JOIN agent_principals ap
                ON ap.agent_id = d.agent_id AND ap.tenant_id = d.tenant_id
            WHERE d.user_id    = $1
              AND d.tenant_id  = $2
              AND d.revoked    = FALSE
              AND d.expires_at > NOW()
            ORDER BY d.created_at DESC
            LIMIT 100
            "#,
        )
        .bind(&claims.sub)
        .bind(&claims.tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("list_delegations: query: {e}")))?;

    let delegations: Vec<DelegationSummary> = rows
        .into_iter()
        .map(|(id, agent_id, agent_name, tools_json, expires_at, created_at)| {
            let allowed_tools: Vec<String> = serde_json::from_value(tools_json).unwrap_or_default();
            DelegationSummary {
                id,
                agent_id,
                agent_name,
                allowed_tools,
                expires_at,
                created_at,
            }
        })
        .collect();

    Ok(Json(delegations))
}
