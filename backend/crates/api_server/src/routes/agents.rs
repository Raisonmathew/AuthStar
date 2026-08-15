//! Agent Principal routes (Sprint A + F — Non-Human Principal Support + Revocation)
//!
//! ## Endpoints
//! - `POST   /api/v1/agents/register`          — Register or update a pre-registered agent
//! - `POST   /api/v1/agents/token`             — Issue an agent JWT for a task
//! - `GET    /api/v1/agents`                   — List agent principals for the tenant
//! - `GET    /api/v1/agents/:agent_id`         — Get a single agent principal
//! - `DELETE /api/v1/agents/:agent_id`         — Soft-deactivate an agent (sets active=false)
//! - `POST   /api/v1/agents/:agent_id/revoke`  — Immediately invalidate all active tokens for this agent
//!
//! ## Authorization
//! Write routes and revocation require the `agent:manage` EIAA action.
//! Token-issuance requires `agent:token`.
//! Both are protected by `EiaaAuthzLayer` in `router.rs`.
//!
//! ## Agent JWT structure
//! Issued tokens are standard AuthStar JWTs with `session_type = "agent"` and
//! the optional agent claims (`agent_id`, `model_id`, `task_id`, `delegation_chain`,
//! `allowed_tools`, `principal_source`) populated from the registered principal.
//! The token is signed by the platform `JwtService` (ES256).
//!
//! ## Revocation model (Sprint F)
//! Agent tokens use empty `sid` so they cannot be revoked via the session store.
//! Instead, revocation writes a Redis key `agent_blocklist:{agent_id}` with a TTL
//! equal to the registered `token_ttl_seconds`.  The `eiaa_authz` middleware and
//! introspection endpoint check this key before authorizing any request carrying
//! an agent JWT.

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::middleware::{evaluate_oauth_action, OAuthEiaaNetwork, OAuthEiaaRequest};
use crate::services::policy_compiler::{AgentScopeConfig, PolicyCompiler};
use crate::state::AppState;
use auth_core::jwt::{session_types, Claims};
use redis;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

// ─── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    /// Human-readable name for this agent.
    pub name: String,
    /// LLM model identifier, e.g. "claude-3-5-sonnet-20241022".
    pub model_id: Option<String>,
    /// Space-separated EIAA action strings to restrict this agent to.
    /// Empty = inherit from compiled capsule policy.
    pub allowed_tools: Option<String>,
    /// Maximum delegation chain depth (1–8, default 3).
    pub max_delegation_depth: Option<i16>,
    /// Token TTL in seconds (60–86400, default 3600).
    pub token_ttl_seconds: Option<i32>,
    /// Optional CIMD metadata URL for hybrid pre-registered + CIMD agents.
    pub cimd_metadata_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub name: String,
    pub model_id: Option<String>,
    pub allowed_tools: String,
    pub max_delegation_depth: i16,
    pub token_ttl_seconds: i32,
    pub principal_source: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct IssueAgentTokenRequest {
    /// The agent_id from the registered principal.
    pub agent_id: String,
    /// Task identifier — groups all tool calls in this task for audit chaining.
    pub task_id: String,
    /// Delegation chain so far (newest delegator first).
    /// The EIAA capsule enforces MAX_SUBCAPSULE_DEPTH (8).
    #[serde(default)]
    pub delegation_chain: Vec<String>,
    /// Override allowed_tools for this specific task (must be a subset of the
    /// registered principal's `allowed_tools`; omit to use the registered value).
    pub allowed_tools: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct IssueAgentTokenResponse {
    pub token: String,
    pub agent_id: String,
    pub task_id: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AgentPrincipalRow {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub model_id: Option<String>,
    pub allowed_tools: String,
    pub max_delegation_depth: i16,
    pub token_ttl_seconds: i32,
    pub principal_source: String,
    pub cimd_metadata_url: Option<String>,
    pub active: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

// ─── Routers ───────────────────────────────────────────────────────────────────

/// Manage routes — protected by `agent:manage` EIAA action in router.rs.
/// `require_auth_ext` is applied at the group level in router.rs.
pub fn manage_router() -> Router<AppState> {
    Router::new()
        .route("/agents/register", post(register_agent))
        .route("/agents", get(list_agents))
        .route("/agents/:agent_id", get(get_agent))
        // Sprint F: deactivation + token revocation
        .route("/agents/:agent_id", delete(deactivate_agent))
        .route("/agents/:agent_id/revoke", post(revoke_agent_tokens))
        // Update agent metadata + capsule re-seeding
        .route("/agents/:agent_id", put(update_agent))
}

/// Token-issuance route — protected by `agent:token` EIAA action in router.rs.
/// `require_auth_ext` is applied at the group level in router.rs.
pub fn token_router() -> Router<AppState> {
    Router::new().route("/agents/token", post(issue_agent_token))
}

/// Authorize route — called by agent JWTs to check tool-call permission.
///
/// This route does **not** get an outer `EiaaAuthzLayer` in `router.rs`
/// because the handler itself calls `evaluate_oauth_action()` internally,
/// passing the agent JWT claims + the requested `tool_name` as the action.
/// An outer EIAA layer would require a different, generic action and run a
/// second capsule execution — doubling the cost with no extra security.
pub fn authorize_router() -> Router<AppState> {
    Router::new().route("/agents/:agent_id/authorize", post(authorize_tool_call))
}

/// Record route — called by agent JWTs after a successful tool execution.
///
/// Protected by `agent:manage` EIAA action because only the agent itself (or
/// an admin on its behalf) should be able to write execution records.
pub fn record_router() -> Router<AppState> {
    Router::new().route("/agents/:agent_id/executions", post(record_execution))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/agents/register
///
/// Upsert a pre-registered agent principal.  If an agent with the same `name`
/// already exists for this tenant, its mutable fields are updated.
async fn register_agent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<(StatusCode, Json<RegisterAgentResponse>)> {
    let tenant_id = &claims.tenant_id;

    // Validate depth and TTL bounds
    let max_depth = req.max_delegation_depth.unwrap_or(3);
    if !(1..=8).contains(&max_depth) {
        return Err(AppError::Validation(
            "max_delegation_depth must be between 1 and 8".into(),
        ));
    }
    let ttl = req.token_ttl_seconds.unwrap_or(3600);
    if !(60..=86400).contains(&ttl) {
        return Err(AppError::Validation(
            "token_ttl_seconds must be between 60 and 86400".into(),
        ));
    }

    let allowed_tools = req.allowed_tools.unwrap_or_default();

    // m-1: Validate that cimd_metadata_url, if provided, is HTTPS
    if let Some(ref url) = req.cimd_metadata_url {
        if !url.starts_with("https://") {
            return Err(AppError::Validation(
                "cimd_metadata_url must use the https:// scheme".into(),
            ));
        }
    }

    // C-3: Set RLS context so the INSERT is tenant-scoped
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set agent register RLS context".into()))?;

    // M-2: Generate agent_id inside SQL to avoid wasted UUID on the UPDATE path
    let row: AgentPrincipalRow = sqlx::query_as(
        r#"
        INSERT INTO agent_principals
            (tenant_id, agent_id, name, model_id, allowed_tools,
             max_delegation_depth, token_ttl_seconds, principal_source, cimd_metadata_url)
        VALUES ($1, 'agt_' || replace(gen_random_uuid()::text, '-', ''), $2, $3, $4, $5, $6, 'pre_registered', $7)
        ON CONFLICT (tenant_id, name) WHERE active = TRUE
        DO UPDATE SET
            model_id             = EXCLUDED.model_id,
            allowed_tools        = EXCLUDED.allowed_tools,
            max_delegation_depth = EXCLUDED.max_delegation_depth,
            token_ttl_seconds    = EXCLUDED.token_ttl_seconds,
            cimd_metadata_url    = EXCLUDED.cimd_metadata_url,
            updated_at           = NOW()
        RETURNING id, agent_id, name, model_id, allowed_tools,
                  max_delegation_depth, token_ttl_seconds, principal_source,
                  cimd_metadata_url, active, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(&req.name)
    .bind(&req.model_id)
    .bind(&allowed_tools)
    .bind(max_depth)
    .bind(ttl)
    .bind(&req.cimd_metadata_url)
    .fetch_one(&mut *conn)
    .await?;

    tracing::info!(
        tenant_id = %tenant_id,
        agent_id = %row.agent_id,
        name = %row.name,
        "Agent principal registered"
    );

    // B.4: Auto-compile and persist agent-specific capsules for each allowed
    // action so that the `agent:<action>` dispatch in `eiaa_authz` has
    // something to resolve immediately — no manual admin step required.
    //
    // One capsule is compiled per whitespace-separated tool/action in
    // `allowed_tools`.  The capsule key is `"agent:{tool_name}"`.
    // Compilation is best-effort: a failure here does NOT fail the registration
    // — the middleware fallback to the human capsule remains available.
    if !row.allowed_tools.is_empty() {
        let model_id = row.model_id.clone().unwrap_or_default();
        let max_depth = row.max_delegation_depth as u8;
        let now = chrono::Utc::now().timestamp();
        let not_after = now + 365 * 24 * 3600; // 1-year capsule validity

        for tool in row.allowed_tools.split_whitespace() {
            let agent_action = format!("agent:{tool}");
            let scope = AgentScopeConfig {
                model_id: model_id.clone(),
                max_depth,
                risk_deny_threshold: 60,
                action: agent_action.clone(),
                resource: tool.to_string(),
            };
            let ast = PolicyCompiler::compile_agent_scope_policy(&scope);

            match capsule_compiler::compile(
                ast,
                tenant_id.clone(),
                agent_action.clone(),
                now,
                not_after,
                &state.ks,
                &state.compiler_kid,
            ) {
                Ok(signed) => {
                    let meta_json = match serde_json::to_value(&signed.meta) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                agent_action = %agent_action,
                                "B.4: capsule meta serialise failed: {e}"
                            );
                            continue;
                        }
                    };
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                    let capsule_hash_b64 = URL_SAFE_NO_PAD.encode(
                        hex::decode(&signed.wasm_hash).unwrap_or_default(),
                    );
                    // LOW-1 FIX: Use the RLS-scoped connection instead of the
                    // bare pool (`state.db`). The `eiaa_capsules` table has RLS
                    // enabled; inserting through the bare pool uses the
                    // `__unset__` org context and may silently fail the
                    // WITH CHECK policy on tenant_isolation.
                    let result = sqlx::query(
                        r#"
                        INSERT INTO eiaa_capsules
                            (tenant_id, action, policy_version, meta, policy_hash_b64,
                             capsule_hash_b64, compiler_kid, compiler_sig_b64,
                             wasm_bytes, ast_bytes)
                        VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9)
                        ON CONFLICT (capsule_hash_b64) DO NOTHING
                        "#,
                    )
                    .bind(tenant_id)
                    .bind(&agent_action)
                    .bind(&meta_json)
                    .bind(&signed.meta.ast_hash_b64)
                    .bind(&capsule_hash_b64)
                    .bind(&signed.compiler_kid)
                    .bind(&signed.compiler_sig_b64)
                    .bind(&signed.wasm_bytes)
                    .bind(&signed.ast_bytes)
                    .execute(&mut *conn)
                    .await;

                    match result {
                        Ok(_) => tracing::info!(
                            tenant_id = %tenant_id,
                            agent_id = %row.agent_id,
                            agent_action = %agent_action,
                            "B.4: agent capsule seeded"
                        ),
                        Err(e) => tracing::warn!(
                            tenant_id = %tenant_id,
                            agent_action = %agent_action,
                            "B.4: capsule persist failed (non-fatal): {e}"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    tenant_id = %tenant_id,
                    agent_action = %agent_action,
                    "B.4: capsule compile failed (non-fatal): {e}"
                ),
            }
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(RegisterAgentResponse {
            agent_id: row.agent_id,
            name: row.name,
            model_id: row.model_id,
            allowed_tools: row.allowed_tools,
            max_delegation_depth: row.max_delegation_depth,
            token_ttl_seconds: row.token_ttl_seconds,
            principal_source: row.principal_source,
            created_at: row.created_at,
        }),
    ))
}

/// POST /api/v1/agents/token
///
/// Issue a short-lived agent JWT for a specific task.
/// The caller must present a valid human (admin or service) session JWT.
/// Agent tokens cannot mint other agent tokens — that would allow privilege escalation
/// by bypassing the EIAA capsule delegation depth check.
async fn issue_agent_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<IssueAgentTokenRequest>,
) -> Result<Json<IssueAgentTokenResponse>> {
    let tenant_id = &claims.tenant_id;

    // C-2: Only admin and service sessions may issue agent tokens.
    // An agent token presenting session_type = "agent" must never mint another token —
    // that path bypasses the EIAA delegation capsule entirely.
    if claims.session_type != session_types::ADMIN
        && claims.session_type != session_types::SERVICE
    {
        return Err(AppError::Forbidden(
            "Only admin or service sessions may issue agent tokens".into(),
        ));
    }

    // C-3: Acquire a connection and set RLS context before querying tenant data
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set agent token RLS context".into()))?;

    // Load the registered principal
    let principal: AgentPrincipalRow = sqlx::query_as(
        r#"
        SELECT id, agent_id, name, model_id, allowed_tools, max_delegation_depth,
               token_ttl_seconds, principal_source, cimd_metadata_url, active,
               created_at, updated_at
        FROM agent_principals
        WHERE tenant_id = $1 AND agent_id = $2 AND active = TRUE
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&req.agent_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| {
        AppError::NotFound(format!("Agent '{}' not found or inactive", req.agent_id))
    })?;

    // Enforce delegation depth cap
    let depth = req.delegation_chain.len() as i16;
    if depth >= principal.max_delegation_depth {
        return Err(AppError::Forbidden(format!(
            "Delegation chain depth {} exceeds maximum {} for this agent",
            depth + 1,
            principal.max_delegation_depth
        )));
    }

    // Resolve allowed_tools: use request override (must be subset) or principal default
    let allowed_tools: Vec<String> = if let Some(ref override_tools) = req.allowed_tools {
        // Validate override is a subset of registered tools
        if !principal.allowed_tools.is_empty() {
            let registered: std::collections::HashSet<&str> =
                principal.allowed_tools.split_whitespace().collect();
            for tool in override_tools {
                if !registered.contains(tool.as_str()) {
                    return Err(AppError::Validation(format!(
                        "Tool '{}' is not in the agent's registered allowed_tools",
                        tool
                    )));
                }
            }
        }
        override_tools.clone()
    } else if principal.allowed_tools.is_empty() {
        vec![]
    } else {
        principal
            .allowed_tools
            .split_whitespace()
            .map(String::from)
            .collect()
    };

    // Build the agent Claims — uses the optional agent fields added in Sprint A
    let now = Utc::now();
    let exp = now.timestamp() + principal.token_ttl_seconds as i64;
    let agent_claims = Claims {
        sub: principal.agent_id.clone(),
        iss: state.config.jwt.issuer.clone(),
        aud: state.config.jwt.audience.clone(),
        exp,
        iat: now.timestamp(),
        nbf: now.timestamp(),
        // Agent tokens are not session-bound; use empty sid.
        sid: String::new(),
        tenant_id: tenant_id.clone(),
        session_type: session_types::AGENT.to_string(),
        agent_id: Some(principal.agent_id.clone()),
        model_id: principal.model_id.clone(),
        task_id: Some(req.task_id.clone()),
        delegation_chain: if req.delegation_chain.is_empty() {
            None
        } else {
            Some(req.delegation_chain.clone())
        },
        allowed_tools: if allowed_tools.is_empty() {
            None
        } else {
            Some(allowed_tools)
        },
        principal_source: Some(principal.principal_source.clone()),
    };

    let token = state.jwt_service.sign_claims(&agent_claims).map_err(|e| {
        AppError::Internal(format!("Failed to sign agent token: {e}"))
    })?;

    tracing::info!(
        tenant_id = %tenant_id,
        agent_id = %principal.agent_id,
        task_id = %req.task_id,
        delegation_depth = depth,
        expires_in = principal.token_ttl_seconds,
        "Agent token issued"
    );

    Ok(Json(IssueAgentTokenResponse {
        token,
        agent_id: principal.agent_id,
        task_id: req.task_id,
        expires_in: principal.token_ttl_seconds as i64,
    }))
}

/// GET /api/v1/agents
async fn list_agents(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<AgentPrincipalRow>>> {
    // C-3: Set RLS context before reading tenant data
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set list_agents RLS context".into()))?;

    let rows: Vec<AgentPrincipalRow> = sqlx::query_as(
        r#"
        SELECT id, agent_id, name, model_id, allowed_tools, max_delegation_depth,
               token_ttl_seconds, principal_source, cimd_metadata_url, active,
               created_at, updated_at
        FROM agent_principals
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(Json(rows))
}

/// GET /api/v1/agents/:agent_id
async fn get_agent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentPrincipalRow>> {
    // C-3: Set RLS context before reading tenant data
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set get_agent RLS context".into()))?;

    let row: AgentPrincipalRow = sqlx::query_as(
        r#"
        SELECT id, agent_id, name, model_id, allowed_tools, max_delegation_depth,
               token_ttl_seconds, principal_source, cimd_metadata_url, active,
               created_at, updated_at
        FROM agent_principals
        WHERE tenant_id = $1 AND agent_id = $2 AND active = TRUE
        LIMIT 1
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&agent_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Agent '{agent_id}' not found")))?;

    Ok(Json(row))
}

/// DELETE /api/v1/agents/:agent_id
///
/// Soft-deactivate a registered agent principal.  Sets `active = FALSE` so the
/// agent can no longer receive new tokens.  Existing unexpired tokens remain
/// valid until they expire or are explicitly revoked via the `/revoke` endpoint.
async fn deactivate_agent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode> {
    let tenant_id = &claims.tenant_id;

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set deactivate_agent RLS context".into()))?;

    let rows_affected = sqlx::query(
        r#"
        UPDATE agent_principals
        SET active = FALSE, updated_at = NOW()
        WHERE tenant_id = $1 AND agent_id = $2 AND active = TRUE
        "#,
    )
    .bind(tenant_id)
    .bind(&agent_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "Agent '{agent_id}' not found or already inactive"
        )));
    }

    tracing::info!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        "Agent principal deactivated"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/agents/:agent_id/revoke
///
/// Immediately invalidate all active tokens issued for this agent by writing a
/// Redis blocklist key `agent_blocklist:{agent_id}` with TTL = the agent's
/// `token_ttl_seconds`.  Any EIAA-protected request carrying an agent JWT with
/// this `agent_id` will be denied until the key expires.
///
/// This is analogous to session revocation for human users, adapted for the
/// agent token model where `sid` is empty.
async fn revoke_agent_tokens(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode> {
    let tenant_id = &claims.tenant_id;

    // Load the principal to get token_ttl_seconds (needed for blocklist TTL)
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set revoke_agent_tokens RLS context".into()))?;

    let ttl: i32 = sqlx::query_scalar(
        "SELECT token_ttl_seconds FROM agent_principals WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(tenant_id)
    .bind(&agent_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Agent '{agent_id}' not found")))?;

    // Write blocklist key — TTL is the maximum possible remaining token lifetime.
    // After this many seconds, any token issued before the revocation will have
    // naturally expired, and the Redis key auto-evicts.
    let blocklist_key = format!("agent_blocklist:{agent_id}");
    redis::cmd("SETEX")
        .arg(&blocklist_key)
        .arg(ttl)
        .arg("1")
        .query_async::<_, ()>(&mut state.redis.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Redis agent blocklist SETEX: {e}")))?;

    tracing::warn!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        blocklist_ttl_secs = ttl,
        "Agent tokens revoked — blocklist key written"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ─── authorize_tool_call request/response ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeToolCallRequest {
    /// The tool/action being requested (maps to `agent:{tool_name}` EIAA action).
    pub tool_name: String,
    /// SHA-256 hash of the tool arguments (for audit chaining).
    /// Stored in the audit trail via the EIAA context; not used by the handler directly.
    #[allow(dead_code)]
    pub tool_args_hash: Option<String>,
    /// Task identifier this call belongs to.
    /// Stored in the audit trail via the EIAA context; not used by the handler directly.
    #[allow(dead_code)]
    pub task_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeToolCallResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub decision_ref: String,
    pub attestation_ref: Option<String>,
    pub risk_score: Option<f64>,
}

// ─── record_execution request/response ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RecordExecutionRequest {
    /// The tool that was executed.
    pub tool_name: String,
    /// Task identifier — required by the `tool_call_audits` schema (NOT NULL).
    pub task_id: String,
    /// Whether the tool call was allowed (required NOT NULL in schema).
    pub allowed: bool,
    /// SHA-256 hash of tool arguments (hex) — stored for tamper evidence.
    pub tool_args_hash: Option<String>,
    /// Denial reason if allowed=false.
    pub denial_reason: Option<String>,
    /// Delegation chain depth at time of execution (default 0).
    #[serde(default)]
    pub delegation_depth: i16,
    /// Client IP for risk correlation.
    pub client_ip: Option<String>,
    /// Principal source from the JWT.
    pub principal_source: Option<String>,
    /// EIAA execution ID this call belongs to (best-effort foreign key).
    pub eiaa_execution_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RecordExecutionResponse {
    pub execution_id: String,
    pub tool_name: String,
    pub task_id: String,
    pub recorded_at: chrono::DateTime<Utc>,
}

// ─── update_agent request ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateAgentRequest {
    /// New LLM model identifier (omit to leave unchanged).
    pub model_id: Option<String>,
    /// Replacement allowed_tools list (omit to leave unchanged).
    pub allowed_tools: Option<String>,
    /// New maximum delegation depth 1–8 (omit to leave unchanged).
    pub max_delegation_depth: Option<i16>,
    /// New token TTL in seconds 60–86400 (omit to leave unchanged).
    pub token_ttl_seconds: Option<i32>,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/agents/:agent_id/authorize
///
/// Agent-initiated tool-call authorization.  The caller MUST present an agent
/// JWT (session_type = "agent") whose `agent_id` claim matches `:agent_id`.
///
/// The handler calls `evaluate_oauth_action` to run the EIAA capsule for
/// `"agent:{tool_name}"` and returns the decision with its decision reference.
async fn authorize_tool_call(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthorizeToolCallRequest>,
) -> Result<Json<AuthorizeToolCallResponse>> {
    // Only agent sessions may call this endpoint.
    if claims.session_type != session_types::AGENT {
        return Err(AppError::Forbidden(
            "Only agent sessions may call /authorize".into(),
        ));
    }

    // The agent_id in the JWT must match the path parameter.
    let jwt_agent_id = claims
        .agent_id
        .as_deref()
        .unwrap_or("");
    if jwt_agent_id != agent_id {
        return Err(AppError::Forbidden(
            "agent_id in JWT does not match path parameter".into(),
        ));
    }

    if req.tool_name.is_empty() {
        return Err(AppError::Validation("tool_name must not be empty".into()));
    }

    // The EIAA action for this tool call — Step 1.7 in the middleware prefixes
    // "agent:" automatically for agent sessions, so we pass the bare action here
    // (evaluate_oauth_action does NOT prefix — we must prefix ourselves since
    // we're bypassing the Tower middleware path).
    let action = format!("agent:{}", req.tool_name);

    let network = OAuthEiaaNetwork::from_headers(&headers);
    // Use ConnectInfo IP as fallback when X-Forwarded-For is absent.
    let network = if network.remote_ip.is_none() {
        OAuthEiaaNetwork {
            remote_ip: Some(addr.ip()),
            ..network
        }
    } else {
        network
    };

    let eiaa_req = OAuthEiaaRequest {
        action: &action,
        subject_id: &claims.sub,
        tenant_id: &claims.tenant_id,
        session_id: None, // agent tokens have empty sid
        session_type: session_types::AGENT,
        client_id: &agent_id,
        scope: None,
        grant_type: None,
        method: "POST",
        path: &format!("/api/v1/agents/{}/authorize", agent_id),
        network,
        confirmation_jkt: None,
        // Pass through the agent-specific claims from the JWT so the capsule's
        // VerifyAgentIdentity and CheckDelegationChain host functions receive
        // the correct runtime values.
        agent_model_id: claims.model_id.clone(),
        agent_id_claim: claims.agent_id.clone(),
        agent_task_id: claims.task_id.clone(),
        agent_delegation_chain: claims.delegation_chain.clone(),
    };

    let artifact = evaluate_oauth_action(&state, eiaa_req)
        .await
        .map_err(|e| AppError::Internal(format!("EIAA evaluation error: {e}")))?;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        agent_id = %agent_id,
        tool_name = %req.tool_name,
        allowed = artifact.allowed,
        decision_ref = %artifact.decision_ref,
        "Agent tool-call authorization evaluated"
    );

    Ok(Json(AuthorizeToolCallResponse {
        allowed: artifact.allowed,
        reason: artifact.reason,
        decision_ref: artifact.decision_ref,
        attestation_ref: artifact.attestation_ref,
        risk_score: None, // risk score not surfaced in EiaaDecisionArtifact
    }))
}

/// POST /api/v1/agents/:agent_id/executions
///
/// Record the completion of a tool execution after it has been authorized.
/// Inserts a row into `tool_call_audits` for compliance and task-chain
/// linkage.  Called by the Python/TypeScript SDK after a successful tool call.
async fn record_execution(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
    Json(req): Json<RecordExecutionRequest>,
) -> Result<(StatusCode, Json<RecordExecutionResponse>)> {
    // Only agent sessions may record executions.
    if claims.session_type != session_types::AGENT {
        return Err(AppError::Forbidden(
            "Only agent sessions may record executions".into(),
        ));
    }

    let jwt_agent_id = claims.agent_id.as_deref().unwrap_or("");
    if jwt_agent_id != agent_id {
        return Err(AppError::Forbidden(
            "agent_id in JWT does not match path parameter".into(),
        ));
    }

    if req.tool_name.is_empty() {
        return Err(AppError::Validation("tool_name must not be empty".into()));
    }
    if req.task_id.is_empty() {
        return Err(AppError::Validation("task_id must not be empty".into()));
    }

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set record_execution RLS context".into()))?;

    // CRIT-1 FIX: INSERT columns now match the `tool_call_audits` schema exactly.
    // Removed: result_hash, executed_at, decision_ref (not in schema).
    // Added: allowed (NOT NULL), tool_args_hash, denial_reason, delegation_depth,
    //        principal_source, client_ip, eiaa_execution_id.
    let execution_id: String = sqlx::query_scalar(
        r#"
        INSERT INTO tool_call_audits
            (tenant_id, agent_id, task_id, tool_name, tool_args_hash,
             allowed, denial_reason, delegation_depth, principal_source,
             client_ip, eiaa_execution_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&agent_id)
    .bind(&req.task_id)
    .bind(&req.tool_name)
    .bind(&req.tool_args_hash)
    .bind(req.allowed)
    .bind(&req.denial_reason)
    .bind(req.delegation_depth)
    .bind(&req.principal_source)
    .bind(&req.client_ip)
    .bind(&req.eiaa_execution_id)
    .fetch_one(&mut *conn)
    .await?;

    let recorded_at = Utc::now();

    tracing::info!(
        tenant_id = %claims.tenant_id,
        agent_id = %agent_id,
        tool_name = %req.tool_name,
        execution_id = %execution_id,
        "Agent tool execution recorded"
    );

    Ok((
        StatusCode::CREATED,
        Json(RecordExecutionResponse {
            execution_id,
            tool_name: req.tool_name,
            task_id: req.task_id,
            recorded_at,
        }),
    ))
}

/// PUT /api/v1/agents/:agent_id
///
/// Update a registered agent principal's mutable fields.  Uses COALESCE
/// partial-update semantics — omitted fields are left unchanged.
///
/// If `allowed_tools` is updated, agent-prefixed capsules are re-seeded
/// for any newly added tools (same logic as `register_agent`).
async fn update_agent(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Result<Json<AgentPrincipalRow>> {
    let tenant_id = &claims.tenant_id;

    // Validate bounds if provided.
    if let Some(depth) = req.max_delegation_depth {
        if !(1..=8).contains(&depth) {
            return Err(AppError::Validation(
                "max_delegation_depth must be between 1 and 8".into(),
            ));
        }
    }
    if let Some(ttl) = req.token_ttl_seconds {
        if !(60..=86400).contains(&ttl) {
            return Err(AppError::Validation(
                "token_ttl_seconds must be between 60 and 86400".into(),
            ));
        }
    }

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set update_agent RLS context".into()))?;

    let row: AgentPrincipalRow = sqlx::query_as(
        r#"
        UPDATE agent_principals
        SET
            model_id             = COALESCE($3, model_id),
            allowed_tools        = COALESCE($4, allowed_tools),
            max_delegation_depth = COALESCE($5, max_delegation_depth),
            token_ttl_seconds    = COALESCE($6, token_ttl_seconds),
            updated_at           = NOW()
        WHERE tenant_id = $1 AND agent_id = $2 AND active = TRUE
        RETURNING id, agent_id, name, model_id, allowed_tools,
                  max_delegation_depth, token_ttl_seconds, principal_source,
                  cimd_metadata_url, active, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(&agent_id)
    .bind(&req.model_id)
    .bind(&req.allowed_tools)
    .bind(req.max_delegation_depth)
    .bind(req.token_ttl_seconds)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Agent '{agent_id}' not found or inactive")))?;

    // Re-seed capsules for any newly added tools.
    // HIGH-3 FIX: Seed from `row.allowed_tools` (post-COALESCE DB result) not
    // `req.allowed_tools` (caller input). `row` is the authoritative stored state.
    if !row.allowed_tools.is_empty() && req.allowed_tools.is_some() {
        {
            let model_id = row.model_id.clone().unwrap_or_default();
            let max_depth = row.max_delegation_depth as u8;
            let now = chrono::Utc::now().timestamp();
            let not_after = now + 365 * 24 * 3600;

            for tool in row.allowed_tools.split_whitespace() {
                let agent_action = format!("agent:{tool}");
                let scope = AgentScopeConfig {
                    model_id: model_id.clone(),
                    max_depth,
                    risk_deny_threshold: 60,
                    action: agent_action.clone(),
                    resource: tool.to_string(),
                };
                let ast = PolicyCompiler::compile_agent_scope_policy(&scope);

                match capsule_compiler::compile(
                    ast,
                    tenant_id.clone(),
                    agent_action.clone(),
                    now,
                    not_after,
                    &state.ks,
                    &state.compiler_kid,
                ) {
                    Ok(signed) => {
                        let meta_json = match serde_json::to_value(&signed.meta) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    tenant_id = %tenant_id,
                                    agent_action = %agent_action,
                                    "update_agent: capsule meta serialise failed: {e}"
                                );
                                continue;
                            }
                        };
                        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                        let capsule_hash_b64 = URL_SAFE_NO_PAD.encode(
                            hex::decode(&signed.wasm_hash).unwrap_or_default(),
                        );
                        // LOW-1 FIX: Use the RLS-scoped connection for the capsule INSERT.
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT INTO eiaa_capsules
                                (tenant_id, action, policy_version, meta, policy_hash_b64,
                                 capsule_hash_b64, compiler_kid, compiler_sig_b64,
                                 wasm_bytes, ast_bytes)
                            VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9)
                            ON CONFLICT (capsule_hash_b64) DO NOTHING
                            "#,
                        )
                        .bind(tenant_id)
                        .bind(&agent_action)
                        .bind(&meta_json)
                        .bind(&signed.meta.ast_hash_b64)
                        .bind(&capsule_hash_b64)
                        .bind(&signed.compiler_kid)
                        .bind(&signed.compiler_sig_b64)
                        .bind(&signed.wasm_bytes)
                        .bind(&signed.ast_bytes)
                        .execute(&mut *conn)
                        .await
                        {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                agent_action = %agent_action,
                                "update_agent: capsule persist failed (non-fatal): {e}"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        tenant_id = %tenant_id,
                        agent_action = %agent_action,
                        "update_agent: capsule compile failed (non-fatal): {e}"
                    ),
                }
            }
        }
    }

    tracing::info!(
        tenant_id = %tenant_id,
        agent_id = %agent_id,
        "Agent principal updated"
    );

    Ok(Json(row))
}
