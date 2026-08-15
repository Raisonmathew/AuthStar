//! Task Chain Audit Routes (Sprint C)
//!
//! ## Endpoints
//! - `GET /api/v1/audit/task/:task_id`    — full causal chain for an agent task
//! - `GET /api/v1/audit/agent/:agent_id`  — all executions ever recorded for an agent
//!
//! ## Authorization
//! Both endpoints require the `audit:read` EIAA action (same as existing decisions routes).
//!
//! ## Pagination
//! Both endpoints support cursor-based pagination via `?cursor=<ISO8601>` (uses
//! `created_at` timestamp as the cursor, consistent with existing audit log endpoints).
//!
//! ## Access control
//! Queries are tenant-scoped via RLS: only records belonging to the caller's
//! `tenant_id` (from the JWT) are returned, regardless of the task/agent IDs
//! passed in the URL.

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    /// ISO-8601 timestamp cursor from the previous page's `next_cursor` field.
    pub cursor: Option<DateTime<Utc>>,
    /// Maximum rows per page (1–100, default 50).
    pub limit: Option<i64>,
}

/// A single EIAA execution record returned in the task chain.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ExecutionRow {
    pub id: String,
    pub decision_ref: String,
    pub action: String,
    pub capsule_hash_b64: String,
    pub decision: serde_json::Value,
    pub attestation_signature_b64: String,
    pub attestation_timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    // Task chain fields (null for human sessions)
    pub task_id: Option<String>,
    pub parent_action_id: Option<String>,
    pub delegation_depth: i32,
    pub principal_type: String,
    pub agent_id: Option<String>,
    pub model_id: Option<String>,
    pub tool_name: Option<String>,
    pub tool_args_hash: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainResponse {
    pub items: Vec<ExecutionRow>,
    pub next_cursor: Option<DateTime<Utc>>,
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// Both routes require the `audit:read` EIAA action — applied in `router.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/audit/task/:task_id", get(get_task_chain))
        .route("/audit/agent/:agent_id", get(get_agent_history))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/v1/audit/task/:task_id
///
/// Returns all EIAA execution records for a given task ID, ordered oldest-first
/// so callers can reconstruct the causal chain.  Cursor pagination uses the
/// `created_at` timestamp of the last row returned.
async fn get_task_chain(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(task_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ChainResponse>> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set task chain RLS context".into()))?;

    let rows: Vec<ExecutionRow> = if let Some(cursor) = params.cursor {
        sqlx::query_as(
            r#"
            SELECT id, decision_ref, action, capsule_hash_b64, decision,
                   attestation_signature_b64, attestation_timestamp, created_at,
                   task_id, parent_action_id,
                   COALESCE(delegation_depth, 0)   AS delegation_depth,
                   COALESCE(principal_type, 'human') AS principal_type,
                   agent_id, model_id, tool_name, tool_args_hash, user_id
            FROM eiaa_executions
            WHERE tenant_id = $1
              AND task_id   = $2
              AND created_at > $3
            ORDER BY created_at ASC
            LIMIT $4
            "#,
        )
        .bind(&claims.tenant_id)
        .bind(&task_id)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Task chain query: {e}")))?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, decision_ref, action, capsule_hash_b64, decision,
                   attestation_signature_b64, attestation_timestamp, created_at,
                   task_id, parent_action_id,
                   COALESCE(delegation_depth, 0)   AS delegation_depth,
                   COALESCE(principal_type, 'human') AS principal_type,
                   agent_id, model_id, tool_name, tool_args_hash, user_id
            FROM eiaa_executions
            WHERE tenant_id = $1
              AND task_id   = $2
            ORDER BY created_at ASC
            LIMIT $3
            "#,
        )
        .bind(&claims.tenant_id)
        .bind(&task_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Task chain query: {e}")))?
    };

    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|r| r.created_at)
    } else {
        None
    };

    Ok(Json(ChainResponse {
        items: rows,
        next_cursor,
    }))
}

/// GET /api/v1/audit/agent/:agent_id
///
/// Returns all EIAA execution records ever produced by a specific agent,
/// ordered newest-first (most recent activity first).  Cursor pagination
/// uses `created_at` of the last row (i.e., oldest in the page, since we
/// page backwards in time).
async fn get_agent_history(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(agent_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ChainResponse>> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set agent history RLS context".into()))?;

    let rows: Vec<ExecutionRow> = if let Some(cursor) = params.cursor {
        sqlx::query_as(
            r#"
            SELECT id, decision_ref, action, capsule_hash_b64, decision,
                   attestation_signature_b64, attestation_timestamp, created_at,
                   task_id, parent_action_id,
                   COALESCE(delegation_depth, 0)    AS delegation_depth,
                   COALESCE(principal_type, 'human') AS principal_type,
                   agent_id, model_id, tool_name, tool_args_hash, user_id
            FROM eiaa_executions
            WHERE tenant_id = $1
              AND agent_id  = $2
              AND created_at < $3
            ORDER BY created_at DESC
            LIMIT $4
            "#,
        )
        .bind(&claims.tenant_id)
        .bind(&agent_id)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Agent history query: {e}")))?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, decision_ref, action, capsule_hash_b64, decision,
                   attestation_signature_b64, attestation_timestamp, created_at,
                   task_id, parent_action_id,
                   COALESCE(delegation_depth, 0)    AS delegation_depth,
                   COALESCE(principal_type, 'human') AS principal_type,
                   agent_id, model_id, tool_name, tool_args_hash, user_id
            FROM eiaa_executions
            WHERE tenant_id = $1
              AND agent_id  = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(&claims.tenant_id)
        .bind(&agent_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Agent history query: {e}")))?
    };

    let next_cursor = if rows.len() as i64 == limit {
        rows.last().map(|r| r.created_at)
    } else {
        None
    };

    Ok(Json(ChainResponse {
        items: rows,
        next_cursor,
    }))
}
