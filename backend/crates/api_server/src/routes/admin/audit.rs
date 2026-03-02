use axum::{
    Router,
    routing::get,
    extract::{State, Path, Query},
    Json,
    http::HeaderMap,
};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use shared_types::{Result, AppError};
use chrono::{DateTime, Utc};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_executions))
        .route("/stats", get(get_stats))
        .route("/:id", get(get_execution))
}

/// Query parameters for audit log listing
#[derive(Deserialize, Default)]
pub struct AuditListQuery {
    /// Filter by decision: "allowed" or "denied"
    pub decision: Option<String>,
    /// Maximum number of records to return (default 50, max 200)
    pub limit: Option<i64>,
    /// Cursor for pagination (created_at timestamp of last seen record, ISO 8601)
    pub cursor: Option<String>,
    /// Filter by action type (e.g. "login", "admin_login")
    pub action: Option<String>,
}

/// Dashboard statistics response
#[derive(Serialize)]
pub struct StatsResponse {
    #[serde(rename = "totalExecutions")]
    pub total_executions: i64,
    #[serde(rename = "allowedCount")]
    pub allowed_count: i64,
    #[serde(rename = "deniedCount")]
    pub denied_count: i64,
    #[serde(rename = "executionsLast24h")]
    pub executions_last_24h: i64,
    #[serde(rename = "executionsLast7d")]
    pub executions_last_7d: i64,
    #[serde(rename = "uniqueActionsLast7d")]
    pub unique_actions_last_7d: i64,
}

/*
#[derive(Serialize, sqlx::FromRow)]
struct ExecutionLog {
    id: String,
    created_at: DateTime<Utc>,
    capsule_id: Option<String>,
    capsule_hash_b64: String,
    decision: serde_json::Value,
    // attestation: serde_json::Value, // Heavy, maybe load detailed only
    nonce_b64: String,
    client_id: Option<String>,
    #[sqlx(try_from = "ipnetwork::IpNetwork")]
    ip_address: Option<std::net::IpAddr>, 
}
*/

// Custom IpAddr handling if needed, or use simple string cast in query if sqlx-postgres types unavailable
// For simplicity, let's just use JSON or String for IP if types conflict, but sqlx has `ipnetwork`.
// Let's assume we might need to cast IP to text in SQL to avoid type issues for now.

#[derive(Serialize, sqlx::FromRow)]
struct ExecutionLogSimple {
    id: String,
    created_at: DateTime<Utc>,
    capsule_id: Option<String>,
    capsule_hash_b64: String,
    decision: serde_json::Value,
    nonce_b64: String,
    client_id: Option<String>,
    // ip_address handled as text
    ip_text: Option<String>,
}

/// Extract tenant_id from Authorization header
async fn extract_tenant_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".into()))?;

    let claims = state.jwt_service.verify_token(token)?;
    Ok(claims.tenant_id)
}

/// GET /api/admin/v1/audit
///
/// List EIAA execution logs for the authenticated tenant.
/// Supports filtering by decision outcome, action type, and cursor-based pagination.
///
/// Query params:
///   - `decision`: "allowed" | "denied" — filter by outcome
///   - `action`: e.g. "login" | "admin_login" — filter by action type
///   - `limit`: max records (default 50, max 200)
///   - `cursor`: ISO 8601 timestamp — return records older than this (for pagination)
async fn list_executions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuditListQuery>,
) -> Result<Json<serde_json::Value>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;

    let limit = params.limit.unwrap_or(50).min(200).max(1);

    // Build dynamic WHERE clauses
    // Base: join to capsules for tenant scoping
    // Optional: filter by decision.allow, action, cursor
    let mut conditions = vec!["c.tenant_id = $1".to_string()];
    let mut bind_idx = 2usize;

    // Decision filter: parse "allowed"/"denied" → JSON boolean
    let decision_filter = params.decision.as_deref().map(|d| d == "allowed");

    if decision_filter.is_some() {
        conditions.push(format!("(e.decision->>'allow')::boolean = ${}", bind_idx));
        bind_idx += 1;
    }

    // Action filter
    if params.action.is_some() {
        conditions.push(format!("e.action = ${}", bind_idx));
        bind_idx += 1;
    }

    // Cursor-based pagination: return records created before the cursor timestamp
    if params.cursor.is_some() {
        conditions.push(format!("e.created_at < ${}::timestamptz", bind_idx));
        bind_idx += 1;
    }

    let where_clause = conditions.join(" AND ");
    let sql = format!(
        r#"
        SELECT
            e.id, e.created_at, e.capsule_id, e.capsule_hash_b64, e.decision, e.nonce_b64, e.client_id,
            e.ip_address::text as ip_text
        FROM eiaa_executions e
        LEFT JOIN eiaa_capsules c ON e.capsule_hash_b64 = c.capsule_hash_b64
        WHERE {where_clause}
        ORDER BY e.created_at DESC
        LIMIT {limit}
        "#
    );

    // Build query with dynamic bindings
    let mut query = sqlx::query_as::<_, ExecutionLogSimple>(&sql)
        .bind(&tenant_id);

    if let Some(allow) = decision_filter {
        query = query.bind(allow);
    }
    if let Some(action) = &params.action {
        query = query.bind(action);
    }
    if let Some(cursor) = &params.cursor {
        query = query.bind(cursor);
    }

    let logs = query.fetch_all(&state.db).await?;

    // Return with pagination metadata
    let has_more = logs.len() == limit as usize;
    let next_cursor = if has_more {
        logs.last().map(|l| l.created_at.to_rfc3339())
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "logs": logs,
        "hasMore": has_more,
        "nextCursor": next_cursor,
        "count": logs.len(),
    })))
}

/// GET /api/admin/v1/audit/stats
///
/// Returns aggregate statistics for the authenticated tenant's EIAA executions.
/// Used by the admin dashboard to populate stat cards and recent activity.
async fn get_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;

    // Single query: compute all stats in one round-trip using conditional aggregation
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*)                                                                    AS total_executions,
            COUNT(*) FILTER (WHERE (e.decision->>'allow')::boolean = true)             AS allowed_count,
            COUNT(*) FILTER (WHERE (e.decision->>'allow')::boolean = false)            AS denied_count,
            COUNT(*) FILTER (WHERE e.created_at >= NOW() - INTERVAL '24 hours')        AS executions_last_24h,
            COUNT(*) FILTER (WHERE e.created_at >= NOW() - INTERVAL '7 days')          AS executions_last_7d,
            COUNT(DISTINCT e.action) FILTER (WHERE e.created_at >= NOW() - INTERVAL '7 days') AS unique_actions_last_7d
        FROM eiaa_executions e
        LEFT JOIN eiaa_capsules c ON e.capsule_hash_b64 = c.capsule_hash_b64
        WHERE c.tenant_id = $1
        "#
    )
    .bind(&tenant_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(StatsResponse {
        total_executions: row.0,
        allowed_count: row.1,
        denied_count: row.2,
        executions_last_24h: row.3,
        executions_last_7d: row.4,
        unique_actions_last_7d: row.5,
    }))
}

async fn get_execution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;

    // Return full details including attestation — scoped to tenant via capsule join
    let log = sqlx::query_as::<_, (serde_json::Value,)>(
        r#"
        SELECT to_jsonb(e.*)
        FROM eiaa_executions e
        LEFT JOIN eiaa_capsules c ON e.capsule_hash_b64 = c.capsule_hash_b64
        WHERE e.id = $1 AND c.tenant_id = $2
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .map(|r| r.0)
    .ok_or_else(|| shared_types::AppError::NotFound("Log not found".into()))?;

    Ok(Json(log))
}
