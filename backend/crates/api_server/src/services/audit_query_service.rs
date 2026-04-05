use chrono::{DateTime, Utc};
use shared_types::Result;
use sqlx::PgPool;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
pub struct AuditListQuery {
    pub decision: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    pub action: Option<String>,
}

#[derive(serde::Serialize)]
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

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct ExecutionLogSimple {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub capsule_id: Option<String>,
    pub capsule_hash_b64: String,
    pub decision: serde_json::Value,
    pub nonce_b64: String,
    pub client_id: Option<String>,
    pub ip_text: Option<String>,
}

#[derive(serde::Serialize)]
pub struct AuditListResponse {
    pub logs: Vec<ExecutionLogSimple>,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
    pub count: usize,
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuditQueryService {
    db: PgPool,
}

impl AuditQueryService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// List EIAA execution logs for a tenant with filtering and cursor pagination.
    pub async fn list_executions(
        &self,
        tenant_id: &str,
        params: &AuditListQuery,
    ) -> Result<AuditListResponse> {
        let limit = params.limit.unwrap_or(50).clamp(1, 200);

        let mut conditions = vec!["c.tenant_id = $1".to_string()];
        let mut bind_idx = 2usize;

        let decision_filter = params.decision.as_deref().map(|d| d == "allowed");

        if decision_filter.is_some() {
            conditions.push(format!("(e.decision->>'allow')::boolean = ${bind_idx}"));
            bind_idx += 1;
        }
        if params.action.is_some() {
            conditions.push(format!("e.action = ${bind_idx}"));
            bind_idx += 1;
        }
        if params.cursor.is_some() {
            conditions.push(format!("e.created_at < ${bind_idx}::timestamptz"));
            #[allow(unused_assignments)]
            {
                bind_idx += 1;
            }
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

        let mut query = sqlx::query_as::<_, ExecutionLogSimple>(&sql).bind(tenant_id);

        if let Some(allow) = decision_filter {
            query = query.bind(allow);
        }
        if let Some(action) = &params.action {
            query = query.bind(action);
        }
        if let Some(cursor) = &params.cursor {
            query = query.bind(cursor);
        }

        let logs = query.fetch_all(&self.db).await?;

        let has_more = logs.len() == limit as usize;
        let next_cursor = if has_more {
            logs.last().map(|l| l.created_at.to_rfc3339())
        } else {
            None
        };
        let count = logs.len();

        Ok(AuditListResponse {
            logs,
            has_more,
            next_cursor,
            count,
        })
    }

    /// Aggregate stats for a tenant's EIAA executions.
    pub async fn get_stats(&self, tenant_id: &str) -> Result<StatsResponse> {
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
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await?;

        Ok(StatsResponse {
            total_executions: row.0,
            allowed_count: row.1,
            denied_count: row.2,
            executions_last_24h: row.3,
            executions_last_7d: row.4,
            unique_actions_last_7d: row.5,
        })
    }

    /// Get full details of a single EIAA execution, scoped to tenant.
    pub async fn get_execution(&self, id: &str, tenant_id: &str) -> Result<serde_json::Value> {
        let log = sqlx::query_as::<_, (serde_json::Value,)>(
            r#"
            SELECT to_jsonb(e.*)
            FROM eiaa_executions e
            LEFT JOIN eiaa_capsules c ON e.capsule_hash_b64 = c.capsule_hash_b64
            WHERE e.id = $1 AND c.tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?
        .map(|r| r.0)
        .ok_or_else(|| shared_types::AppError::NotFound("Log not found".into()))?;

        Ok(log)
    }
}
