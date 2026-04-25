use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::Result;
use sqlx::PgPool;
use std::net::IpAddr;

// ─── Event Types ──────────────────────────────────────────────────────────────

/// Well-known event type constants.
#[allow(dead_code)]
pub mod event_types {
    // Authentication
    pub const USER_LOGIN_SUCCESS: &str = "user.login_success";
    pub const USER_LOGIN_FAILED: &str = "user.login_failed";
    pub const USER_LOGOUT: &str = "user.logout";
    pub const USER_SIGNUP: &str = "user.signup";
    pub const USER_TOKEN_REFRESH: &str = "user.token_refresh";

    // Admin
    pub const ADMIN_LOGIN_SUCCESS: &str = "admin.login_success";
    pub const ADMIN_LOGIN_FAILED: &str = "admin.login_failed";

    // SSO
    pub const SSO_LOGIN_SUCCESS: &str = "sso.login_success";
    pub const SSO_CONNECTION_CREATED: &str = "sso.connection_created";
    pub const SSO_CONNECTION_UPDATED: &str = "sso.connection_updated";
    pub const SSO_CONNECTION_DELETED: &str = "sso.connection_deleted";

    // API Keys
    pub const API_KEY_CREATED: &str = "api_key.created";
    pub const API_KEY_REVOKED: &str = "api_key.revoked";

    // Publishable Keys
    pub const PUBLISHABLE_KEY_CREATED: &str = "publishable_key.created";
    pub const PUBLISHABLE_KEY_REVOKED: &str = "publishable_key.revoked";

    // Sessions
    pub const SESSION_REVOKED: &str = "session.revoked";
    pub const SESSION_REVOKED_ALL: &str = "session.revoked_all";

    // Org config
    pub const ORG_CONFIG_UPDATED: &str = "org.config_updated";
    pub const ORG_BRANDING_UPDATED: &str = "org.branding_updated";

    // Organization management
    pub const ORG_CREATED: &str = "org.created";
    pub const ORG_SWITCHED: &str = "org.switched";
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// Parameters for recording an audit event.
pub struct RecordEventParams {
    pub tenant_id: String,
    pub event_type: &'static str,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub target_type: Option<&'static str>,
    pub target_id: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub metadata: serde_json::Value,
}

/// A single audit event row (for API responses).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditEventRow {
    pub id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventListResponse {
    pub events: Vec<AuditEventRow>,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct AuditEventStats {
    #[serde(rename = "totalEvents")]
    pub total_events: i64,
    #[serde(rename = "eventsLast24h")]
    pub events_last_24h: i64,
    #[serde(rename = "eventsLast7d")]
    pub events_last_7d: i64,
    #[serde(rename = "uniqueEventTypes")]
    pub unique_event_types: i64,
    #[serde(rename = "loginSuccessLast24h")]
    pub login_success_last_24h: i64,
    #[serde(rename = "loginFailedLast24h")]
    pub login_failed_last_24h: i64,
}

#[derive(Deserialize, Default)]
pub struct AuditEventListQuery {
    pub event_type: Option<String>,
    pub actor_id: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuditEventService {
    db: PgPool,
}

impl AuditEventService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Record a single audit event. Non-blocking: errors are logged but not propagated
    /// to avoid failing the primary request when audit recording has issues.
    ///
    /// If `actor_email` is `None` but `actor_id` is `Some`, the email is resolved from
    /// the `identities` table. JWT `Claims` are identity-only (no email per EIAA design),
    /// so callers cannot supply email cheaply — this lookup ensures every authenticated
    /// audit row carries an actor_email for compliance reporting.
    pub async fn record(&self, params: RecordEventParams) {
        let ip_str = params.ip_address.map(|ip| ip.to_string());
        let resolved_email = match (&params.actor_email, &params.actor_id) {
            (Some(_), _) => params.actor_email.clone(),
            (None, Some(uid)) => self.resolve_email_for_user(uid).await,
            (None, None) => None,
        };

        let result = sqlx::query(
            r#"
            INSERT INTO audit_events (
                tenant_id, event_type, actor_id, actor_email,
                target_type, target_id, ip_address, user_agent, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9)
            "#,
        )
        .bind(&params.tenant_id)
        .bind(params.event_type)
        .bind(&params.actor_id)
        .bind(&resolved_email)
        .bind(params.target_type)
        .bind(&params.target_id)
        .bind(&ip_str)
        .bind(&params.user_agent)
        .bind(&params.metadata)
        .execute(&self.db)
        .await;

        if let Err(e) = result {
            tracing::error!(
                event_type = %params.event_type,
                tenant_id = %params.tenant_id,
                error = %e,
                "Failed to record audit event"
            );
        }
    }

    /// Resolve a user's primary email from the `identities` table. Returns `None`
    /// if no email identity exists or the lookup fails (audit must remain best-effort).
    async fn resolve_email_for_user(&self, user_id: &str) -> Option<String> {
        let result: std::result::Result<Option<(String,)>, sqlx::Error> = sqlx::query_as(
            r#"
            SELECT identifier
            FROM identities
            WHERE user_id = $1 AND type = 'email'
            ORDER BY verified DESC NULLS LAST, created_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await;

        match result {
            Ok(row) => row.map(|(email,)| email),
            Err(e) => {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "Failed to resolve actor_email for audit event"
                );
                None
            }
        }
    }

    /// List audit events with filtering and cursor-based pagination.
    pub async fn list_events(
        &self,
        tenant_id: &str,
        params: &AuditEventListQuery,
    ) -> Result<AuditEventListResponse> {
        let limit = params.limit.unwrap_or(50).clamp(1, 200);

        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut bind_idx = 2usize;

        if params.event_type.is_some() {
            conditions.push(format!("event_type = ${bind_idx}"));
            bind_idx += 1;
        }
        if params.actor_id.is_some() {
            conditions.push(format!("actor_id = ${bind_idx}"));
            bind_idx += 1;
        }
        if params.cursor.is_some() {
            conditions.push(format!("created_at < ${bind_idx}::timestamptz"));
            #[allow(unused_assignments)]
            {
                bind_idx += 1;
            }
        }

        let where_clause = conditions.join(" AND ");
        let sql = format!(
            r#"
            SELECT id, tenant_id, event_type, actor_id, actor_email,
                   target_type, target_id, host(ip_address) as ip_address,
                   user_agent, metadata, created_at
            FROM audit_events
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT {limit}
            "#,
        );

        let mut query = sqlx::query_as::<_, AuditEventRow>(&sql).bind(tenant_id);

        if let Some(event_type) = &params.event_type {
            query = query.bind(event_type);
        }
        if let Some(actor_id) = &params.actor_id {
            query = query.bind(actor_id);
        }
        if let Some(cursor) = &params.cursor {
            query = query.bind(cursor);
        }

        let events = query.fetch_all(&self.db).await?;

        let has_more = events.len() == limit as usize;
        let next_cursor = if has_more {
            events.last().map(|e| e.created_at.to_rfc3339())
        } else {
            None
        };
        let count = events.len();

        Ok(AuditEventListResponse {
            events,
            has_more,
            next_cursor,
            count,
        })
    }

    /// Aggregate stats for audit events.
    pub async fn get_stats(&self, tenant_id: &str) -> Result<AuditEventStats> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*)                                                                     AS total_events,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')           AS events_last_24h,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')             AS events_last_7d,
                COUNT(DISTINCT event_type)                                                   AS unique_event_types,
                COUNT(*) FILTER (WHERE event_type = 'user.login_success'
                                   AND created_at >= NOW() - INTERVAL '24 hours')           AS login_success_last_24h,
                COUNT(*) FILTER (WHERE event_type = 'user.login_failed'
                                   AND created_at >= NOW() - INTERVAL '24 hours')           AS login_failed_last_24h
            FROM audit_events
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await?;

        Ok(AuditEventStats {
            total_events: row.0,
            events_last_24h: row.1,
            events_last_7d: row.2,
            unique_event_types: row.3,
            login_success_last_24h: row.4,
            login_failed_last_24h: row.5,
        })
    }

    /// Get a single audit event by ID, scoped to tenant.
    pub async fn get_event(&self, id: &str, tenant_id: &str) -> Result<serde_json::Value> {
        let row = sqlx::query_as::<_, (serde_json::Value,)>(
            r#"
            SELECT to_jsonb(e.*) FROM (
                SELECT id, tenant_id, event_type, actor_id, actor_email,
                       target_type, target_id, host(ip_address) as ip_address,
                       user_agent, metadata, created_at
                FROM audit_events
                WHERE id = $1 AND tenant_id = $2
            ) e
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?
        .map(|r| r.0)
        .ok_or_else(|| shared_types::AppError::NotFound("Event not found".into()))?;

        Ok(row)
    }
}
