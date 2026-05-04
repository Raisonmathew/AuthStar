use crate::middleware::org_context::set_rls_context_on_conn;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, AppError, Result};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    NotRequired,
    Pending,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext<'a> {
    pub tenant_id: &'a str,
    pub user_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub code: String,
    pub status: ActionStatus,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RequiredActionRecord {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub code: String,
    pub state: String,
    pub priority: i32,
    pub ttl_seconds: Option<i32>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait RequiredAction: Send + Sync {
    fn code(&self) -> &'static str;
    fn priority(&self) -> i32;
    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus>;
    async fn challenge(&self, _db: &PgPool, ctx: &ActionContext<'_>) -> Result<ChallengeResponse> {
        Ok(ChallengeResponse {
            code: self.code().to_string(),
            status: ActionStatus::Pending,
            metadata: serde_json::json!({
                "tenant_id": ctx.tenant_id,
                "user_id": ctx.user_id,
            }),
        })
    }
    async fn complete(
        &self,
        _db: &PgPool,
        _ctx: &ActionContext<'_>,
        _payload: serde_json::Value,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RequiredActionRegistry {
    actions: Arc<HashMap<&'static str, Arc<dyn RequiredAction>>>,
}

impl RequiredActionRegistry {
    pub fn new(actions: Vec<Arc<dyn RequiredAction>>) -> Self {
        let actions = actions.into_iter().map(|a| (a.code(), a)).collect();
        Self {
            actions: Arc::new(actions),
        }
    }

    pub fn default_actions() -> Self {
        Self::new(vec![
            Arc::new(VerifyEmailRequiredAction),
            Arc::new(ConfigureMfaRequiredAction),
            Arc::new(UpdatePasswordRequiredAction),
        ])
    }

    pub fn get(&self, code: &str) -> Option<Arc<dyn RequiredAction>> {
        self.actions.get(code).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<dyn RequiredAction>> + '_ {
        self.actions.values().cloned()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }
}

#[derive(Clone)]
pub struct RequiredActionService {
    db: PgPool,
    registry: RequiredActionRegistry,
}

impl RequiredActionService {
    pub fn new(db: PgPool, registry: RequiredActionRegistry) -> Self {
        Self { db, registry }
    }

    pub async fn evaluate_and_sync(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<RequiredActionRecord>> {
        let ctx = ActionContext { tenant_id, user_id };
        for action in self.registry.iter() {
            match action.evaluate(&self.db, &ctx).await? {
                ActionStatus::Pending => {
                    self.ensure_pending(tenant_id, user_id, action.code(), action.priority(), None)
                        .await?;
                }
                ActionStatus::Completed => {
                    self.mark_completed_if_pending(tenant_id, user_id, action.code())
                        .await?;
                }
                ActionStatus::NotRequired => {}
            }
        }
        self.pending_for_user(tenant_id, user_id).await
    }

    pub async fn pending_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<RequiredActionRecord>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, RequiredActionRecord>(
            r#"
            SELECT id, tenant_id, user_id, code, state, priority, ttl_seconds, metadata,
                   created_at, updated_at, completed_at, expires_at
            FROM required_actions
            WHERE tenant_id = $1
              AND user_id = $2
              AND state = 'pending'
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("List required actions: {e}")))?;
        Ok(rows)
    }

    pub async fn pending_codes(&self, tenant_id: &str, user_id: &str) -> Result<Vec<String>> {
        Ok(self
            .pending_for_user(tenant_id, user_id)
            .await?
            .into_iter()
            .map(|r| r.code)
            .collect())
    }

    pub async fn ensure_pending(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
        priority: i32,
        metadata: Option<serde_json::Value>,
    ) -> Result<RequiredActionRecord> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let id = generate_id("reqact");
        let metadata = metadata.unwrap_or_else(|| serde_json::json!({}));
        let row = sqlx::query_as::<_, RequiredActionRecord>(
            r#"
            INSERT INTO required_actions (id, tenant_id, user_id, code, state, priority, metadata)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            ON CONFLICT (tenant_id, user_id, code, state)
            DO UPDATE SET priority = EXCLUDED.priority, metadata = EXCLUDED.metadata, updated_at = NOW()
            RETURNING id, tenant_id, user_id, code, state, priority, ttl_seconds, metadata,
                      created_at, updated_at, completed_at, expires_at
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(code)
        .bind(priority)
        .bind(metadata)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Ensure required action: {e}")))?;
        Ok(row)
    }

    pub async fn challenge(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<ChallengeResponse> {
        let action = self
            .registry
            .get(code)
            .ok_or_else(|| AppError::NotFound(format!("Unknown required action: {code}")))?;
        action
            .challenge(&self.db, &ActionContext { tenant_id, user_id })
            .await
    }

    pub async fn complete(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let action = self
            .registry
            .get(code)
            .ok_or_else(|| AppError::NotFound(format!("Unknown required action: {code}")))?;
        action
            .complete(&self.db, &ActionContext { tenant_id, user_id }, payload)
            .await?;
        self.mark_completed_if_pending(tenant_id, user_id, code)
            .await
    }

    async fn mark_completed_if_pending(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE required_actions
            SET state = 'completed', completed_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND code = $3 AND state = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(code)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Complete required action: {e}")))?;
        Ok(())
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set required-action RLS context".into()))?;
        Ok(conn)
    }
}

pub struct VerifyEmailRequiredAction;

#[async_trait]
impl RequiredAction for VerifyEmailRequiredAction {
    fn code(&self) -> &'static str {
        "verify_email"
    }

    fn priority(&self) -> i32 {
        10
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        let verified: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM identities
                WHERE user_id = $1 AND type = 'email' AND verified = TRUE
            )
            "#,
        )
        .bind(ctx.user_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Internal(format!("Evaluate verify_email action: {e}")))?;
        Ok(if verified {
            ActionStatus::Completed
        } else {
            ActionStatus::Pending
        })
    }
}

pub struct ConfigureMfaRequiredAction;

#[async_trait]
impl RequiredAction for ConfigureMfaRequiredAction {
    fn code(&self) -> &'static str {
        "configure_mfa"
    }

    fn priority(&self) -> i32 {
        20
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        let has_factor: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM user_factors
                WHERE user_id = $1 AND tenant_id = $2 AND status IN ('active', 'verified')
                UNION ALL
                SELECT 1 FROM mfa_factors
                WHERE user_id = $1 AND enabled = TRUE AND verified = TRUE
                LIMIT 1
            )
            "#,
        )
        .bind(ctx.user_id)
        .bind(ctx.tenant_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Internal(format!("Evaluate configure_mfa action: {e}")))?;
        Ok(if has_factor {
            ActionStatus::Completed
        } else {
            ActionStatus::NotRequired
        })
    }
}

pub struct UpdatePasswordRequiredAction;

#[async_trait]
impl RequiredAction for UpdatePasswordRequiredAction {
    fn code(&self) -> &'static str {
        "update_password"
    }

    fn priority(&self) -> i32 {
        30
    }

    async fn evaluate(&self, _db: &PgPool, _ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        Ok(ActionStatus::NotRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::RequiredActionRegistry;

    #[test]
    fn default_registry_has_expected_actions() {
        let registry = RequiredActionRegistry::default_actions();
        assert_eq!(registry.len(), 3);
        assert!(registry.get("verify_email").is_some());
        assert!(registry.get("configure_mfa").is_some());
        assert!(registry.get("update_password").is_some());
    }
}
