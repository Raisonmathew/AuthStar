use crate::middleware::org_context::set_rls_context_on_conn;
use chrono::{DateTime, Duration, Utc};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use sqlx::{PgPool, Postgres};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    Password,
    Totp,
    Hotp,
    WebAuthn,
    RecoveryCode,
    Sms,
    Email,
}

impl FactorKind {
    pub const ALL: [FactorKind; 7] = [
        FactorKind::Password,
        FactorKind::Totp,
        FactorKind::Hotp,
        FactorKind::WebAuthn,
        FactorKind::RecoveryCode,
        FactorKind::Sms,
        FactorKind::Email,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FactorKind::Password => "password",
            FactorKind::Totp => "totp",
            FactorKind::Hotp => "hotp",
            FactorKind::WebAuthn => "webauthn",
            FactorKind::RecoveryCode => "recovery_code",
            FactorKind::Sms => "sms",
            FactorKind::Email => "email",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCounters {
    pub last_1h: i32,
    pub last_24h: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct CredentialLockoutPolicy {
    pub id: String,
    pub tenant_id: String,
    pub factor_kind: String,
    pub enabled: bool,
    pub failure_threshold: i32,
    pub window_seconds: i32,
    pub lock_duration_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCredentialLockoutPolicyRequest {
    pub enabled: Option<bool>,
    pub failure_threshold: Option<i32>,
    pub window_seconds: Option<i32>,
    pub lock_duration_seconds: Option<i32>,
}

#[derive(Clone)]
pub struct CredentialLockoutService {
    db: PgPool,
    redis: ConnectionManager,
}

impl CredentialLockoutService {
    pub fn new(db: PgPool, redis: ConnectionManager) -> Self {
        Self { db, redis }
    }

    pub async fn record_failure(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
    ) -> Result<CredentialCounters> {
        let policy = self.get_policy(tenant_id, factor).await?;
        let one_hour = self
            .increment_window(tenant_id, user_id, factor, "1h", 3600)
            .await?;
        let day = self
            .increment_window(tenant_id, user_id, factor, "24h", 24 * 3600)
            .await?;

        let active_count = if !policy.enabled {
            0
        } else if policy.window_seconds == 3600 {
            one_hour
        } else if policy.window_seconds == 24 * 3600 {
            day
        } else {
            self.increment_window(
                tenant_id,
                user_id,
                factor,
                &policy_window_key(policy.window_seconds),
                policy.window_seconds as i64,
            )
            .await?
        };
        let locked_until = if policy.enabled && active_count >= policy.failure_threshold {
            Some(Utc::now() + Duration::seconds(policy.lock_duration_seconds as i64))
        } else {
            None
        };

        let counters = CredentialCounters {
            last_1h: one_hour,
            last_24h: day,
            locked_until,
        };
        self.persist(tenant_id, user_id, factor, &counters, true)
            .await?;
        Ok(counters)
    }

    pub async fn record_success(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
    ) -> Result<()> {
        let policy = self.get_policy(tenant_id, factor).await?;
        let mut conn = self.redis.clone();
        for window in reset_windows(policy.window_seconds) {
            let key = self.redis_key(tenant_id, user_id, factor, &window);
            let _: () = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|e| AppError::Internal(format!("Redis DEL credential counter: {e}")))?;
        }
        let counters = CredentialCounters {
            last_1h: 0,
            last_24h: 0,
            locked_until: None,
        };
        self.persist(tenant_id, user_id, factor, &counters, false)
            .await
    }

    pub async fn ensure_not_locked(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
    ) -> Result<()> {
        let policy = self.get_policy(tenant_id, factor).await?;
        if !policy.enabled {
            return Ok(());
        }

        if let Some(locked_until) = self.locked_until(tenant_id, user_id, factor).await? {
            return Err(AppError::TooManyRequests(format!(
                "Credential is locked until {}",
                locked_until.to_rfc3339()
            )));
        }
        Ok(())
    }

    pub async fn locked_until(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
    ) -> Result<Option<DateTime<Utc>>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let locked_until: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            SELECT locked_until
            FROM credential_attempt_counters
            WHERE tenant_id = $1 AND user_id = $2 AND factor_kind = $3
              AND locked_until > NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(factor.as_str())
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch credential lockout: {e}")))?
        .flatten();
        Ok(locked_until)
    }

    pub async fn reset_user_factor(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
    ) -> Result<()> {
        let policy = self.get_policy(tenant_id, factor).await?;
        let mut redis_conn = self.redis.clone();
        for window in reset_windows(policy.window_seconds) {
            let key = self.redis_key(tenant_id, user_id, factor, &window);
            let _: () = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut redis_conn)
                .await
                .map_err(|e| AppError::Internal(format!("Redis DEL credential counter: {e}")))?;
        }

        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE credential_attempt_counters
            SET last_1h = 0,
                last_24h = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND factor_kind = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(factor.as_str())
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Reset credential counters: {e}")))?;
        Ok(())
    }

    pub async fn get_policy(
        &self,
        tenant_id: &str,
        factor: FactorKind,
    ) -> Result<CredentialLockoutPolicy> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        self.get_policy_with_conn(tenant_id, factor, &mut conn)
            .await
    }

    pub async fn update_policy(
        &self,
        tenant_id: &str,
        factor: FactorKind,
        req: UpdateCredentialLockoutPolicyRequest,
    ) -> Result<CredentialLockoutPolicy> {
        if let Some(threshold) = req.failure_threshold {
            if !(1..=100).contains(&threshold) {
                return Err(AppError::Validation(
                    "failureThreshold must be between 1 and 100".to_string(),
                ));
            }
        }
        if let Some(window) = req.window_seconds {
            if !(60..=86_400).contains(&window) {
                return Err(AppError::Validation(
                    "windowSeconds must be between 60 and 86400".to_string(),
                ));
            }
        }
        if let Some(duration) = req.lock_duration_seconds {
            if !(60..=2_592_000).contains(&duration) {
                return Err(AppError::Validation(
                    "lockDurationSeconds must be between 60 and 2592000".to_string(),
                ));
            }
        }

        let mut conn = self.tenant_conn(tenant_id).await?;
        self.get_policy_with_conn(tenant_id, factor, &mut conn)
            .await?;
        let policy = sqlx::query_as::<_, CredentialLockoutPolicy>(
            r#"
            UPDATE credential_lockout_policies
            SET enabled = COALESCE($3, enabled),
                failure_threshold = COALESCE($4, failure_threshold),
                window_seconds = COALESCE($5, window_seconds),
                lock_duration_seconds = COALESCE($6, lock_duration_seconds),
                updated_at = NOW()
            WHERE tenant_id = $1 AND factor_kind = $2
            RETURNING id, tenant_id, factor_kind, enabled, failure_threshold,
                      window_seconds, lock_duration_seconds, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(factor.as_str())
        .bind(req.enabled)
        .bind(req.failure_threshold)
        .bind(req.window_seconds)
        .bind(req.lock_duration_seconds)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Update lockout policy: {e}")))?;
        Ok(policy)
    }

    pub async fn snapshot(&self, tenant_id: &str, user_id: &str) -> Result<HashMap<String, i32>> {
        let mut out = HashMap::new();
        for factor in FactorKind::ALL {
            let count = self
                .window_count(tenant_id, user_id, factor, "1h")
                .await
                .unwrap_or(0);
            if count > 0 {
                out.insert(factor.as_str().to_string(), count);
            }
        }

        if !out.is_empty() {
            return Ok(out);
        }

        let mut db_conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut db_conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set credential counter RLS context".into()))?;

        let rows: Vec<(String, i32)> = sqlx::query_as(
            r#"
            SELECT factor_kind, last_1h
            FROM credential_attempt_counters
            WHERE tenant_id = $1 AND user_id = $2 AND last_1h > 0
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *db_conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch credential counters: {e}")))?;

        Ok(rows.into_iter().collect())
    }

    async fn increment_window(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
        window: &str,
        ttl_seconds: i64,
    ) -> Result<i32> {
        let key = self.redis_key(tenant_id, user_id, factor, window);
        let mut conn = self.redis.clone();
        let count: i64 = redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis INCR credential counter: {e}")))?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(ttl_seconds)
                .query_async(&mut conn)
                .await
                .map_err(|e| AppError::Internal(format!("Redis EXPIRE credential counter: {e}")))?;
        }
        Ok(count.min(i32::MAX as i64) as i32)
    }

    async fn window_count(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
        window: &str,
    ) -> Result<i32> {
        let key = self.redis_key(tenant_id, user_id, factor, window);
        let mut conn = self.redis.clone();
        let value: Option<i64> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET credential counter: {e}")))?;
        Ok(value.unwrap_or(0).min(i32::MAX as i64) as i32)
    }

    async fn persist(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
        counters: &CredentialCounters,
        failure: bool,
    ) -> Result<()> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set credential counter RLS context".into()))?;

        sqlx::query(
            r#"
            INSERT INTO credential_attempt_counters
                (tenant_id, user_id, factor_kind, last_1h, last_24h, locked_until, last_failure_at, last_success_at)
            VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN NOW() ELSE NULL END, CASE WHEN $7 THEN NULL ELSE NOW() END)
            ON CONFLICT (tenant_id, user_id, factor_kind)
            DO UPDATE SET
                last_1h = EXCLUDED.last_1h,
                last_24h = EXCLUDED.last_24h,
                locked_until = EXCLUDED.locked_until,
                last_failure_at = CASE WHEN $7 THEN NOW() ELSE credential_attempt_counters.last_failure_at END,
                last_success_at = CASE WHEN $7 THEN credential_attempt_counters.last_success_at ELSE NOW() END,
                updated_at = NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(factor.as_str())
        .bind(counters.last_1h)
        .bind(counters.last_24h)
        .bind(counters.locked_until)
        .bind(failure)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Persist credential counters: {e}")))?;
        Ok(())
    }

    async fn get_policy_with_conn(
        &self,
        tenant_id: &str,
        factor: FactorKind,
        conn: &mut sqlx::pool::PoolConnection<Postgres>,
    ) -> Result<CredentialLockoutPolicy> {
        if let Some(policy) = sqlx::query_as::<_, CredentialLockoutPolicy>(
            r#"
            SELECT id, tenant_id, factor_kind, enabled, failure_threshold,
                   window_seconds, lock_duration_seconds, created_at, updated_at
            FROM credential_lockout_policies
            WHERE tenant_id = $1 AND factor_kind = $2
            "#,
        )
        .bind(tenant_id)
        .bind(factor.as_str())
        .fetch_optional(&mut **conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch lockout policy: {e}")))?
        {
            return Ok(policy);
        }

        sqlx::query_as::<_, CredentialLockoutPolicy>(
            r#"
            INSERT INTO credential_lockout_policies (tenant_id, factor_kind)
            VALUES ($1, $2)
            RETURNING id, tenant_id, factor_kind, enabled, failure_threshold,
                      window_seconds, lock_duration_seconds, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(factor.as_str())
        .fetch_one(&mut **conn)
        .await
        .map_err(|e| AppError::Internal(format!("Create default lockout policy: {e}")))
    }

    async fn tenant_conn(&self, tenant_id: &str) -> Result<sqlx::pool::PoolConnection<Postgres>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set credential lockout RLS context".into()))?;
        Ok(conn)
    }

    fn redis_key(
        &self,
        tenant_id: &str,
        user_id: &str,
        factor: FactorKind,
        window: &str,
    ) -> String {
        format!(
            "cred_attempt:{tenant_id}:{user_id}:{}:{window}",
            factor.as_str()
        )
    }
}

fn policy_window_key(window_seconds: i32) -> String {
    format!("policy:{}s", window_seconds)
}

fn reset_windows(window_seconds: i32) -> Vec<String> {
    let mut windows = vec!["1h".to_string(), "24h".to_string()];
    let policy_window = policy_window_key(window_seconds);
    if !windows.iter().any(|window| window == &policy_window) {
        windows.push(policy_window);
    }
    windows
}

#[cfg(test)]
mod tests {
    use super::FactorKind;

    #[test]
    fn factor_kind_names_are_stable() {
        assert_eq!(FactorKind::Password.as_str(), "password");
        assert_eq!(FactorKind::WebAuthn.as_str(), "webauthn");
        assert_eq!(FactorKind::RecoveryCode.as_str(), "recovery_code");
    }
}
