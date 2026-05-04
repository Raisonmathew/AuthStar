use crate::middleware::org_context::set_rls_context_on_conn;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use sqlx::PgPool;
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
        let one_hour = self
            .increment_window(tenant_id, user_id, factor, "1h", 3600)
            .await?;
        let day = self
            .increment_window(tenant_id, user_id, factor, "24h", 24 * 3600)
            .await?;

        let counters = CredentialCounters {
            last_1h: one_hour,
            last_24h: day,
            locked_until: None,
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
        let mut conn = self.redis.clone();
        for window in ["1h", "24h"] {
            let key = self.redis_key(tenant_id, user_id, factor, window);
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
