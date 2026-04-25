//! Auth Attempts Pruning Job
//!
//! Periodically deletes rows from `auth_attempts` older than the configured
//! retention window (default: 7 days). Without pruning, this table grows
//! unboundedly with every login/MFA/refresh attempt and slowly degrades
//! risk-engine query performance (behavior + history signals scan it on
//! every authorization decision).
//!
//! Retention is intentionally short because the data is only consumed by
//! short-horizon risk signals (recent failure rate, IP velocity, etc.).
//! Long-term auditing lives in the immutable audit log, not here.

use sqlx::PgPool;
use std::time::Duration;
use tracing::{error, info};

/// How long to keep `auth_attempts` rows before pruning.
const RETENTION_DAYS: i32 = 7;

/// How often the prune loop wakes up.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

#[derive(Clone)]
pub struct AuthAttemptsPruneJob {
    db: PgPool,
}

impl AuthAttemptsPruneJob {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Delete rows older than `RETENTION_DAYS` days. Returns the number of
    /// rows removed in this pass.
    pub async fn run_once(&self) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM auth_attempts WHERE created_at < NOW() - ($1 || ' days')::INTERVAL",
        )
        .bind(RETENTION_DAYS.to_string())
        .execute(&self.db)
        .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!(
                deleted_rows = deleted,
                retention_days = RETENTION_DAYS,
                "Pruned old auth_attempts rows"
            );
        }
        Ok(deleted)
    }

    /// Spawn the periodic background loop. Safe to call once at startup.
    pub fn spawn(self) {
        tokio::spawn(async move {
            // Initial delay so we don't compete with startup work.
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                if let Err(e) = self.run_once().await {
                    error!(error = %e, "auth_attempts prune job failed");
                }
                tokio::time::sleep(PRUNE_INTERVAL).await;
            }
        });
    }
}
