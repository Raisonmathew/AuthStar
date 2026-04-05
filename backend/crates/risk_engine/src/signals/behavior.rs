//! Behavior Signal Service
//!
//! Analyzes user behavior patterns for anomalies.

use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Normalized behavior signals
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorSignals {
    /// Login at unusual time for this user
    pub time_anomaly: bool,
    /// Interaction speed suggests automation
    pub automation_suspected: bool,
    /// Flow was completed unusually fast or with unexpected patterns
    pub flow_deviation: bool,
    /// Overall behavior anomaly flag
    pub anomaly_detected: bool,
}

impl BehaviorSignals {
    pub fn risk_score(&self) -> f64 {
        let mut score = 0.0;
        if self.time_anomaly {
            score += 10.0;
        }
        if self.automation_suspected {
            score += 20.0;
        }
        if self.flow_deviation {
            score += 15.0;
        }
        score
    }
}

/// Behavior signal analysis service
#[derive(Clone)]
pub struct BehaviorSignalService {
    db: Option<sqlx::PgPool>,
}

impl BehaviorSignalService {
    pub fn new() -> Self {
        Self { db: None }
    }

    pub fn with_db(db: sqlx::PgPool) -> Self {
        Self { db: Some(db) }
    }

    /// Analyze behavior signals
    pub async fn analyze(&self, user_id: Option<&str>) -> BehaviorSignals {
        let Some(uid) = user_id else {
            return BehaviorSignals::default();
        };

        let Some(db) = &self.db else {
            return BehaviorSignals::default();
        };

        let mut signals = BehaviorSignals::default();

        if let Some(time_anomaly) = self.check_time_anomaly_with_db(db, uid).await {
            signals.time_anomaly = time_anomaly;
        }

        if let Some((success_2m, fail_2m, total_10m)) =
            self.load_recent_attempt_counts(db, uid).await
        {
            signals.automation_suspected = success_2m >= 3 || fail_2m >= 10;
            signals.flow_deviation = total_10m >= 20;
        }

        signals.anomaly_detected =
            signals.time_anomaly || signals.automation_suspected || signals.flow_deviation;
        signals
    }

    /// Check if current time is anomalous for this user
    pub async fn check_time_anomaly(&self, _user_id: &str) -> bool {
        false
    }
}

impl BehaviorSignalService {
    async fn check_time_anomaly_with_db(&self, db: &sqlx::PgPool, user_id: &str) -> Option<bool> {
        let rows = sqlx::query(
            r#"
            SELECT date_part('hour', created_at AT TIME ZONE 'UTC') as hour, COUNT(*) as cnt
            FROM auth_attempts
            WHERE user_id = $1 AND success = true AND created_at > NOW() - INTERVAL '30 days'
            GROUP BY hour
            "#
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(|e| {
            tracing::warn!(user_id = %user_id, error = %e, "Failed to load time anomaly data from DB");
            e
        })
        .ok()?;

        let mut total = 0i64;
        let mut hours: Vec<i32> = Vec::new();
        for row in rows {
            let hour = row.get::<Option<f64>, _>("hour").unwrap_or(0.0) as i32;
            let cnt = row.get::<Option<i64>, _>("cnt").unwrap_or(0);
            total += cnt;
            if cnt > 0 {
                hours.push(hour);
            }
        }

        if total < 5 {
            return Some(false);
        }

        let current_hour = Utc::now().hour() as i32;
        let within_window = hours.iter().any(|h| {
            let diff = (current_hour - *h).abs();
            diff <= 1 || diff >= 23
        });

        Some(!within_window)
    }

    async fn load_recent_attempt_counts(
        &self,
        db: &sqlx::PgPool,
        user_id: &str,
    ) -> Option<(i64, i64, i64)> {
        let row = sqlx::query(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '2 minutes' AND success = true) as success_2m,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '2 minutes' AND success = false) as fail_2m,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '10 minutes') as total_10m
            FROM auth_attempts
            WHERE user_id = $1
            "#
        )
        .bind(user_id)
        .fetch_optional(db)
        .await
        .ok()??;

        let success_2m = row.get::<Option<i64>, _>("success_2m").unwrap_or(0);
        let fail_2m = row.get::<Option<i64>, _>("fail_2m").unwrap_or(0);
        let total_10m = row.get::<Option<i64>, _>("total_10m").unwrap_or(0);

        Some((success_2m, fail_2m, total_10m))
    }
}

impl Default for BehaviorSignalService {
    fn default() -> Self {
        Self::new()
    }
}
