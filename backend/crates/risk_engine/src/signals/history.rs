//! History Signal Service
//!
//! Analyzes account history for security events.

use serde::{Deserialize, Serialize};

use shared_types::AccountStability;

/// Normalized history signals
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistorySignals {
    /// Account stability classification
    pub stability: AccountStability,
    /// Recent password reset (within 24h)
    pub recent_password_reset: bool,
    /// Recent MFA reset (within 7d)
    pub recent_mfa_reset: bool,
    /// Failed auth attempts in last hour
    pub failed_attempts_1h: u32,
    /// Failed auth attempts in last 24 hours
    pub failed_attempts_24h: u32,
    /// Recent lockout (within 24h)
    pub recent_lockout: bool,
}

impl HistorySignals {
    pub fn risk_score(&self) -> f64 {
        let mut score = 0.0;
        
        if self.recent_password_reset { score += 20.0; }
        if self.recent_mfa_reset { score += 30.0; }
        if self.recent_lockout { score += 25.0; }
        
        // Failed attempts contribution
        if self.failed_attempts_1h > 5 { score += 30.0; }
        else if self.failed_attempts_1h > 2 { score += 15.0; }
        
        if self.failed_attempts_24h > 20 { score += 20.0; }
        else if self.failed_attempts_24h > 10 { score += 10.0; }
        
        score
    }
    
    pub fn is_stable(&self) -> bool {
        !self.recent_password_reset 
            && !self.recent_mfa_reset 
            && !self.recent_lockout
            && self.failed_attempts_24h < 10
    }
}

/// History signal analysis service
#[derive(Clone)]
pub struct HistorySignalService {
    db: sqlx::PgPool,
}

impl HistorySignalService {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }
    
    /// Analyze account history signals
    pub async fn analyze(&self, user_id: Option<&str>) -> HistorySignals {
        let Some(uid) = user_id else {
            // No user context - return clean signals
            return HistorySignals::default();
        };
        
        // Load security events from database
        let events = self.load_security_events(uid).await;
        let failed_counts = self.load_failed_attempts(uid).await;
        
        let recent_password_reset = events.password_reset_within_24h;
        let recent_mfa_reset = events.mfa_reset_within_7d;
        let recent_lockout = events.lockout_within_24h;
        
        let stability = if recent_password_reset || recent_mfa_reset || recent_lockout {
            AccountStability::Unstable
        } else {
            AccountStability::Stable
        };
        
        HistorySignals {
            stability,
            recent_password_reset,
            recent_mfa_reset,
            failed_attempts_1h: failed_counts.last_1h,
            failed_attempts_24h: failed_counts.last_24h,
            recent_lockout,
        }
    }
    
    async fn load_security_events(&self, user_id: &str) -> SecurityEvents {
        // Use runtime query - tables may not exist yet
        let result = sqlx::query(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE event_type = 'password_reset' AND created_at > NOW() - INTERVAL '24 hours') as password_resets,
                COUNT(*) FILTER (WHERE event_type = 'mfa_reset' AND created_at > NOW() - INTERVAL '7 days') as mfa_resets,
                COUNT(*) FILTER (WHERE event_type = 'lockout' AND created_at > NOW() - INTERVAL '24 hours') as lockouts
            FROM security_events
            WHERE user_id = $1
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await;
        
        match result {
            Ok(Some(row)) => {
                use sqlx::Row;
                SecurityEvents {
                    password_reset_within_24h: row.get::<Option<i64>, _>("password_resets").unwrap_or(0) > 0,
                    mfa_reset_within_7d: row.get::<Option<i64>, _>("mfa_resets").unwrap_or(0) > 0,
                    lockout_within_24h: row.get::<Option<i64>, _>("lockouts").unwrap_or(0) > 0,
                }
            },
            _ => SecurityEvents::default(),
        }
    }
    
    async fn load_failed_attempts(&self, user_id: &str) -> FailedAttemptCounts {
        let result = sqlx::query(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') as last_1h,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h
            FROM auth_attempts
            WHERE user_id = $1 AND success = false
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await;
        
        match result {
            Ok(Some(row)) => {
                use sqlx::Row;
                FailedAttemptCounts {
                    last_1h: row.get::<Option<i64>, _>("last_1h").unwrap_or(0) as u32,
                    last_24h: row.get::<Option<i64>, _>("last_24h").unwrap_or(0) as u32,
                }
            },
            _ => FailedAttemptCounts::default(),
        }
    }
}

#[derive(Debug, Default)]
struct SecurityEvents {
    password_reset_within_24h: bool,
    mfa_reset_within_7d: bool,
    lockout_within_24h: bool,
}

#[derive(Debug, Default)]
struct FailedAttemptCounts {
    last_1h: u32,
    last_24h: u32,
}

