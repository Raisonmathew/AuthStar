//! Risk Decay Service
//!
//! Manages temporal decay, sticky risk, and non-decaying risk states.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use shared_types::AssuranceLevel;

/// Decay model for a risk signal
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecayModel {
    /// Exponential time-based decay
    Temporal { half_life_hours: u32 },
    /// Decays only after stabilizing event
    Sticky { required_event: StabilizingEvent, required_aal: Option<AssuranceLevel> },
    /// Never auto-decays, requires manual remediation
    NonDecaying { required_actions: Vec<RemediationAction> },
}

/// Events that can stabilize sticky risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StabilizingEvent {
    SuccessfulAal2Auth,
    SuccessfulAal3Auth,
    PasskeyEnrollment,
    AdminVerification,
    PasswordChangeWithMfa,
}

/// Actions required to clear non-decaying risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    DeviceReRegistration,
    PasswordResetWithMfa,
    AdminApproval,
    IdentityVerification,
}

/// Persistent risk state entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskStateEntry {
    pub signal_type: String,
    pub value: String,
    pub initial_score: f64,
    pub effective_score: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub decay_model: DecayModel,
    pub stabilized_at: Option<DateTime<Utc>>,
    pub cleared_at: Option<DateTime<Utc>>,
}

impl RiskStateEntry {
    pub fn with_effective_score(mut self, score: f64) -> Self {
        self.effective_score = score;
        self
    }
}

/// Subject's complete risk state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectRiskState {
    pub subject_id: String,
    pub entries: HashMap<String, RiskStateEntry>,
    pub last_evaluated: DateTime<Utc>,
}

/// Risk decay service
#[derive(Clone)]
pub struct RiskDecayService {
    db: sqlx::PgPool,
}

impl RiskDecayService {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }
    
    /// Load risk state and compute decayed scores
    pub async fn load_and_decay(&self, subject_id: &str) -> Option<SubjectRiskState> {
        let now = Utc::now();
        let entries = self.load_risk_entries(subject_id).await;
        
        if entries.is_empty() {
            return None;
        }
        
        let mut effective_entries = HashMap::new();
        
        for (signal_type, mut entry) in entries {
            let effective_score = match &entry.decay_model {
                DecayModel::Temporal { half_life_hours } => {
                    Self::compute_temporal_decay(
                        entry.initial_score,
                        entry.last_seen,
                        now,
                        *half_life_hours,
                    )
                }
                DecayModel::Sticky { .. } => {
                    if entry.stabilized_at.is_some() {
                        0.0 // Stabilized = no risk
                    } else {
                        entry.initial_score // Full risk until stabilized
                    }
                }
                DecayModel::NonDecaying { .. } => {
                    if entry.cleared_at.is_some() {
                        0.0 // Manually cleared
                    } else {
                        entry.initial_score // Full risk until remediated
                    }
                }
            };
            
            // Only include entries with significant remaining risk
            if effective_score > 1.0 {
                entry.effective_score = effective_score;
                effective_entries.insert(signal_type, entry);
            }
        }
        
        Some(SubjectRiskState {
            subject_id: subject_id.to_string(),
            entries: effective_entries,
            last_evaluated: now,
        })
    }
    
    /// Compute temporal decay using exponential formula
    /// effective_score(t) = initial_score × e^(−λ × elapsed_time)
    /// where λ = ln(2) / half_life
    fn compute_temporal_decay(
        initial_score: f64,
        last_seen: DateTime<Utc>,
        now: DateTime<Utc>,
        half_life_hours: u32,
    ) -> f64 {
        let elapsed_hours = (now - last_seen).num_seconds() as f64 / 3600.0;
        let lambda = 0.693147 / (half_life_hours as f64); // ln(2)
        initial_score * (-lambda * elapsed_hours).exp()
    }
    
    /// Apply stabilizing event to clear sticky risks
    pub async fn apply_stabilizing_event(
        &self,
        subject_id: &str,
        event: StabilizingEvent,
        achieved_aal: AssuranceLevel,
    ) {
        let entries = self.load_risk_entries(subject_id).await;
        
        for (signal_type, entry) in entries {
            if let DecayModel::Sticky { required_event, required_aal } = &entry.decay_model {
                if event == *required_event {
                    let aal_ok = required_aal.map_or(true, |min| achieved_aal >= min);
                    if aal_ok {
                        self.mark_stabilized(subject_id, &signal_type).await;
                    }
                }
            }
        }
    }
    
    /// Apply remediation to clear non-decaying risks
    pub async fn apply_remediation(
        &self,
        subject_id: &str,
        signal_type: &str,
        completed_actions: &[RemediationAction],
    ) -> bool {
        if let Some(entry) = self.load_risk_entry(subject_id, signal_type).await {
            if let DecayModel::NonDecaying { required_actions } = &entry.decay_model {
                let all_complete = required_actions.iter().all(|a| completed_actions.contains(a));
                if all_complete {
                    self.mark_cleared(subject_id, signal_type).await;
                    return true;
                }
            }
        }
        false
    }
    
    /// Store a new risk state entry
    pub async fn store_risk(&self, subject_id: &str, entry: RiskStateEntry) {
        let decay_model_json = serde_json::to_string(&entry.decay_model).unwrap_or_default();
        
        sqlx::query(
            r#"
            INSERT INTO risk_states (
                id, subject_type, subject_id, signal_type, value,
                initial_score, severity, decay_model, decay_config,
                first_seen_at, last_seen_at
            )
            VALUES ($1, 'user', $2, $3, $4, $5, 'medium', 'temporal', $6, $7, $7)
            ON CONFLICT (subject_type, subject_id, signal_type) DO UPDATE SET
                last_seen_at = $7,
                initial_score = GREATEST(risk_states.initial_score, $5)
            "#
        )
        .bind(shared_types::generate_id("rsk"))
        .bind(subject_id)
        .bind(&entry.signal_type)
        .bind(&entry.value)
        .bind(entry.initial_score)
        .bind(&decay_model_json)
        .bind(entry.last_seen)
        .execute(&self.db)
        .await
        .ok();
    }
    
    async fn load_risk_entries(&self, subject_id: &str) -> HashMap<String, RiskStateEntry> {
        // Use runtime query - table may not exist yet
        let rows = sqlx::query(
            r#"
            SELECT 
                signal_type, value, initial_score,
                first_seen_at, last_seen_at,
                decay_config, stabilized_at, cleared_at
            FROM risk_states
            WHERE subject_id = $1 AND subject_type = 'user'
              AND cleared_at IS NULL
            "#
        )
        .bind(subject_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();
        
        let mut entries = HashMap::new();
        for row in rows {
            use sqlx::Row;
            let signal_type: String = row.get("signal_type");
            let decay_config: Option<String> = row.get("decay_config");
            let decay_model = serde_json::from_str(&decay_config.unwrap_or_default())
                .unwrap_or(DecayModel::Temporal { half_life_hours: 24 });
            
            entries.insert(signal_type.clone(), RiskStateEntry {
                signal_type,
                value: row.get("value"),
                initial_score: row.get::<Option<f64>, _>("initial_score").unwrap_or(0.0),
                effective_score: 0.0,
                first_seen: row.get("first_seen_at"),
                last_seen: row.get("last_seen_at"),
                decay_model,
                stabilized_at: row.get("stabilized_at"),
                cleared_at: row.get("cleared_at"),
            });
        }
        entries
    }
    
    async fn load_risk_entry(&self, subject_id: &str, signal_type: &str) -> Option<RiskStateEntry> {
        self.load_risk_entries(subject_id).await.remove(signal_type)
    }
    
    async fn mark_stabilized(&self, subject_id: &str, signal_type: &str) {
        sqlx::query(
            r#"
            UPDATE risk_states 
            SET stabilized_at = NOW()
            WHERE subject_id = $1 AND signal_type = $2 AND subject_type = 'user'
            "#
        )
        .bind(subject_id)
        .bind(signal_type)
        .execute(&self.db)
        .await
        .ok();
    }
    
    async fn mark_cleared(&self, subject_id: &str, signal_type: &str) {
        sqlx::query(
            r#"
            UPDATE risk_states 
            SET cleared_at = NOW()
            WHERE subject_id = $1 AND signal_type = $2 AND subject_type = 'user'
            "#
        )
        .bind(subject_id)
        .bind(signal_type)
        .execute(&self.db)
        .await
        .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    
    #[test]
    fn test_temporal_decay_half_life() {
        let initial = 100.0;
        let half_life = 24; // hours
        let last_seen = Utc::now() - Duration::hours(24);
        let now = Utc::now();
        
        let decayed = RiskDecayService::compute_temporal_decay(initial, last_seen, now, half_life);
        
        // After one half-life, should be ~50%
        assert!(decayed > 45.0 && decayed < 55.0);
    }
    
    #[test]
    fn test_temporal_decay_two_half_lives() {
        let initial = 100.0;
        let half_life = 24;
        let last_seen = Utc::now() - Duration::hours(48);
        let now = Utc::now();
        
        let decayed = RiskDecayService::compute_temporal_decay(initial, last_seen, now, half_life);
        
        // After two half-lives, should be ~25%
        assert!(decayed > 22.0 && decayed < 28.0);
    }
    
    #[test]
    fn test_temporal_decay_zero_time() {
        let initial = 100.0;
        let half_life = 24;
        let now = Utc::now();
        
        let decayed = RiskDecayService::compute_temporal_decay(initial, now, now, half_life);
        
        // No time passed, should be 100%
        assert!((decayed - initial).abs() < 0.1);
    }
}
