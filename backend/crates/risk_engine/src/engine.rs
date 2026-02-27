//! Risk Engine
//!
//! Main orchestrator that runs signal collection, scoring, decay, and constraint derivation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use shared_types::{RiskContext, RiskConstraints, AssuranceLevel};

use crate::signals::{SignalCollector, NetworkInput, WebDeviceInput};
use crate::scoring::RiskScorer;
use crate::decay::{RiskDecayService, StabilizingEvent};
use crate::rules::RulesEngine;

/// Risk evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvaluation {
    pub risk: RiskContext,
    pub constraints: RiskConstraints,
    pub evaluated_at: DateTime<Utc>,
    pub flow_id: Option<String>,
}

/// Request context for risk evaluation
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub network: NetworkInput,
    pub device: Option<WebDeviceInput>,
}

/// Subject context (user information if known)
#[derive(Debug, Clone)]
pub struct SubjectContext {
    pub subject_id: String,
    pub org_id: String,
}

/// Main Risk Engine service
#[derive(Clone)]
pub struct RiskEngine {
    signal_collector: SignalCollector,
    scorer: RiskScorer,
    decay_service: RiskDecayService,
    rules_engine: RulesEngine,
    db: PgPool,
}

impl RiskEngine {
    pub fn new(db: PgPool) -> Self {
        Self {
            signal_collector: SignalCollector::new(db.clone()),
            scorer: RiskScorer::new(),
            decay_service: RiskDecayService::new(db.clone()),
            rules_engine: RulesEngine::new(),
            db,
        }
    }
    
    /// Create with IPLocate client for real IP intelligence
    pub fn with_iplocate(db: PgPool, iplocate: crate::signals::IpLocateClient) -> Self {
        Self {
            signal_collector: SignalCollector::with_iplocate(db.clone(), iplocate),
            scorer: RiskScorer::new(),
            decay_service: RiskDecayService::new(db.clone()),
            rules_engine: RulesEngine::new(),
            db,
        }
    }
    
    /// Evaluate risk for a request
    ///
    /// This is the main entry point - runs BEFORE capsule execution.
    pub async fn evaluate(
        &self,
        request: &RequestContext,
        subject: Option<&SubjectContext>,
        flow_id: Option<&str>,
    ) -> RiskEvaluation {
        let user_id = subject.map(|s| s.subject_id.as_str());
        
        // 1. Collect raw signals in parallel
        let signals = self.signal_collector.collect(
            &request.network,
            request.device.as_ref(),
            user_id,
        ).await;
        
        // 2. Load decayed risk state for this subject
        let decayed_state = if let Some(uid) = user_id {
            self.decay_service.load_and_decay(uid).await
        } else {
            None
        };
        
        // 3. Score current risk
        let risk = self.scorer.score(&signals, decayed_state.as_ref());
        
        // 4. Derive constraints from risk
        let constraints = self.rules_engine.derive_constraints(&risk);
        
        // 5. Persist significant risk signals for decay
        if let Some(uid) = user_id {
            self.persist_risk_signals(uid, &signals).await;
        
            // 6. Store evaluation for audit
            let evaluation = RiskEvaluation {
                risk,
                constraints,
                evaluated_at: Utc::now(),
                flow_id: flow_id.map(|s| s.to_string()),
            };
            
            self.store_evaluation(uid, &evaluation).await;
            evaluation
        } else {
            // Anonymous evaluation (no persistence)
            RiskEvaluation {
                risk,
                constraints,
                evaluated_at: Utc::now(),
                flow_id: flow_id.map(|s| s.to_string()),
            }
        }
    }

    /// Persist significant risk signals to the decay service
    async fn persist_risk_signals(&self, user_id: &str, signals: &crate::signals::RawSignals) {
        use crate::decay::{RiskStateEntry, DecayModel};
        
        let now = Utc::now();

        // 1. Phishing Risk (Sticky - requires strong auth to clear)
        if signals.network.is_phishing_source {
            let entry = RiskStateEntry {
                signal_type: "phishing_source".to_string(),
                value: "detected".to_string(), // Could store domain/referrer
                initial_score: 30.0,
                effective_score: 30.0, // Calculated by decay service usually, but set here for clarity
                first_seen: now,
                last_seen: now,
                decay_model: DecayModel::Sticky { 
                    required_event: StabilizingEvent::SuccessfulAal2Auth,
                    required_aal: Some(AssuranceLevel::AAL2),
                },
                stabilized_at: None,
                cleared_at: None,
            };
            self.decay_service.store_risk(user_id, entry).await;
        }

        // 2. Impossible Travel (Temporal - decays quickly, e.g. 4 hours)
        if matches!(signals.network.geo_velocity, shared_types::GeoVelocity::Impossible) {
             let entry = RiskStateEntry {
                signal_type: "impossible_travel".to_string(),
                value: "velocity_check".to_string(),
                initial_score: 40.0,
                effective_score: 40.0,
                first_seen: now,
                last_seen: now,
                decay_model: DecayModel::Temporal { half_life_hours: 4 },
                stabilized_at: None,
                cleared_at: None,
            };
            self.decay_service.store_risk(user_id, entry).await;
        }

        // 3. New Device (Temporal - decays over 7 days to trust)
        if matches!(signals.device.trust, shared_types::DeviceTrust::New) {
             let entry = RiskStateEntry {
                signal_type: "new_device".to_string(),
                value: signals.device.device_id.clone().unwrap_or_default(),
                initial_score: 20.0,
                effective_score: 20.0,
                first_seen: now,
                last_seen: now,
                decay_model: DecayModel::Temporal { half_life_hours: 24 * 7 }, // 7 days half-life
                stabilized_at: None,
                cleared_at: None,
            };
            self.decay_service.store_risk(user_id, entry).await;
        }
    }
    
    /// Quick evaluation for existing flows (uses cached signals if available)
    pub async fn quick_evaluate(
        &self,
        subject_id: &str,
    ) -> RiskEvaluation {
        // Load decayed state only
        let decayed_state = self.decay_service.load_and_decay(subject_id).await;
        
        // Create minimal risk context from decayed state
        let risk = if let Some(state) = &decayed_state {
            let mut total_score = 0.0;
            for entry in state.entries.values() {
                total_score += entry.effective_score;
            }
            let overall = shared_types::RiskLevel::from_score(total_score);
            
            RiskContext {
                overall,
                ..Default::default()
            }
        } else {
            RiskContext::default()
        };
        
        let constraints = self.rules_engine.derive_constraints(&risk);
        
        RiskEvaluation {
            risk,
            constraints,
            evaluated_at: Utc::now(),
            flow_id: None,
        }
    }
    
    /// Apply stabilizing event after successful auth
    pub async fn on_successful_auth(
        &self,
        subject_id: &str,
        achieved_aal: AssuranceLevel,
    ) {
        let event = match achieved_aal {
            AssuranceLevel::AAL3 => StabilizingEvent::SuccessfulAal3Auth,
            AssuranceLevel::AAL2 => StabilizingEvent::SuccessfulAal2Auth,
            _ => return, // AAL0/AAL1 don't stabilize
        };
        
        self.decay_service.apply_stabilizing_event(subject_id, event, achieved_aal).await;
    }
    
    /// Record device trust after successful auth
    pub async fn on_device_verified(
        &self,
        device_id: &str,
        subject_id: &str,
        device_input: &WebDeviceInput,
    ) {
        self.signal_collector.device
            .record_successful_auth(device_id, subject_id, device_input)
            .await
            .ok();
    }
    
    /// Store risk evaluation for audit
    async fn store_evaluation(&self, subject_id: &str, eval: &RiskEvaluation) {
        let risk_json = serde_json::to_string(&eval.risk).unwrap_or_default();
        let constraints_json = serde_json::to_string(&eval.constraints).unwrap_or_default();
        
        sqlx::query(
            r#"
            INSERT INTO risk_evaluations (
                id, subject_id, flow_id, risk_snapshot, constraints_derived, evaluated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#
        )
        .bind(shared_types::generate_id("reval"))
        .bind(subject_id)
        .bind(&eval.flow_id)
        .bind(&risk_json)
        .bind(&constraints_json)
        .bind(eval.evaluated_at)
        .execute(&self.db)
        .await
        .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    
    // Note: Full integration tests require a database connection
    // These are placeholder tests for the API structure
    
    #[test]
    fn test_risk_evaluation_serde() {
        let eval = RiskEvaluation {
            risk: RiskContext::default(),
            constraints: RiskConstraints::default(),
            evaluated_at: Utc::now(),
            flow_id: Some("flow_123".to_string()),
        };
        
        let json = serde_json::to_string(&eval).unwrap();
        let parsed: RiskEvaluation = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.flow_id, Some("flow_123".to_string()));
    }
    
    #[test]
    fn test_request_context_creation() {
        use chrono::Utc;
        
        let ctx = RequestContext {
            network: NetworkInput {
                remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
                x_forwarded_for: None,
                user_agent: "test".to_string(),
                accept_language: None,
                timestamp: Utc::now(),
            },
            device: None,
        };
        
        assert!(ctx.device.is_none());
    }
}
