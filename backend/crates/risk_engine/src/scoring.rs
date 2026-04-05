//! Risk Scoring
//!
//! Deterministic risk scoring from collected signals.

use shared_types::{DeviceTrust, GeoVelocity, IpReputation, RiskContext, RiskLevel};

use crate::decay::SubjectRiskState;
use crate::signals::RawSignals;

/// Risk scorer that computes overall risk from signals
#[derive(Clone, Copy)]
pub struct RiskScorer;

impl RiskScorer {
    pub fn new() -> Self {
        Self
    }

    /// Score risk from raw signals and optionally decayed persistent state
    pub fn score(
        &self,
        signals: &RawSignals,
        decayed_state: Option<&SubjectRiskState>,
    ) -> RiskContext {
        let mut total_score = 0.0;

        // Network signals
        total_score += Self::ip_reputation_score(&signals.network.ip_reputation);
        total_score += Self::geo_velocity_score(&signals.network.geo_velocity);
        if signals.network.is_phishing_source {
            total_score += 30.0;
        }

        // Device signals
        total_score += Self::device_trust_score(&signals.device.trust);

        // Behavior signals
        total_score += signals.behavior.risk_score();

        // History signals
        total_score += signals.history.risk_score();

        // Add residual risk from persistent decayed state
        if let Some(state) = decayed_state {
            for entry in state.entries.values() {
                total_score += entry.effective_score;
            }
        }

        // Classify overall risk
        let overall = RiskLevel::from_score(total_score);

        RiskContext {
            overall,
            device_trust: signals.device.trust,
            ip_reputation: signals.network.ip_reputation,
            geo_velocity: signals.network.geo_velocity,
            phishing_risk: signals.network.is_phishing_source,
            account_stability: signals.history.stability,
            behavior_anomaly: signals.behavior.anomaly_detected,
            failed_attempts_1h: signals.history.failed_attempts_1h,
            failed_attempts_24h: signals.history.failed_attempts_24h,
        }
    }

    /// IP reputation risk score
    fn ip_reputation_score(rep: &IpReputation) -> f64 {
        match rep {
            IpReputation::Low => 0.0,
            IpReputation::Medium => 15.0,
            IpReputation::High => 30.0,
        }
    }

    /// Geo velocity risk score
    fn geo_velocity_score(vel: &GeoVelocity) -> f64 {
        match vel {
            GeoVelocity::Normal => 0.0,
            GeoVelocity::Unlikely => 20.0,
            GeoVelocity::Impossible => 40.0,
        }
    }

    /// Device trust risk score
    fn device_trust_score(trust: &DeviceTrust) -> f64 {
        match trust {
            DeviceTrust::Known => 0.0,
            DeviceTrust::New => 20.0,
            DeviceTrust::Unknown => 25.0,
            DeviceTrust::Changed => 30.0,
            DeviceTrust::Compromised => 50.0,
        }
    }
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{BehaviorSignals, DeviceSignals, HistorySignals, NetworkSignals};

    #[test]
    fn test_low_risk_scoring() {
        let scorer = RiskScorer::new();

        let signals = RawSignals {
            network: NetworkSignals {
                ip_reputation: IpReputation::Low,
                geo_velocity: GeoVelocity::Normal,
                ..Default::default()
            },
            device: DeviceSignals {
                trust: DeviceTrust::Known,
                ..Default::default()
            },
            behavior: BehaviorSignals::default(),
            history: HistorySignals::default(),
        };

        let context = scorer.score(&signals, None);

        assert_eq!(context.overall, RiskLevel::Low);
    }

    #[test]
    fn test_high_risk_scoring() {
        let scorer = RiskScorer::new();

        let signals = RawSignals {
            network: NetworkSignals {
                ip_reputation: IpReputation::High,
                geo_velocity: GeoVelocity::Impossible,
                is_phishing_source: true,
                ..Default::default()
            },
            device: DeviceSignals {
                trust: DeviceTrust::Compromised,
                ..Default::default()
            },
            behavior: BehaviorSignals::default(),
            history: HistorySignals::default(),
        };

        let context = scorer.score(&signals, None);

        assert_eq!(context.overall, RiskLevel::High);
        assert!(context.phishing_risk);
    }
}
