//! Risk → Assurance Rules
//!
//! Maps risk context to assurance requirements and capability restrictions.

use shared_types::{
    AccountStability, AssuranceLevel, Capability, DeviceTrust, GeoVelocity, IpReputation,
    RiskConstraints, RiskContext, SessionRestriction,
};
use std::collections::HashSet;

/// Risk-score band thresholds.
///
/// Used by the EIAA enforcement layer to map a numeric `RiskContext::total_score()`
/// to a required `AssuranceLevel`. Admin sessions have a stricter mapping than
/// end-user sessions because they unlock higher-blast-radius capabilities.
///
/// User bands:
///   `score < 40`  → AAL1
///   `40 ≤ score < 70`  → AAL2
///   `70 ≤ score < 90`  → AAL3
///   `score ≥ 90`  → DENY
///
/// Admin bands (baseline AAL2 always — MFA mandatory regardless of score):
///   `score < 30`  → AAL2
///   `30 ≤ score < 60`  → AAL3
///   `score ≥ 60`  → DENY
pub mod bands {
    pub const USER_AAL2_THRESHOLD: f64 = 40.0;
    pub const USER_AAL3_THRESHOLD: f64 = 70.0;
    pub const USER_DENY_THRESHOLD: f64 = 90.0;

    pub const ADMIN_AAL3_THRESHOLD: f64 = 30.0;
    pub const ADMIN_DENY_THRESHOLD: f64 = 60.0;
}

/// Decision returned by [`derive_required_aal`] — either a target AAL or an
/// outright deny when the score is critically high.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AalRequirement {
    /// Allow the request once the session reaches this AAL.
    Required(AssuranceLevel),
    /// Risk score is critical — deny regardless of available factors.
    Deny,
}

/// Derive the required AAL from a numeric risk score, applying admin-stricter
/// bands when `is_admin = true`. Admin sessions always require AAL2 baseline.
pub fn derive_required_aal(score: f64, is_admin: bool) -> AalRequirement {
    if is_admin {
        if score >= bands::ADMIN_DENY_THRESHOLD {
            AalRequirement::Deny
        } else if score >= bands::ADMIN_AAL3_THRESHOLD {
            AalRequirement::Required(AssuranceLevel::AAL3)
        } else {
            AalRequirement::Required(AssuranceLevel::AAL2)
        }
    } else if score >= bands::USER_DENY_THRESHOLD {
        AalRequirement::Deny
    } else if score >= bands::USER_AAL3_THRESHOLD {
        AalRequirement::Required(AssuranceLevel::AAL3)
    } else if score >= bands::USER_AAL2_THRESHOLD {
        AalRequirement::Required(AssuranceLevel::AAL2)
    } else {
        AalRequirement::Required(AssuranceLevel::AAL1)
    }
}

/// Service that derives constraints from risk context
#[derive(Clone, Copy)]
pub struct RulesEngine;

impl RulesEngine {
    pub fn new() -> Self {
        Self
    }

    /// Derive assurance requirements and capability restrictions from risk.
    ///
    /// Equivalent to `derive_constraints_for(risk, false)` — kept for backwards
    /// compatibility with non-admin call sites.
    pub fn derive_constraints(&self, risk: &RiskContext) -> RiskConstraints {
        self.derive_constraints_for(risk, false)
    }

    /// Derive constraints with admin-awareness. Admin sessions have a baseline
    /// of AAL2 (MFA always required) and stricter risk-score bands.
    pub fn derive_constraints_for(&self, risk: &RiskContext, is_admin: bool) -> RiskConstraints {
        // Start from the score-based band, which already encodes the admin
        // baseline (≥AAL2 for admin sessions even at score 0).
        let mut required_aal = match derive_required_aal(risk.total_score(), is_admin) {
            AalRequirement::Required(aal) => aal,
            // Score-driven deny is enforced by the caller (eiaa middleware /
            // login handler) by inspecting the score directly. Here we still
            // return the strongest AAL so legacy callers fail closed.
            AalRequirement::Deny => AssuranceLevel::AAL3,
        };
        let mut disallowed: HashSet<Capability> = HashSet::new();
        let mut require_pr = false;
        let mut restrictions = vec![];

        // === Device Trust Rules ===
        match risk.device_trust {
            DeviceTrust::Known => {
                // No additional requirements
            }
            DeviceTrust::New | DeviceTrust::Unknown => {
                // Unknown is the normal state for pre-identification (no user yet,
                // so device trust cannot be evaluated). Treat the same as New:
                // step-up to AAL2 but allow password as first factor.
                required_aal = required_aal.max(AssuranceLevel::AAL2);
            }
            DeviceTrust::Changed => {
                required_aal = required_aal.max(AssuranceLevel::AAL2);
                disallowed.insert(Capability::Password);
            }
            DeviceTrust::Compromised => {
                required_aal = required_aal.max(AssuranceLevel::AAL3);
                disallowed.insert(Capability::Password);
                disallowed.insert(Capability::SmsOtp);
                disallowed.insert(Capability::EmailOtp);
                require_pr = true;
            }
        }

        // === IP Reputation Rules ===
        match risk.ip_reputation {
            IpReputation::Low => {}
            IpReputation::Medium => {
                required_aal = required_aal.max(AssuranceLevel::AAL2);
            }
            IpReputation::High => {
                required_aal = required_aal.max(AssuranceLevel::AAL3);
                disallowed.insert(Capability::Password);
                disallowed.insert(Capability::SmsOtp);
            }
        }

        // === Geo Velocity Rules ===
        match risk.geo_velocity {
            GeoVelocity::Normal => {}
            GeoVelocity::Unlikely => {
                required_aal = required_aal.max(AssuranceLevel::AAL2);
                restrictions.push(SessionRestriction::Provisional);
            }
            GeoVelocity::Impossible => {
                required_aal = required_aal.max(AssuranceLevel::AAL3);
                restrictions.push(SessionRestriction::Provisional);
            }
        }

        // === Phishing Risk ===
        if risk.phishing_risk {
            disallowed.insert(Capability::Password);
            disallowed.insert(Capability::EmailOtp);
            require_pr = true;
        }

        // === Account Stability ===
        if risk.account_stability == AccountStability::Unstable {
            required_aal = required_aal.max(AssuranceLevel::AAL2);
            restrictions.push(SessionRestriction::Provisional);
        }

        // === Failed Attempts ===
        if risk.failed_attempts_1h > 5 {
            required_aal = required_aal.max(AssuranceLevel::AAL2);
            disallowed.insert(Capability::Password);
        } else if risk.failed_attempts_1h > 2 {
            required_aal = required_aal.max(AssuranceLevel::AAL2);
        }

        // === Behavior Anomaly ===
        if risk.behavior_anomaly {
            required_aal = required_aal.max(AssuranceLevel::AAL2);
        }

        RiskConstraints {
            required_assurance: required_aal,
            disallowed_capabilities: disallowed,
            require_phishing_resistant: require_pr,
            session_restrictions: restrictions,
        }
    }

    /// Compute acceptable capabilities by intersecting sets and removing disallowed.
    /// Does NOT filter by required_aal — multi-factor flows use lower-assurance
    /// factors as building blocks to reach the target AAL cumulatively.
    pub fn compute_acceptable_capabilities(
        &self,
        org_allowed: &HashSet<Capability>,
        user_enrolled: &HashSet<Capability>,
        risk_disallowed: &HashSet<Capability>,
        _required_aal: AssuranceLevel,
    ) -> Vec<Capability> {
        org_allowed
            .iter()
            .filter(|c| user_enrolled.contains(c))
            .filter(|c| !risk_disallowed.contains(c))
            .cloned()
            .collect()
    }

    /// Compute acceptable capabilities that are phishing-resistant
    pub fn compute_phishing_resistant_capabilities(
        &self,
        acceptable: &[Capability],
    ) -> Vec<Capability> {
        acceptable
            .iter()
            .filter(|c| c.is_phishing_resistant())
            .cloned()
            .collect()
    }
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Action-specific assurance requirements
#[derive(Debug, Clone)]
pub struct ActionAssuranceRules;

impl ActionAssuranceRules {
    /// Minimum AAL required for enrollment actions
    pub fn enrollment_required_aal(action: &str) -> AssuranceLevel {
        match action {
            "add_passkey" | "add_totp" | "add_sms" => AssuranceLevel::AAL2,
            "remove_mfa" => AssuranceLevel::AAL3,
            "change_password" => AssuranceLevel::AAL2,
            "change_email" => AssuranceLevel::AAL3,
            _ => AssuranceLevel::AAL2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_risk_constraints() {
        let engine = RulesEngine::new();
        // Low risk = known device, low IP reputation, stable account
        let risk = RiskContext {
            device_trust: DeviceTrust::Known,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            account_stability: AccountStability::Stable,
            ..Default::default()
        };

        let constraints = engine.derive_constraints(&risk);

        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL1);
        assert!(constraints.disallowed_capabilities.is_empty());
        assert!(!constraints.require_phishing_resistant);
    }

    #[test]
    fn test_compromised_device_constraints() {
        let engine = RulesEngine::new();
        let risk = RiskContext {
            device_trust: DeviceTrust::Compromised,
            ..Default::default()
        };

        let constraints = engine.derive_constraints(&risk);

        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::SmsOtp));
        assert!(constraints.require_phishing_resistant);
    }

    #[test]
    fn test_high_ip_reputation_constraints() {
        let engine = RulesEngine::new();
        let risk = RiskContext {
            ip_reputation: IpReputation::High,
            ..Default::default()
        };

        let constraints = engine.derive_constraints(&risk);

        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
    }

    #[test]
    fn test_compute_acceptable_capabilities() {
        let engine = RulesEngine::new();

        let org_allowed: HashSet<_> = [
            Capability::Password,
            Capability::Totp,
            Capability::PasskeySynced,
        ]
        .into();
        let user_enrolled: HashSet<_> = [Capability::Password, Capability::Totp].into();
        let disallowed: HashSet<_> = [Capability::Password].into();

        let acceptable = engine.compute_acceptable_capabilities(
            &org_allowed,
            &user_enrolled,
            &disallowed,
            AssuranceLevel::AAL2,
        );

        assert_eq!(acceptable.len(), 1);
        assert!(acceptable.contains(&Capability::Totp));
    }
}
