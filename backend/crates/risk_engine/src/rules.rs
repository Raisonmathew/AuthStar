//! Risk → Assurance Rules
//!
//! Maps risk context to assurance requirements and capability restrictions.

use shared_types::{
    AccountStability, AssuranceLevel, Capability, DeviceTrust, GeoVelocity, IpReputation,
    RiskConstraints, RiskContext, SessionRestriction,
};
use std::collections::HashSet;

/// Service that derives constraints from risk context
#[derive(Clone, Copy)]
pub struct RulesEngine;

impl RulesEngine {
    pub fn new() -> Self {
        Self
    }

    /// Derive assurance requirements and capability restrictions from risk
    pub fn derive_constraints(&self, risk: &RiskContext) -> RiskConstraints {
        let mut required_aal = AssuranceLevel::AAL1;
        let mut disallowed: HashSet<Capability> = HashSet::new();
        let mut require_pr = false;
        let mut restrictions = vec![];

        // === Device Trust Rules ===
        match risk.device_trust {
            DeviceTrust::Known => {
                // No additional requirements
            }
            DeviceTrust::New => {
                required_aal = required_aal.max(AssuranceLevel::AAL2);
            }
            DeviceTrust::Unknown | DeviceTrust::Changed => {
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

    /// Compute acceptable capabilities by intersecting sets and removing disallowed
    pub fn compute_acceptable_capabilities(
        &self,
        org_allowed: &HashSet<Capability>,
        user_enrolled: &HashSet<Capability>,
        risk_disallowed: &HashSet<Capability>,
        required_aal: AssuranceLevel,
    ) -> Vec<Capability> {
        org_allowed
            .iter()
            .filter(|c| user_enrolled.contains(c))
            .filter(|c| !risk_disallowed.contains(c))
            .filter(|c| c.max_assurance() >= required_aal)
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
