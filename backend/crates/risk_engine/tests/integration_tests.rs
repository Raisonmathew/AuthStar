//! Integration Tests for EIAA Risk Engine
//!
//! These tests verify the complete flow from signal collection through
//! risk scoring, decay, and constraint derivation.

use shared_types::{
    AccountStability, AssuranceLevel, Capability, DeviceTrust, GeoVelocity, IpReputation,
    RiskConstraints, RiskContext, RiskLevel,
};

mod risk_scoring {
    use super::*;

    /// Test: Low-risk scenario produces minimal constraints
    #[test]
    fn test_low_risk_flow() {
        // Given: All low-risk signals
        let risk = RiskContext {
            overall: RiskLevel::Low,
            device_trust: DeviceTrust::Known,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            behavior_anomaly: false,
            failed_attempts_1h: 0,
            failed_attempts_24h: 0,
        };

        // When: Derive constraints
        let constraints = RiskConstraints::from_risk(&risk);

        // Then: Minimal restrictions (AAL0 is default, AAL1 is minimum practical)
        assert!(constraints.required_assurance <= AssuranceLevel::AAL1);
        assert!(constraints.disallowed_capabilities.is_empty());
        assert!(!constraints.require_phishing_resistant);
        assert!(constraints.session_restrictions.is_empty());
    }

    /// Test: High-risk scenario produces strong constraints
    #[test]
    fn test_high_risk_flow() {
        // Given: High-risk signals
        let risk = RiskContext {
            overall: RiskLevel::High,
            device_trust: DeviceTrust::Compromised,
            ip_reputation: IpReputation::High,
            geo_velocity: GeoVelocity::Impossible,
            phishing_risk: true,
            account_stability: AccountStability::Unstable,
            behavior_anomaly: true,
            failed_attempts_1h: 10,
            failed_attempts_24h: 50,
        };

        // When: Derive constraints
        let constraints = RiskConstraints::from_risk(&risk);

        // Then: Maximum restrictions
        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::SmsOtp));
        assert!(constraints.require_phishing_resistant);
    }

    /// Test: Medium-risk escalates to AAL2
    #[test]
    fn test_medium_risk_escalation() {
        let risk = RiskContext {
            device_trust: DeviceTrust::New,
            ip_reputation: IpReputation::Medium,
            geo_velocity: GeoVelocity::Unlikely,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // AAL2 required due to combination of new device + medium IP
        assert!(constraints.required_assurance >= AssuranceLevel::AAL2);
    }
}

mod capability_filtering {
    use super::*;

    /// Test: Password disabled on compromised device
    #[test]
    fn test_compromised_device_disables_password() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Compromised,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::SmsOtp));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::EmailOtp));
    }

    /// Test: Phishing risk requires phishing-resistant auth
    #[test]
    fn test_phishing_risk_requires_pr_auth() {
        let risk = RiskContext {
            phishing_risk: true,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        assert!(constraints.require_phishing_resistant);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::EmailOtp));
    }

    /// Test: High IP reputation blocks weak factors
    #[test]
    fn test_high_ip_reputation_restrictions() {
        let risk = RiskContext {
            ip_reputation: IpReputation::High,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::SmsOtp));
    }
}

mod aal_computation {
    use super::*;

    /// Test: AAL is max of verified capabilities
    #[test]
    fn test_aal_from_capabilities() {
        // Password only = AAL1
        assert_eq!(Capability::Password.max_assurance(), AssuranceLevel::AAL1);

        // Password + TOTP = AAL2
        assert_eq!(Capability::Totp.max_assurance(), AssuranceLevel::AAL2);

        // Hardware passkey = AAL3
        assert_eq!(
            Capability::PasskeyHardware.max_assurance(),
            AssuranceLevel::AAL3
        );
    }

    /// Test: Multiple capabilities take highest AAL
    #[test]
    fn test_multi_cap_takes_highest() {
        let caps = [Capability::Password, Capability::Totp, Capability::SmsOtp];

        let achieved = caps
            .iter()
            .map(|c| c.max_assurance())
            .max()
            .unwrap_or(AssuranceLevel::AAL0);

        assert_eq!(achieved, AssuranceLevel::AAL2);
    }

    /// Test: Phishing-resistant capabilities
    #[test]
    fn test_phishing_resistant_capabilities() {
        assert!(Capability::PasskeyHardware.is_phishing_resistant());
        assert!(Capability::PasskeySynced.is_phishing_resistant());
        assert!(!Capability::Password.is_phishing_resistant());
        assert!(!Capability::Totp.is_phishing_resistant());
    }
}

mod risk_level_classification {
    use super::*;

    /// Test: Score thresholds for risk levels
    #[test]
    fn test_risk_level_thresholds() {
        assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(29.9), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(30.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(69.9), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(100.0), RiskLevel::High);
    }

    /// Test: Total score computation
    #[test]
    fn test_total_score_computation() {
        let risk = RiskContext {
            device_trust: DeviceTrust::New,              // +20
            ip_reputation: IpReputation::Medium,         // +15
            geo_velocity: GeoVelocity::Normal,           // +0
            phishing_risk: false,                        // +0
            account_stability: AccountStability::Stable, // +0
            behavior_anomaly: false,                     // +0
            failed_attempts_1h: 0,                       // +0
            failed_attempts_24h: 0,                      // +0
            ..Default::default()
        };

        assert_eq!(risk.total_score(), 35.0);
    }
}

mod assurance_level_ordering {
    use super::*;

    /// Test: AAL ordering is correct
    #[test]
    fn test_aal_ordering() {
        assert!(AssuranceLevel::AAL0 < AssuranceLevel::AAL1);
        assert!(AssuranceLevel::AAL1 < AssuranceLevel::AAL2);
        assert!(AssuranceLevel::AAL2 < AssuranceLevel::AAL3);
    }

    /// Test: AAL satisfies relationship
    #[test]
    fn test_aal_satisfies() {
        assert!(AssuranceLevel::AAL3.satisfies(AssuranceLevel::AAL2));
        assert!(AssuranceLevel::AAL2.satisfies(AssuranceLevel::AAL2));
        assert!(!AssuranceLevel::AAL1.satisfies(AssuranceLevel::AAL2));
        assert!(!AssuranceLevel::AAL0.satisfies(AssuranceLevel::AAL1));
    }
}

mod device_trust_rules {
    use super::*;

    /// Test: Device trust → AAL mapping
    #[test]
    fn test_device_trust_to_aal() {
        assert_eq!(DeviceTrust::Known.min_required_aal(), AssuranceLevel::AAL1);
        assert_eq!(DeviceTrust::New.min_required_aal(), AssuranceLevel::AAL2);
        assert_eq!(
            DeviceTrust::Unknown.min_required_aal(),
            AssuranceLevel::AAL2
        );
        assert_eq!(
            DeviceTrust::Changed.min_required_aal(),
            AssuranceLevel::AAL2
        );
        assert_eq!(
            DeviceTrust::Compromised.min_required_aal(),
            AssuranceLevel::AAL3
        );
    }

    /// Test: Device trust risk scores
    #[test]
    fn test_device_trust_scores() {
        assert_eq!(DeviceTrust::Known.risk_score(), 0.0);
        assert_eq!(DeviceTrust::New.risk_score(), 20.0);
        assert_eq!(DeviceTrust::Unknown.risk_score(), 25.0);
        assert_eq!(DeviceTrust::Changed.risk_score(), 30.0);
        assert_eq!(DeviceTrust::Compromised.risk_score(), 50.0);
    }
}

mod capability_amr_mapping {
    use super::*;

    /// Test: AMR claim → Capability mapping
    #[test]
    fn test_amr_to_capability() {
        assert_eq!(Capability::from_amr("pwd"), Some(Capability::Password));
        assert_eq!(Capability::from_amr("password"), Some(Capability::Password));
        assert_eq!(Capability::from_amr("totp"), Some(Capability::Totp));
        assert_eq!(Capability::from_amr("otp"), Some(Capability::Totp));
        assert_eq!(Capability::from_amr("sms"), Some(Capability::SmsOtp));
        assert_eq!(Capability::from_amr("email"), Some(Capability::EmailOtp));
        assert_eq!(
            Capability::from_amr("webauthn"),
            Some(Capability::PasskeyHardware)
        );
        assert_eq!(
            Capability::from_amr("fido"),
            Some(Capability::PasskeyHardware)
        );
        assert_eq!(
            Capability::from_amr("fido2"),
            Some(Capability::PasskeyHardware)
        );
        assert_eq!(Capability::from_amr("hwk"), Some(Capability::HardwareKey));
        assert_eq!(Capability::from_amr("unknown_method"), None);
    }
}

mod serialization {
    use super::*;

    /// Test: RiskContext JSON serialization round-trip
    #[test]
    fn test_risk_context_serde() {
        let risk = RiskContext {
            overall: RiskLevel::Medium,
            device_trust: DeviceTrust::New,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            behavior_anomaly: true,
            failed_attempts_1h: 3,
            failed_attempts_24h: 10,
        };

        let json = serde_json::to_string(&risk).unwrap();
        let parsed: RiskContext = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.device_trust, DeviceTrust::New);
        assert_eq!(parsed.failed_attempts_1h, 3);
        assert!(parsed.behavior_anomaly);
    }

    /// Test: Capability JSON serialization
    #[test]
    fn test_capability_serde() {
        let cap = Capability::PasskeyHardware;
        let json = serde_json::to_string(&cap).unwrap();
        assert_eq!(json, "\"passkey_hardware\"");

        let parsed: Capability = serde_json::from_str("\"totp\"").unwrap();
        assert_eq!(parsed, Capability::Totp);
    }

    /// Test: AssuranceLevel JSON serialization
    #[test]
    fn test_assurance_level_serde() {
        let aal = AssuranceLevel::AAL3;
        let json = serde_json::to_string(&aal).unwrap();
        assert_eq!(json, "\"AAL3\"");

        let parsed: AssuranceLevel = serde_json::from_str("\"AAL2\"").unwrap();
        assert_eq!(parsed, AssuranceLevel::AAL2);
    }
}

mod scenario_tests {
    use super::*;

    /// Scenario: First-time login from residential IP, new device
    #[test]
    fn test_scenario_first_time_login() {
        let risk = RiskContext {
            device_trust: DeviceTrust::New,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // New device requires AAL2
        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL2);
        // No capabilities blocked
        assert!(constraints.disallowed_capabilities.is_empty());
    }

    /// Scenario: Known user from TOR exit node
    #[test]
    fn test_scenario_tor_exit_login() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Known,
            ip_reputation: IpReputation::High, // TOR = high risk
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // High IP reputation requires AAL3
        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        // Password and SMS blocked
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::SmsOtp));
    }

    /// Scenario: Impossible geo velocity (credential theft indicator)
    #[test]
    fn test_scenario_impossible_travel() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Known,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Impossible,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // Impossible travel requires AAL3
        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
    }

    /// Scenario: Recent password reset + lockout
    #[test]
    fn test_scenario_unstable_account() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Known,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Unstable,
            failed_attempts_1h: 6, // > 5 triggers password block
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // Unstable account + failed attempts = AAL2 + password blocked
        assert!(constraints.required_assurance >= AssuranceLevel::AAL2);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
    }

    /// Scenario: Phishing attack detected
    #[test]
    fn test_scenario_phishing_attack() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Unknown,
            ip_reputation: IpReputation::High,
            phishing_risk: true,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        // Phishing requires phishing-resistant auth
        assert!(constraints.require_phishing_resistant);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::EmailOtp));
        // Only passkeys should work
    }
}
