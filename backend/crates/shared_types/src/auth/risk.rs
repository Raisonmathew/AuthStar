//! Risk Context Types
//!
//! Normalized risk signals and constraints used by the EIAA Risk Engine.
//! These types are finite, serializable, and contain no PII.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::{AssuranceLevel, Capability};

/// Overall risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 70.0 {
            Self::High
        } else if score >= 30.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Device trust state
///
/// Derived from device binding history and signal stability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrust {
    /// Never seen before - no device ID present
    #[default]
    Unknown,
    /// Previously bound, stable signals over multiple logins
    Known,
    /// First successful bind to this subject
    New,
    /// Fingerprint changed materially (OS downgrade, platform change)
    Changed,
    /// High-confidence compromise detected
    Compromised,
}

impl DeviceTrust {
    /// Risk score contribution
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Known => 0.0,
            Self::New => 20.0,
            Self::Unknown => 25.0,
            Self::Changed => 30.0,
            Self::Compromised => 50.0,
        }
    }

    /// Minimum required AAL for this trust level
    pub fn min_required_aal(&self) -> AssuranceLevel {
        match self {
            Self::Known => AssuranceLevel::AAL1,
            Self::New | Self::Unknown | Self::Changed => AssuranceLevel::AAL2,
            Self::Compromised => AssuranceLevel::AAL3,
        }
    }
}

/// IP reputation classification
///
/// Derived from ASN type, reputation feeds, and abuse history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpReputation {
    /// Residential ISP, mobile carrier, clean IP
    #[default]
    Low,
    /// Hosting/VPS provider, proxy detected
    Medium,
    /// TOR exit, known bad IP, active abuse
    High,
}

impl IpReputation {
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Low => 0.0,
            Self::Medium => 15.0,
            Self::High => 30.0,
        }
    }

    pub fn min_required_aal(&self) -> AssuranceLevel {
        match self {
            Self::Low => AssuranceLevel::AAL1,
            Self::Medium => AssuranceLevel::AAL2,
            Self::High => AssuranceLevel::AAL3,
        }
    }
}

/// ASN (Autonomous System Number) type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AsnType {
    /// Residential ISP (Comcast, Vodafone, etc.)
    #[default]
    Residential,
    /// Hosting/VPS provider (AWS, OVH, DigitalOcean)
    Hosting,
    /// Anonymous infrastructure (TOR exit, known proxies)
    Anonymous,
}

/// Geographic velocity classification
///
/// Derived from comparing current location to historical baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GeoVelocity {
    /// Normal movement, within expected travel speed
    #[default]
    Normal,
    /// Suspicious but possible (multiple countries in short time)
    Unlikely,
    /// Physically impossible travel (credential theft indicator)
    Impossible,
}

impl GeoVelocity {
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Normal => 0.0,
            Self::Unlikely => 20.0,
            Self::Impossible => 40.0,
        }
    }

    pub fn min_required_aal(&self) -> AssuranceLevel {
        match self {
            Self::Normal => AssuranceLevel::AAL1,
            Self::Unlikely => AssuranceLevel::AAL2,
            Self::Impossible => AssuranceLevel::AAL3,
        }
    }
}

/// Account stability classification
///
/// Derived from recent security events (password reset, MFA changes, lockouts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStability {
    /// No recent security events
    #[default]
    Stable,
    /// Recent password reset, MFA change, or lockout
    Unstable,
}

impl AccountStability {
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Stable => 0.0,
            Self::Unstable => 25.0,
        }
    }
}

/// Complete risk context - normalized facts for capsule consumption
///
/// This struct contains NO PII. Raw IPs, fingerprints, and vendor scores
/// are never stored or passed to capsules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskContext {
    /// Overall classified risk level
    pub overall: RiskLevel,
    /// Device binding and trust state
    pub device_trust: DeviceTrust,
    /// IP reputation classification
    pub ip_reputation: IpReputation,
    /// Geographic velocity check result
    pub geo_velocity: GeoVelocity,
    /// Phishing risk detected (high-risk IP + other signals)
    pub phishing_risk: bool,
    /// Account stability based on recent security events
    pub account_stability: AccountStability,
    /// Behavior anomaly detected (login time, interaction speed)
    pub behavior_anomaly: bool,
    /// Failed auth attempts in last hour
    #[serde(default)]
    pub failed_attempts_1h: u32,
    /// Failed auth attempts in last 24 hours
    #[serde(default)]
    pub failed_attempts_24h: u32,
}

impl RiskContext {
    /// Compute total risk score from all signals
    pub fn total_score(&self) -> f64 {
        let mut score = 0.0;

        score += self.device_trust.risk_score();
        score += self.ip_reputation.risk_score();
        score += self.geo_velocity.risk_score();
        score += self.account_stability.risk_score();

        if self.phishing_risk {
            score += 30.0;
        }
        if self.behavior_anomaly {
            score += 15.0;
        }

        // Failed attempts contribution
        if self.failed_attempts_1h > 5 {
            score += 30.0;
        } else if self.failed_attempts_1h > 2 {
            score += 15.0;
        }

        if self.failed_attempts_24h > 20 {
            score += 20.0;
        }

        score
    }

    /// Classify overall risk from total score
    pub fn classify(&mut self) {
        self.overall = RiskLevel::from_score(self.total_score());
    }
}

/// Session restriction types for provisional access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRestriction {
    /// Limited access, requires enrollment to upgrade
    Provisional,
    /// Can only perform enrollment actions
    EnrollmentOnly,
    /// Read-only access to own data
    ReadOnly,
}

/// Risk-derived constraints for capsule and flow engine
///
/// These constraints are computed by the Risk Engine and fed into
/// context assembly before capsule execution.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskConstraints {
    /// Minimum required assurance level based on risk
    pub required_assurance: AssuranceLevel,
    /// Capabilities that are disallowed due to risk
    pub disallowed_capabilities: HashSet<Capability>,
    /// Whether phishing-resistant auth is mandatory
    pub require_phishing_resistant: bool,
    /// Session restrictions if auth succeeds
    pub session_restrictions: Vec<SessionRestriction>,
}

impl RiskConstraints {
    /// Create constraints from risk context
    pub fn from_risk(risk: &RiskContext) -> Self {
        let mut constraints = Self::default();
        let mut disallowed = HashSet::new();

        // Device trust rules
        match risk.device_trust {
            DeviceTrust::Unknown | DeviceTrust::Changed => {
                constraints.required_assurance =
                    constraints.required_assurance.max(AssuranceLevel::AAL2);
                disallowed.insert(Capability::Password);
            }
            DeviceTrust::Compromised => {
                constraints.required_assurance =
                    constraints.required_assurance.max(AssuranceLevel::AAL3);
                disallowed.insert(Capability::Password);
                disallowed.insert(Capability::SmsOtp);
                disallowed.insert(Capability::EmailOtp);
                constraints.require_phishing_resistant = true;
            }
            DeviceTrust::New => {
                constraints.required_assurance =
                    constraints.required_assurance.max(AssuranceLevel::AAL2);
            }
            DeviceTrust::Known => {}
        }

        // IP reputation rules
        match risk.ip_reputation {
            IpReputation::Medium => {
                constraints.required_assurance =
                    constraints.required_assurance.max(AssuranceLevel::AAL2);
            }
            IpReputation::High => {
                constraints.required_assurance =
                    constraints.required_assurance.max(AssuranceLevel::AAL3);
                disallowed.insert(Capability::Password);
                disallowed.insert(Capability::SmsOtp);
            }
            IpReputation::Low => {}
        }

        // Geo velocity rules
        if risk.geo_velocity == GeoVelocity::Impossible {
            constraints.required_assurance =
                constraints.required_assurance.max(AssuranceLevel::AAL3);
        }

        // Phishing risk
        if risk.phishing_risk {
            disallowed.insert(Capability::Password);
            disallowed.insert(Capability::EmailOtp);
            constraints.require_phishing_resistant = true;
        }

        // Account stability
        if risk.account_stability == AccountStability::Unstable {
            constraints.required_assurance =
                constraints.required_assurance.max(AssuranceLevel::AAL2);
            constraints
                .session_restrictions
                .push(SessionRestriction::Provisional);
        }

        // High failed attempts
        if risk.failed_attempts_1h > 5 {
            constraints.required_assurance =
                constraints.required_assurance.max(AssuranceLevel::AAL2);
            disallowed.insert(Capability::Password);
        }

        constraints.disallowed_capabilities = disallowed;
        constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(10.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(80.0), RiskLevel::High);
    }

    #[test]
    fn test_device_trust_scores() {
        assert_eq!(DeviceTrust::Known.risk_score(), 0.0);
        assert_eq!(DeviceTrust::Compromised.risk_score(), 50.0);
    }

    #[test]
    fn test_risk_context_total_score() {
        // Start with known (low-risk) device
        let mut ctx = RiskContext {
            device_trust: DeviceTrust::Known,
            ..Default::default()
        };
        assert_eq!(ctx.total_score(), 0.0);

        ctx.device_trust = DeviceTrust::New;
        ctx.ip_reputation = IpReputation::Medium;
        assert_eq!(ctx.total_score(), 35.0); // 20 + 15
    }

    #[test]
    fn test_risk_constraints_from_risk() {
        let risk = RiskContext {
            device_trust: DeviceTrust::Compromised,
            ip_reputation: IpReputation::High,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        assert_eq!(constraints.required_assurance, AssuranceLevel::AAL3);
        assert!(constraints
            .disallowed_capabilities
            .contains(&Capability::Password));
        assert!(constraints.require_phishing_resistant);
    }

    #[test]
    fn test_risk_constraints_provisional_session() {
        let risk = RiskContext {
            account_stability: AccountStability::Unstable,
            ..Default::default()
        };

        let constraints = RiskConstraints::from_risk(&risk);

        assert!(constraints
            .session_restrictions
            .contains(&SessionRestriction::Provisional));
    }

    #[test]
    fn test_serde_roundtrip() {
        let risk = RiskContext {
            overall: RiskLevel::Medium,
            device_trust: DeviceTrust::New,
            ip_reputation: IpReputation::Low,
            geo_velocity: GeoVelocity::Normal,
            phishing_risk: false,
            account_stability: AccountStability::Stable,
            behavior_anomaly: false,
            failed_attempts_1h: 2,
            failed_attempts_24h: 5,
        };

        let json = serde_json::to_string(&risk).unwrap();
        let parsed: RiskContext = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.device_trust, DeviceTrust::New);
        assert_eq!(parsed.failed_attempts_1h, 2);
    }
}
