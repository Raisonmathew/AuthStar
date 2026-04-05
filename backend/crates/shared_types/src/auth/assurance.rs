//! Authentication Assurance Level (AAL)
//!
//! NIST SP 800-63B compliant assurance levels that describe
//! the confidence in a user's claimed identity.

use serde::{Deserialize, Serialize};

/// Authentication Assurance Level per NIST SP 800-63B
///
/// Levels are ordinal - higher is stronger assurance.
/// AAL is computed from verified authentication factors, not asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AssuranceLevel {
    /// No authentication performed
    #[serde(rename = "AAL0")]
    AAL0 = 0,

    /// Single-factor authentication (password, weak OAuth)
    #[serde(rename = "AAL1")]
    AAL1 = 1,

    /// Multi-factor authentication (password + TOTP, software passkey)
    #[serde(rename = "AAL2")]
    AAL2 = 2,

    /// Hardware-backed, phishing-resistant authentication (hardware passkey, FIDO2)
    #[serde(rename = "AAL3")]
    AAL3 = 3,
}

impl Default for AssuranceLevel {
    fn default() -> Self {
        Self::AAL0
    }
}

impl AssuranceLevel {
    /// Parse from string (e.g., "AAL2" or "2")
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "AAL0" | "0" => Some(Self::AAL0),
            "AAL1" | "1" => Some(Self::AAL1),
            "AAL2" | "2" => Some(Self::AAL2),
            "AAL3" | "3" => Some(Self::AAL3),
            _ => None,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AAL0 => "AAL0",
            Self::AAL1 => "AAL1",
            Self::AAL2 => "AAL2",
            Self::AAL3 => "AAL3",
        }
    }

    /// Convert to numeric value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this level meets or exceeds required level
    pub fn satisfies(&self, required: AssuranceLevel) -> bool {
        *self >= required
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AAL0 => write!(f, "AAL0"),
            Self::AAL1 => write!(f, "AAL1"),
            Self::AAL2 => write!(f, "AAL2"),
            Self::AAL3 => write!(f, "AAL3"),
        }
    }
}

impl std::str::FromStr for AssuranceLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_loose(s).ok_or_else(|| format!("Invalid AAL level: {s}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aal_ordering() {
        assert!(AssuranceLevel::AAL0 < AssuranceLevel::AAL1);
        assert!(AssuranceLevel::AAL1 < AssuranceLevel::AAL2);
        assert!(AssuranceLevel::AAL2 < AssuranceLevel::AAL3);
    }

    #[test]
    fn test_aal_satisfies() {
        assert!(AssuranceLevel::AAL3.satisfies(AssuranceLevel::AAL2));
        assert!(AssuranceLevel::AAL2.satisfies(AssuranceLevel::AAL2));
        assert!(!AssuranceLevel::AAL1.satisfies(AssuranceLevel::AAL2));
    }

    #[test]
    fn test_aal_from_str() {
        assert_eq!(
            AssuranceLevel::from_str_loose("AAL2"),
            Some(AssuranceLevel::AAL2)
        );
        assert_eq!(
            AssuranceLevel::from_str_loose("2"),
            Some(AssuranceLevel::AAL2)
        );
        assert_eq!(
            AssuranceLevel::from_str_loose("aal3"),
            Some(AssuranceLevel::AAL3)
        );
        assert_eq!(AssuranceLevel::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_aal_serde() {
        let aal = AssuranceLevel::AAL2;
        let json = serde_json::to_string(&aal).unwrap();
        assert_eq!(json, "\"AAL2\"");

        let parsed: AssuranceLevel = serde_json::from_str("\"AAL3\"").unwrap();
        assert_eq!(parsed, AssuranceLevel::AAL3);
    }
}
