//! Authentication Capabilities
//!
//! Capabilities represent the verification mechanisms that can raise
//! assurance to a given level. Each capability maps to a maximum AAL.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::AssuranceLevel;

/// Authentication capability - a verification mechanism that can prove identity
///
/// Each capability has a maximum assurance level it can provide.
/// Capabilities are NOT methods - they are security affordances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Password authentication (AAL1)
    Password,

    /// Email one-time password (AAL1 - easily phished)
    EmailOtp,

    /// SMS one-time password (AAL2 - weak but acceptable)
    SmsOtp,

    /// TOTP authenticator app (AAL2)
    Totp,

    /// Synced passkey / software WebAuthn (AAL2)
    PasskeySynced,

    /// Hardware-bound passkey / FIDO2 key (AAL3)
    PasskeyHardware,

    /// Google OAuth (AAL1-2, policy-defined)
    OAuthGoogle,

    /// GitHub OAuth (AAL1-2, policy-defined)
    OAuthGitHub,

    /// Microsoft OAuth (AAL1-2, policy-defined)
    OAuthMicrosoft,

    /// SAML SSO (AAL2-3, depends on IdP)
    SamlSso,

    /// Hardware security key (AAL3)
    HardwareKey,

    /// Backup/recovery codes (AAL2)
    BackupCodes,
}

impl Capability {
    /// Maximum assurance level this capability can provide
    pub fn max_assurance(&self) -> AssuranceLevel {
        match self {
            // Single-factor / easily phished
            Self::Password | Self::EmailOtp => AssuranceLevel::AAL1,

            // Multi-factor but not phishing-resistant
            Self::SmsOtp
            | Self::Totp
            | Self::PasskeySynced
            | Self::OAuthGoogle
            | Self::OAuthGitHub
            | Self::OAuthMicrosoft
            | Self::BackupCodes => AssuranceLevel::AAL2,

            // Hardware-backed, phishing-resistant
            Self::PasskeyHardware | Self::SamlSso | Self::HardwareKey => AssuranceLevel::AAL3,
        }
    }

    /// Is this capability phishing-resistant?
    pub fn is_phishing_resistant(&self) -> bool {
        matches!(
            self,
            Self::PasskeyHardware | Self::PasskeySynced | Self::HardwareKey
        )
    }

    /// Parse from OIDC amr (Authentication Methods References) claim
    pub fn from_amr(amr: &str) -> Option<Self> {
        match amr.to_lowercase().as_str() {
            "pwd" | "password" => Some(Self::Password),
            "otp" | "totp" => Some(Self::Totp),
            "sms" => Some(Self::SmsOtp),
            "email" => Some(Self::EmailOtp),
            "webauthn" | "fido" | "fido2" => Some(Self::PasskeyHardware),
            "hwk" | "hardware" => Some(Self::HardwareKey),
            "oauth" | "fed" | "federated" => Some(Self::OAuthGoogle), // Disambiguated by provider
            "mfa" => Some(Self::Totp),                                // Generic MFA, assume TOTP
            "backup" | "recovery" => Some(Self::BackupCodes),
            _ => None,
        }
    }

    /// Get display name for UI
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::EmailOtp => "Email Code",
            Self::SmsOtp => "SMS Code",
            Self::Totp => "Authenticator App",
            Self::PasskeySynced => "Passkey",
            Self::PasskeyHardware => "Security Key",
            Self::OAuthGoogle => "Google",
            Self::OAuthGitHub => "GitHub",
            Self::OAuthMicrosoft => "Microsoft",
            Self::SamlSso => "SSO",
            Self::HardwareKey => "Hardware Key",
            Self::BackupCodes => "Backup Code",
        }
    }

    /// Get string representation for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::EmailOtp => "email_otp",
            Self::SmsOtp => "sms_otp",
            Self::Totp => "totp",
            Self::PasskeySynced => "passkey_synced",
            Self::PasskeyHardware => "passkey_hardware",
            Self::OAuthGoogle => "oauth_google",
            Self::OAuthGitHub => "oauth_github",
            Self::OAuthMicrosoft => "oauth_microsoft",
            Self::SamlSso => "saml_sso",
            Self::HardwareKey => "hardware_key",
            Self::BackupCodes => "backup_codes",
        }
    }

    /// All capabilities as a set (for policy defaults)
    pub fn all() -> HashSet<Capability> {
        [
            Self::Password,
            Self::EmailOtp,
            Self::SmsOtp,
            Self::Totp,
            Self::PasskeySynced,
            Self::PasskeyHardware,
            Self::OAuthGoogle,
            Self::OAuthGitHub,
            Self::OAuthMicrosoft,
            Self::SamlSso,
            Self::HardwareKey,
            Self::BackupCodes,
        ]
        .into_iter()
        .collect()
    }

    /// Default capabilities for a new organization
    pub fn default_enabled() -> HashSet<Capability> {
        [Self::Password, Self::Totp, Self::PasskeySynced]
            .into_iter()
            .collect()
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_max_assurance() {
        assert_eq!(Capability::Password.max_assurance(), AssuranceLevel::AAL1);
        assert_eq!(Capability::Totp.max_assurance(), AssuranceLevel::AAL2);
        assert_eq!(
            Capability::PasskeyHardware.max_assurance(),
            AssuranceLevel::AAL3
        );
    }

    #[test]
    fn test_capability_phishing_resistant() {
        assert!(!Capability::Password.is_phishing_resistant());
        assert!(!Capability::Totp.is_phishing_resistant());
        assert!(Capability::PasskeyHardware.is_phishing_resistant());
        assert!(Capability::PasskeySynced.is_phishing_resistant());
    }

    #[test]
    fn test_capability_from_amr() {
        assert_eq!(Capability::from_amr("pwd"), Some(Capability::Password));
        assert_eq!(Capability::from_amr("totp"), Some(Capability::Totp));
        assert_eq!(
            Capability::from_amr("webauthn"),
            Some(Capability::PasskeyHardware)
        );
        assert_eq!(Capability::from_amr("unknown"), None);
    }

    #[test]
    fn test_capability_serde() {
        let cap = Capability::PasskeyHardware;
        let json = serde_json::to_string(&cap).unwrap();
        assert_eq!(json, "\"passkey_hardware\"");

        let parsed: Capability = serde_json::from_str("\"totp\"").unwrap();
        assert_eq!(parsed, Capability::Totp);
    }

    #[test]
    fn test_capability_all() {
        let all = Capability::all();
        assert!(all.contains(&Capability::Password));
        assert!(all.contains(&Capability::PasskeyHardware));
        assert_eq!(all.len(), 12);
    }
}
