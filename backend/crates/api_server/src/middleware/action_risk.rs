//! Action Risk Classification for Attestation Frequency Matrix
//!
//! Classifies actions by risk level to determine attestation caching strategy:
//! - High: Every request (no caching)
//! - Medium: Short cache (5-30 seconds)
//! - Low: Long cache (30-120 seconds)
//! - Internal: Per-batch (60 seconds)

use serde::{Deserialize, Serialize};

/// Risk classification for actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionRiskLevel {
    /// High-risk: Unlock door, transfer money, delete org
    /// Attestation: Every request (no caching)
    High,
    /// Medium-risk: Change device config, write data
    /// Attestation: Per request OR short cache (5-30s)
    Medium,
    /// Low-risk: Read dashboards, list devices
    /// Attestation: Cached decision (30-120s)
    Low,
    /// Internal system call: Service-to-service
    /// Attestation: Per call or per batch (60s)
    Internal,
}

impl ActionRiskLevel {
    /// Classify an action string into a risk level
    pub fn from_action(action: &str) -> Self {
        // High-risk patterns: destructive, financial, security-critical
        let high_risk_patterns = [
            "delete", "remove", "destroy",  // Destructive
            "transfer", "payment", "refund", // Financial
            "unlock", "reset_password", "revoke", // Security
            "org:delete", "user:delete", "billing:transfer",
            "device:unlock", "passkey:delete", "mfa:disable",
        ];

        // Medium-risk patterns: mutations, configuration changes
        let medium_risk_patterns = [
            "update", "modify", "change", "config",
            "write", "create", "invite", "enable",
            "device:config", "user:update", "org:update",
            "policy:update", "role:assign",
        ];

        // Internal patterns: service-to-service
        let internal_patterns = [
            "internal:", "service:", "system:",
            "batch:", "sync:", "background:",
        ];

        let action_lower = action.to_lowercase();

        // Check high-risk first
        for pattern in &high_risk_patterns {
            if action_lower.contains(pattern) {
                return Self::High;
            }
        }

        // Check internal
        for pattern in &internal_patterns {
            if action_lower.starts_with(pattern) {
                return Self::Internal;
            }
        }

        // Check medium-risk
        for pattern in &medium_risk_patterns {
            if action_lower.contains(pattern) {
                return Self::Medium;
            }
        }

        // Default to Low for reads and lists
        Self::Low
    }

    /// Get cache TTL in seconds for this risk level
    pub fn cache_ttl_seconds(&self) -> u64 {
        match self {
            Self::High => 0,      // No caching, every request
            Self::Medium => 15,   // 15 seconds (middle of 5-30 range)
            Self::Low => 60,      // 60 seconds (middle of 30-120 range)
            Self::Internal => 60, // Per-batch, 60 seconds
        }
    }

    /// Check if caching is allowed for this risk level
    pub fn allows_caching(&self) -> bool {
        !matches!(self, Self::High)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_actions() {
        assert_eq!(ActionRiskLevel::from_action("org:delete"), ActionRiskLevel::High);
        assert_eq!(ActionRiskLevel::from_action("billing:transfer"), ActionRiskLevel::High);
        assert_eq!(ActionRiskLevel::from_action("device:unlock"), ActionRiskLevel::High);
        assert_eq!(ActionRiskLevel::from_action("user:delete"), ActionRiskLevel::High);
        assert_eq!(ActionRiskLevel::from_action("reset_password"), ActionRiskLevel::High);
    }

    #[test]
    fn test_medium_risk_actions() {
        assert_eq!(ActionRiskLevel::from_action("device:config"), ActionRiskLevel::Medium);
        assert_eq!(ActionRiskLevel::from_action("user:update"), ActionRiskLevel::Medium);
        assert_eq!(ActionRiskLevel::from_action("org:invite"), ActionRiskLevel::Medium);
        assert_eq!(ActionRiskLevel::from_action("policy:create"), ActionRiskLevel::Medium);
    }

    #[test]
    fn test_low_risk_actions() {
        assert_eq!(ActionRiskLevel::from_action("dashboard:read"), ActionRiskLevel::Low);
        assert_eq!(ActionRiskLevel::from_action("device:list"), ActionRiskLevel::Low);
        assert_eq!(ActionRiskLevel::from_action("user:get"), ActionRiskLevel::Low);
        assert_eq!(ActionRiskLevel::from_action("org:list"), ActionRiskLevel::Low);
    }

    #[test]
    fn test_internal_actions() {
        assert_eq!(ActionRiskLevel::from_action("internal:sync_users"), ActionRiskLevel::Internal);
        assert_eq!(ActionRiskLevel::from_action("service:health_check"), ActionRiskLevel::Internal);
        assert_eq!(ActionRiskLevel::from_action("batch:process_queue"), ActionRiskLevel::Internal);
    }

    #[test]
    fn test_cache_ttl() {
        assert_eq!(ActionRiskLevel::High.cache_ttl_seconds(), 0);
        assert_eq!(ActionRiskLevel::Medium.cache_ttl_seconds(), 15);
        assert_eq!(ActionRiskLevel::Low.cache_ttl_seconds(), 60);
        assert_eq!(ActionRiskLevel::Internal.cache_ttl_seconds(), 60);
    }

    #[test]
    fn test_allows_caching() {
        assert!(!ActionRiskLevel::High.allows_caching());
        assert!(ActionRiskLevel::Medium.allows_caching());
        assert!(ActionRiskLevel::Low.allows_caching());
        assert!(ActionRiskLevel::Internal.allows_caching());
    }
}
