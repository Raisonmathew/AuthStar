//! Assurance Service
//!
//! Computes effective assurance level from verified capabilities,
//! org/app policy, and risk constraints.

use std::collections::HashSet;
use shared_types::{AssuranceLevel, Capability, RiskConstraints};

/// Service for computing and validating authentication assurance levels
#[derive(Clone, Copy)]
pub struct AssuranceService;

impl AssuranceService {
    pub fn new() -> Self {
        Self
    }
    
    /// Compute achieved AAL from verified capabilities
    pub fn compute_achieved_aal(&self, verified: &[Capability]) -> AssuranceLevel {
        verified.iter()
            .map(|c| c.max_assurance())
            .max()
            .unwrap_or(AssuranceLevel::AAL0)
    }
    
    /// Compute required AAL by merging org baseline, app requirement, and risk constraints
    pub fn compute_required_aal(
        &self,
        org_baseline: AssuranceLevel,
        app_required: Option<AssuranceLevel>,
        risk_required: AssuranceLevel,
    ) -> AssuranceLevel {
        [
            org_baseline,
            app_required.unwrap_or(AssuranceLevel::AAL1),
            risk_required,
        ].into_iter().max().unwrap()
    }
    
    /// Check if achieved AAL meets required AAL
    pub fn meets_requirement(&self, achieved: AssuranceLevel, required: AssuranceLevel) -> bool {
        achieved >= required
    }
    
    /// Derive the "next step" capabilities that would satisfy the requirement
    pub fn suggest_next_capabilities(
        &self,
        required_aal: AssuranceLevel,
        already_verified: &[Capability],
        acceptable: &[Capability],
    ) -> Vec<Capability> {
        let verified_set: HashSet<_> = already_verified.iter().collect();
        
        // Find capabilities that:
        // 1. Are not yet verified
        // 2. Would raise AAL to at least required level
        acceptable.iter()
            .filter(|c| !verified_set.contains(c))
            .filter(|c| c.max_assurance() >= required_aal)
            .cloned()
            .collect()
    }
}

impl Default for AssuranceService {
    fn default() -> Self {
        Self::new()
    }
}

/// Capability service for computing acceptable authentication methods
#[derive(Clone, Copy)]
pub struct CapabilityService;

impl CapabilityService {
    pub fn new() -> Self {
        Self
    }
    
    /// Compute acceptable capabilities by intersecting:
    /// - Org enabled capabilities
    /// - User enrolled factors
    /// - Minus risk-disallowed capabilities
    /// - Filtered to those that can reach required AAL
    pub fn compute_acceptable(
        &self,
        org_enabled: &HashSet<Capability>,
        user_enrolled: &HashSet<Capability>,
        risk_constraints: &RiskConstraints,
        required_aal: AssuranceLevel,
    ) -> Vec<Capability> {
        org_enabled.iter()
            .filter(|c| user_enrolled.contains(c))
            .filter(|c| !risk_constraints.disallowed_capabilities.contains(c))
            .filter(|c| c.max_assurance() >= required_aal)
            .filter(|c| {
                // If phishing-resistant required, only include PR capabilities
                if risk_constraints.require_phishing_resistant {
                    c.is_phishing_resistant()
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }
    
    /// Get default org-enabled capabilities
    pub fn default_org_enabled() -> HashSet<Capability> {
        Capability::default_enabled()
    }
    
    /// Convert from stored JSON array to HashSet
    pub fn from_json_array(json: &serde_json::Value) -> HashSet<Capability> {
        json.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for CapabilityService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compute_achieved_aal() {
        let svc = AssuranceService::new();
        
        assert_eq!(svc.compute_achieved_aal(&[]), AssuranceLevel::AAL0);
        assert_eq!(svc.compute_achieved_aal(&[Capability::Password]), AssuranceLevel::AAL1);
        assert_eq!(svc.compute_achieved_aal(&[Capability::Password, Capability::Totp]), AssuranceLevel::AAL2);
        assert_eq!(svc.compute_achieved_aal(&[Capability::PasskeyHardware]), AssuranceLevel::AAL3);
    }
    
    #[test]
    fn test_compute_required_aal() {
        let svc = AssuranceService::new();
        
        // Take max of all requirements
        let result = svc.compute_required_aal(
            AssuranceLevel::AAL1,
            Some(AssuranceLevel::AAL2),
            AssuranceLevel::AAL1,
        );
        assert_eq!(result, AssuranceLevel::AAL2);
    }
    
    #[test]
    fn test_suggest_next_capabilities() {
        let svc = AssuranceService::new();
        
        let acceptable = vec![Capability::Password, Capability::Totp, Capability::PasskeySynced];
        let verified = vec![Capability::Password];
        
        let suggestions = svc.suggest_next_capabilities(
            AssuranceLevel::AAL2,
            &verified,
            &acceptable,
        );
        
        assert!(suggestions.contains(&Capability::Totp));
        assert!(suggestions.contains(&Capability::PasskeySynced));
        assert!(!suggestions.contains(&Capability::Password));
    }
    
    #[test]
    fn test_compute_acceptable_with_risk() {
        let svc = CapabilityService::new();
        
        let org_enabled: HashSet<_> = [Capability::Password, Capability::Totp, Capability::PasskeySynced].into();
        let user_enrolled: HashSet<_> = [Capability::Password, Capability::Totp].into();
        
        let mut constraints = RiskConstraints::default();
        constraints.disallowed_capabilities.insert(Capability::Password);
        
        let acceptable = svc.compute_acceptable(
            &org_enabled,
            &user_enrolled,
            &constraints,
            AssuranceLevel::AAL2,
        );
        
        assert_eq!(acceptable.len(), 1);
        assert!(acceptable.contains(&Capability::Totp));
    }
    
    #[test]
    fn test_phishing_resistant_filter() {
        let svc = CapabilityService::new();
        
        let org_enabled: HashSet<_> = [Capability::Password, Capability::Totp, Capability::PasskeySynced].into();
        let user_enrolled = org_enabled.clone();
        
        let constraints = RiskConstraints { require_phishing_resistant: true, ..Default::default() };
        
        let acceptable = svc.compute_acceptable(
            &org_enabled,
            &user_enrolled,
            &constraints,
            AssuranceLevel::AAL1,
        );
        
        // Only PasskeySynced is phishing-resistant
        assert!(acceptable.contains(&Capability::PasskeySynced));
        assert!(!acceptable.contains(&Capability::Password));
        assert!(!acceptable.contains(&Capability::Totp));
    }
}
