//! Type-safe EIAA action registry.
//!
//! Central registry of all EIAA capsule actions used in the system.
//! Prevents typos in string literals and provides a single source of truth
//! for route authorization actions.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Before (string literal, typo-prone):
//! .layer(EiaaAuthzLayer::new("billing:read", config))
//!
//! // After (type-safe, compile-time checked):
//! .layer(EiaaAuthzLayer::action(Action::BillingRead, config))
//! ```

/// All EIAA capsule actions used in route authorization.
///
/// Each variant maps to a string action that capsules evaluate.
/// Adding a new route action requires adding a variant here first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    // ─── Admin ────────────────────────────────────────────────────
    AdminManage,

    // ─── API Keys ─────────────────────────────────────────────────
    ApiKeysManage,

    // ─── Audit ────────────────────────────────────────────────────
    AuditRead,
    AuditVerify,

    // ─── Auth ─────────────────────────────────────────────────────
    AuthStepUp,

    // ─── Billing ──────────────────────────────────────────────────
    BillingRead,
    BillingWrite,

    // ─── Domains ──────────────────────────────────────────────────
    DomainsManage,

    // ─── EIAA ─────────────────────────────────────────────────────
    EiaaManage,

    // ─── MFA ──────────────────────────────────────────────────────
    MfaManage,

    // ─── Members ──────────────────────────────────────────────────
    MembersManage,

    // ─── Org ──────────────────────────────────────────────────────
    OrgConfig,
    OrgCreate,
    OrgRead,
    OrgSwitch,
    // ─── Passkeys ─────────────────────────────────────────────────
    PasskeysManage,

    // ─── Policies ─────────────────────────────────────────────────
    PoliciesManage,

    // ─── Roles ────────────────────────────────────────────────────
    RolesManage,

    // ─── Runtime ──────────────────────────────────────────────────
    RuntimeKeysRead,

    // ─── Session ──────────────────────────────────────────────────
    SessionLogout,
    SessionRefresh,

    // ─── User ─────────────────────────────────────────────────────
    UserManageFactors,
    UserManageProfile,
    UserRead,
}

impl Action {
    /// The string identifier passed to EIAA capsule evaluation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::AdminManage => "admin:manage",
            Action::ApiKeysManage => "apikeys:manage",
            Action::AuditRead => "audit:read",
            Action::AuditVerify => "audit:verify",
            Action::AuthStepUp => "auth:step_up",
            Action::BillingRead => "billing:read",
            Action::BillingWrite => "billing:write",
            Action::DomainsManage => "domains:manage",
            Action::EiaaManage => "eiaa:manage",
            Action::MfaManage => "mfa:manage",
            Action::MembersManage => "members:manage",
            Action::OrgConfig => "org:config",
            Action::OrgCreate => "org:create",
            Action::OrgRead => "org:read",
            Action::OrgSwitch => "org:switch",
            Action::PasskeysManage => "passkeys:manage",
            Action::PoliciesManage => "policies:manage",
            Action::RolesManage => "roles:manage",
            Action::RuntimeKeysRead => "runtime:keys:read",
            Action::SessionLogout => "session:logout",
            Action::SessionRefresh => "session:refresh",
            Action::UserManageFactors => "user:manage_factors",
            Action::UserManageProfile => "user:manage_profile",
            Action::UserRead => "user:read",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn action_strings_are_unique() {
        let variants = [
            Action::AdminManage,
            Action::ApiKeysManage,
            Action::AuditRead,
            Action::AuditVerify,
            Action::AuthStepUp,
            Action::BillingRead,
            Action::BillingWrite,
            Action::DomainsManage,
            Action::EiaaManage,
            Action::MfaManage,
            Action::MembersManage,
            Action::OrgConfig,
            Action::OrgCreate,
            Action::OrgRead,
            Action::PasskeysManage,
            Action::PoliciesManage,
            Action::RolesManage,
            Action::RuntimeKeysRead,
            Action::SessionLogout,
            Action::SessionRefresh,
            Action::UserManageFactors,
            Action::UserManageProfile,
            Action::UserRead,
        ];
        let strings: HashSet<&str> = variants.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            strings.len(),
            variants.len(),
            "All action strings must be unique"
        );
    }
}
