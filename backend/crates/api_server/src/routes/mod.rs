pub mod admin;
pub mod api_keys;
pub mod auth;
pub mod auth_flow;
pub mod billing;
pub mod decisions;
pub mod domains;
pub mod eiaa;
pub mod guards;
pub mod hosted;
pub mod invitations;
pub mod metrics;
pub mod mfa;
pub mod oauth2;
pub mod org_config;
pub mod passkeys;
pub mod policy_builder;
pub mod publishable_keys;
pub mod reexecution;
pub mod roles;
pub mod sdk_manifest;
pub mod signup;
pub mod sso;
pub mod user;

// Test seeding endpoint - only available in non-production
#[cfg(not(feature = "production"))]
pub mod test_seed;
