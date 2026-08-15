pub mod action_handlers;
pub mod agent_webhook_service;
pub mod api_key_service;
pub mod assurance_service;
pub mod attestation_decision_cache;
pub mod attestation_verifier;
pub mod audit_event_service;
pub mod audit_query_service;
pub mod audit_writer;
pub mod authenticators;
pub mod capsule_cache;
pub mod client_scope_service;
pub mod credential_lockout;
pub mod credentials;
pub mod custom_domain_service;
pub mod db_keystore;
pub mod eiaa_flow_service;
pub mod factor_encryption;
pub mod flow_state_service;
pub mod ldap_client;
pub mod nonce_store;
pub mod oauth_as_service;
pub mod password_policy;
pub mod policy_compiler;
pub mod publishable_key_service;
pub mod reexecution_service;
pub mod required_actions;
pub mod runtime_key_cache;
pub mod scim_service;
pub mod secret_provider;
pub mod secret_store;
pub mod sso_connection_service;
pub mod sso_encryption;
pub mod token_binding;
pub mod user_factor_service;

// Sprint D — Agent webhook events. Wired at call sites in eiaa_authz.rs when
// an agent principal triggers an Allow or Deny decision.
#[allow(unused_imports)]
pub use agent_webhook_service::{
    AgentEventKind, AgentWebhookPayload, AgentWebhookService,
};
pub use api_key_service::ApiKeyService;
pub use attestation_decision_cache::{AttestationDecisionCache, CacheDecisionParams};
pub use attestation_verifier::AttestationVerifier;
pub use audit_event_service::AuditEventService;
pub use audit_query_service::AuditQueryService;
pub use audit_writer::{
    AuditDecision, AuditRecord, AuditWriter, AuditWriterBuilder, StoreAttestationParams,
};
#[allow(unused_imports)]
pub use authenticators::{
    AuthFlow, AuthFlowEngine, AuthFlowOutcome, Authenticator, AuthenticatorRegistry,
    FactorEvidence, Requirement,
};
pub use capsule_cache::CapsuleCacheService;
// T2.8 — re-exports kept for the upcoming admin routes; suppress dead-code
// warnings until those routes consume them.
#[allow(unused_imports)]
pub use client_scope_service::{ClientScope, ClientScopeService, ScopeKind};
#[allow(unused_imports)]
pub use credential_lockout::{
    CredentialCounters, CredentialLockoutPolicy, CredentialLockoutService, FactorKind,
    UpdateCredentialLockoutPolicyRequest,
};
pub use custom_domain_service::{CustomDomainService, SslStatus, VerificationStatus};
pub use nonce_store::NonceStore;
pub use oauth_as_service::OAuthAsService;
pub use password_policy::{PasswordPolicy, PasswordPolicyService, UpdatePasswordPolicyRequest};
#[allow(unused_imports)]
pub use required_actions::{
    ActionStatus, RequiredAction, RequiredActionRecord, RequiredActionRegistry,
    RequiredActionService,
};
pub use runtime_key_cache::RuntimeKeyCache;
pub use scim_service::ScimService;
pub use secret_store::{build_secret_store, DatabaseSecretStore, SecretStore};
pub use sso_connection_service::SsoConnectionService;
// T2.3 — re-exports kept for the upcoming auth-extractor middleware.
#[allow(unused_imports)]
pub use token_binding::{
    BindingRequest, DpopBinding, MtlsBinding, TokenBinding, TokenBindingChain,
};
pub use user_factor_service::UserFactorService;
