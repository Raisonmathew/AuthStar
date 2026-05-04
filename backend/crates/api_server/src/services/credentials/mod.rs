//! Credential Provider Framework (T1.6 — additive, EIAA-strict)
//!
//! ## Purpose
//!
//! Unifies the surface area for *any* credential kind (TOTP, passkey, password,
//! backup codes, future hardware tokens, etc.) behind a single trait, so the
//! authentication-flow engine and policy capsules can reason about credentials
//! uniformly without knowing which concrete table or service owns the data.
//!
//! ## Why additive (not a data migration)
//!
//! The codebase already has two persistence services (`UserFactorService` →
//! `user_factors`, `MfaService` → `mfa_factors`) with established UI / API /
//! audit dependencies. A real table merger is a multi-release operational
//! exercise. This framework instead introduces an **Adapter** layer:
//! `CredentialProvider` impls delegate to the existing services. New code
//! targets the trait; no existing flow changes.
//!
//! ## Design pattern stack
//!
//! - **Strategy** — one impl per `FactorKind`, one trait method per lifecycle stage.
//! - **Adapter** — each impl wraps an existing service (e.g. `UserFactorService`).
//! - **Registry** — `CredentialRegistry` keys impls by `FactorKind`.
//! - **Repository** — providers expose CRUD-style methods over their own store.
//!
//! ## EIAA fit
//!
//! Providers attest *what* the user proved (returning `FactorKind`) — they
//! never decide *whether* that proof suffices for the requested action. That
//! decision still flows through `EiaaAuthzLayer` → capsule. Invariant preserved.

// T1.6 scaffold: the trait + registry expose the FULL CRUD surface that
// Phase 3 ("legacy read switch") and Phase 4 ("drop legacy tables") will
// route real traffic to. Today only `list` (and via `list_all`) has a
// production caller — `GET /api/v1/credentials`. Keeping the rest of the
// trait and `CredentialStore` warning-free without deleting them is
// intentional: the next phases plug in here without re-litigating the
// design. Remove this allow once `enroll` / `verify` / `delete` have live
// callers (Phase 3).
#![allow(dead_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use std::collections::HashMap;
use std::sync::Arc;

pub mod passkey_adapter;
pub mod store;
pub mod totp_adapter;

pub use passkey_adapter::PasskeyCredentialProvider;
pub use store::CredentialStore;
pub use totp_adapter::TotpCredentialProvider;

/// Stable, closed enum of credential kinds.
///
/// Adding a new kind is a deliberate compile-time event that forces every
/// `match` site (and the registry) to acknowledge it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// WebAuthn / FIDO2 passkey.
    Passkey,
    /// SMS-delivered one-time code.
    SmsOtp,
    /// Email-delivered one-time code.
    EmailOtp,
    /// Recovery / backup codes.
    BackupCodes,
    /// Knowledge-based: password. Listed for completeness; rarely registered
    /// through this surface (handled by `auth_core::password`).
    Password,
}

impl FactorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Passkey => "passkey",
            Self::SmsOtp => "sms_otp",
            Self::EmailOtp => "email_otp",
            Self::BackupCodes => "backup_codes",
            Self::Password => "password",
        }
    }
}

/// Public-safe view of a credential. NEVER carries the secret material;
/// secrets stay encrypted at rest in the underlying store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub kind: FactorKind,
    pub status: CredentialStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Free-form label for the credential ("iPhone passkey", "YubiKey 5C").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// Enrollment started, awaiting verification of the first proof-of-possession.
    Pending,
    /// Active and usable for verification.
    Active,
    /// Disabled by the user or by policy. Kept for audit; not usable.
    Disabled,
}

/// Result of starting an enrollment. The provider returns whatever provisioning
/// material the client needs to complete the second leg (e.g. TOTP secret to
/// render a QR code, WebAuthn `PublicKeyCredentialCreationOptions`).
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentResult {
    /// Pending credential id — the client passes this back to `verify_enrollment`.
    pub credential_id: String,
    /// Provisioning payload (kind-specific). Treated as opaque by the caller.
    pub provisioning: serde_json::Value,
}

/// Outcome of a verification attempt. Distinguishes "wrong proof" from
/// "couldn't be evaluated" so the auth-flow engine can pick the right next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// Proof matched. The provider has updated `last_used_at` etc.
    Success,
    /// Proof was syntactically valid but did not match the stored credential.
    Rejected,
    /// Credential is in a state that forbids verification (Pending, Disabled,
    /// expired). Includes a stable reason code for telemetry.
    NotEvaluable(&'static str),
}

/// One impl per `FactorKind`. Methods are intentionally narrow — providers
/// own the storage details, callers own the orchestration (EIAA flow engine).
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    fn kind(&self) -> FactorKind;

    /// Begin an enrollment. Returns the (pending) credential id and any
    /// kind-specific provisioning payload the client needs.
    async fn enroll(
        &self,
        user_id: &str,
        tenant_id: &str,
        params: serde_json::Value,
    ) -> Result<EnrollmentResult>;

    /// Verify the *first* proof-of-possession after `enroll`. On success the
    /// credential transitions Pending → Active.
    async fn verify_enrollment(
        &self,
        user_id: &str,
        tenant_id: &str,
        credential_id: &str,
        proof: &str,
    ) -> Result<VerificationOutcome>;

    /// Verify a *subsequent* proof of an already-active credential
    /// (e.g. step-up auth, MFA challenge during sign-in).
    async fn verify(
        &self,
        user_id: &str,
        tenant_id: &str,
        credential_id: &str,
        proof: &str,
    ) -> Result<VerificationOutcome>;

    /// List the user's credentials of this kind.
    async fn list(&self, user_id: &str, tenant_id: &str) -> Result<Vec<CredentialRecord>>;

    /// Remove a credential. Implementations may soft-delete or hard-delete;
    /// audit happens at the calling layer.
    async fn delete(&self, user_id: &str, tenant_id: &str, credential_id: &str) -> Result<()>;
}

/// Registry of providers, keyed by `FactorKind`. Built once at startup.
#[derive(Default, Clone)]
pub struct CredentialRegistry {
    providers: Arc<HashMap<FactorKind, Arc<dyn CredentialProvider>>>,
}

impl CredentialRegistry {
    /// Build a registry from a list of providers. Panics if two providers
    /// claim the same `FactorKind` — a startup misconfiguration that must
    /// not be allowed to enter steady state.
    pub fn new(providers: Vec<Arc<dyn CredentialProvider>>) -> Self {
        let mut map: HashMap<FactorKind, Arc<dyn CredentialProvider>> = HashMap::new();
        for p in providers {
            let k = p.kind();
            if map.insert(k, p).is_some() {
                panic!(
                    "CredentialRegistry: duplicate provider for kind '{}'",
                    k.as_str()
                );
            }
        }
        Self {
            providers: Arc::new(map),
        }
    }

    /// Look up a provider by kind. Returns `BadRequest` for unregistered kinds
    /// so callers can map to a uniform 400 without leaking config state.
    pub fn get(&self, kind: FactorKind) -> Result<Arc<dyn CredentialProvider>> {
        self.providers.get(&kind).cloned().ok_or_else(|| {
            AppError::BadRequest(format!(
                "no credential provider registered for kind '{}'",
                kind.as_str()
            ))
        })
    }

    /// Aggregate every credential the user has across every registered kind.
    /// Useful for the security-settings page and for capsules that want to
    /// see "what does this user have to prove with".
    pub async fn list_all(&self, user_id: &str, tenant_id: &str) -> Result<Vec<CredentialRecord>> {
        let mut out = Vec::new();
        for provider in self.providers.values() {
            let mut chunk = provider.list(user_id, tenant_id).await?;
            out.append(&mut chunk);
        }
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubProvider(FactorKind);

    #[async_trait]
    impl CredentialProvider for StubProvider {
        fn kind(&self) -> FactorKind {
            self.0
        }
        async fn enroll(&self, _: &str, _: &str, _: serde_json::Value) -> Result<EnrollmentResult> {
            Ok(EnrollmentResult {
                credential_id: format!("stub_{}", self.0.as_str()),
                provisioning: serde_json::Value::Null,
            })
        }
        async fn verify_enrollment(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<VerificationOutcome> {
            Ok(VerificationOutcome::Success)
        }
        async fn verify(&self, _: &str, _: &str, _: &str, _: &str) -> Result<VerificationOutcome> {
            Ok(VerificationOutcome::Success)
        }
        async fn list(&self, _: &str, _: &str) -> Result<Vec<CredentialRecord>> {
            Ok(vec![])
        }
        async fn delete(&self, _: &str, _: &str, _: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registry_lookup_and_aggregation() {
        let reg = CredentialRegistry::new(vec![
            Arc::new(StubProvider(FactorKind::Totp)),
            Arc::new(StubProvider(FactorKind::Passkey)),
        ]);
        assert_eq!(reg.len(), 2);
        assert!(reg.get(FactorKind::Totp).is_ok());
        assert!(reg.get(FactorKind::Passkey).is_ok());
        let Err(err) = reg.get(FactorKind::SmsOtp) else {
            panic!("expected Err for unregistered FactorKind::SmsOtp");
        };
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    #[should_panic(expected = "duplicate provider")]
    fn duplicate_registration_panics() {
        let _ = CredentialRegistry::new(vec![
            Arc::new(StubProvider(FactorKind::Totp)),
            Arc::new(StubProvider(FactorKind::Totp)),
        ]);
    }

    #[test]
    fn factor_kind_strings_are_stable() {
        // Cross-language interop relies on these.
        assert_eq!(FactorKind::Totp.as_str(), "totp");
        assert_eq!(FactorKind::Passkey.as_str(), "passkey");
        assert_eq!(FactorKind::SmsOtp.as_str(), "sms_otp");
        assert_eq!(FactorKind::EmailOtp.as_str(), "email_otp");
        assert_eq!(FactorKind::BackupCodes.as_str(), "backup_codes");
        assert_eq!(FactorKind::Password.as_str(), "password");
    }
}
