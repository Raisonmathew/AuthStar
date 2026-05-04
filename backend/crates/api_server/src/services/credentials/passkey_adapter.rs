//! Passkey adapter (T1.6) — bridges `CredentialProvider` to the existing
//! [`identity_engine::services::PasskeyService`] (the `passkey_credentials`
//! table + WebAuthn-rs ceremony).
//!
//! ## Surface mapping
//!
//! Passkey enrollment is a two-leg WebAuthn ceremony that requires a Redis-
//! backed session and structured `RegisterPublicKeyCredential` payloads —
//! none of which fit the trait's flat `(user_id, params: JsonValue)` shape.
//! For that reason `enroll` and `verify_enrollment` here return `BadRequest`
//! pointing callers at the dedicated `/api/v1/passkeys/*` routes. The trait
//! still gives us a uniform surface for the *read* paths (`list`, `delete`)
//! which is what the unified credentials view needs.
//!
//! `verify` is intentionally not wired either: passkey verification is part
//! of an authentication flow, not a credential-id-based step-up, so it goes
//! through `PasskeyService::finish_authentication` from the auth route.

use async_trait::async_trait;
use identity_engine::services::PasskeyService;
use shared_types::{AppError, Result};

use super::{
    CredentialProvider, CredentialRecord, CredentialStatus, EnrollmentResult, FactorKind,
    VerificationOutcome,
};

pub struct PasskeyCredentialProvider {
    inner: PasskeyService,
}

impl PasskeyCredentialProvider {
    pub fn new(inner: PasskeyService) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl CredentialProvider for PasskeyCredentialProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::Passkey
    }

    async fn enroll(
        &self,
        _user_id: &str,
        _tenant_id: &str,
        _params: serde_json::Value,
    ) -> Result<EnrollmentResult> {
        Err(AppError::BadRequest(
            "passkey enrollment requires the WebAuthn ceremony at \
             POST /api/v1/passkeys/register/start"
                .into(),
        ))
    }

    async fn verify_enrollment(
        &self,
        _user_id: &str,
        _tenant_id: &str,
        _credential_id: &str,
        _proof: &str,
    ) -> Result<VerificationOutcome> {
        Err(AppError::BadRequest(
            "passkey enrollment verification happens via \
             POST /api/v1/passkeys/register/finish"
                .into(),
        ))
    }

    async fn verify(
        &self,
        _user_id: &str,
        _tenant_id: &str,
        _credential_id: &str,
        _proof: &str,
    ) -> Result<VerificationOutcome> {
        // Passkey verification is part of an auth flow, not a per-credential
        // step-up. Surfacing a stub here would be misleading.
        Ok(VerificationOutcome::NotEvaluable("use_webauthn_flow"))
    }

    async fn list(&self, user_id: &str, tenant_id: &str) -> Result<Vec<CredentialRecord>> {
        let infos = self.inner.list_passkeys(user_id, tenant_id).await?;
        Ok(infos
            .into_iter()
            .map(|p| CredentialRecord {
                id: p.id,
                user_id: user_id.to_string(),
                // Passkeys are tenant-scoped as of migration 055; the rows
                // returned above are already filtered by `tenant_id` so
                // stamping the caller's tenant here is a tautology, kept
                // explicit for shape parity with the other providers.
                tenant_id: tenant_id.to_string(),
                kind: FactorKind::Passkey,
                status: CredentialStatus::Active,
                created_at: p.created_at,
                enrolled_at: Some(p.created_at),
                last_used_at: p.last_used_at,
                label: Some(p.name),
            })
            .collect())
    }

    async fn delete(&self, user_id: &str, tenant_id: &str, credential_id: &str) -> Result<()> {
        self.inner
            .delete_passkey(user_id, tenant_id, credential_id)
            .await
    }
}
