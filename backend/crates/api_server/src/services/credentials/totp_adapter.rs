//! TOTP adapter (T1.6) — bridges `CredentialProvider` to the existing
//! `UserFactorService`, which already owns the `user_factors` table, the
//! TOTP secret encryption (`FactorEncryption`), and the step-up logic.
//!
//! ## Why an adapter
//!
//! `UserFactorService` predates the `CredentialProvider` trait and uses
//! `anyhow::Error`. This adapter:
//!
//! 1. Maps `anyhow::Error` → `shared_types::AppError`.
//! 2. Restricts the surface to TOTP (filters out other rows).
//! 3. Translates the domain types (`UserFactor`, status strings) into the
//!    framework types (`CredentialRecord`, `CredentialStatus`).
//!
//! No business logic lives here — this is pure translation glue.

use async_trait::async_trait;
use shared_types::{AppError, Result};
use std::sync::Arc;

use super::{
    store::{CredentialStore, NewCredential},
    CredentialProvider, CredentialRecord, CredentialStatus, EnrollmentResult, FactorKind,
    VerificationOutcome,
};
use crate::services::user_factor_service::{UserFactor, UserFactorService};

pub struct TotpCredentialProvider {
    inner: UserFactorService,
    /// T1.6 Phase 2.5 — optional dual-write into the unified `credentials`
    /// table. When `Some`, every successful TOTP enroll / verify / delete
    /// also updates `credentials` so the unified read path
    /// (`GET /api/v1/credentials`) sees the row. Failures here are logged
    /// but never break the legacy flow — the `user_factors` row remains
    /// the source of truth until Phase 4 swaps the read.
    store: Option<Arc<CredentialStore>>,
}

impl TotpCredentialProvider {
    pub fn new(inner: UserFactorService) -> Self {
        Self { inner, store: None }
    }

    /// Enable Phase 2.5 dual-write into the unified credentials table.
    pub fn with_store(mut self, store: Arc<CredentialStore>) -> Self {
        self.store = Some(store);
        self
    }
}

#[async_trait]
impl CredentialProvider for TotpCredentialProvider {
    fn kind(&self) -> FactorKind {
        FactorKind::Totp
    }

    async fn enroll(
        &self,
        user_id: &str,
        tenant_id: &str,
        _params: serde_json::Value,
    ) -> Result<EnrollmentResult> {
        let (factor_id, secret) = self
            .inner
            .initiate_enrollment(user_id, tenant_id, "totp")
            .await
            .map_err(map_anyhow)?;
        if let Some(store) = &self.store {
            // Best-effort dual-write. Use `legacy_factor_id = factor_id` and
            // mirror the same id as the unified credential id so the lookup
            // by id stays trivial (no separate mapping table needed).
            let res = store
                .insert(NewCredential {
                    id: &factor_id,
                    user_id,
                    tenant_id,
                    kind: FactorKind::Totp,
                    status: CredentialStatus::Pending,
                    label: None,
                    secret_material: None, // legacy table holds the encrypted secret
                    cipher_alg: None,
                    public_data: serde_json::json!({}),
                    legacy_factor_id: Some(&factor_id),
                    legacy_table: Some("user_factors"),
                })
                .await;
            if let Err(e) = res {
                tracing::warn!(
                    factor_id = %factor_id,
                    error = %e,
                    "totp dual-write to credentials table failed (legacy row is authoritative)"
                );
            }
        }
        Ok(EnrollmentResult {
            credential_id: factor_id,
            // The base32 TOTP secret is the only provisioning artefact the
            // client needs (to render the otpauth:// URI / QR code). The
            // wrapper key on `inner.encryption` keeps the *stored* form
            // encrypted; the plaintext is returned exactly once, here, and
            // never persisted in this layer.
            provisioning: serde_json::json!({ "secret": secret, "type": "totp" }),
        })
    }

    async fn verify_enrollment(
        &self,
        user_id: &str,
        tenant_id: &str,
        credential_id: &str,
        proof: &str,
    ) -> Result<VerificationOutcome> {
        let ok = self
            .inner
            .verify_enrollment(user_id, tenant_id, credential_id, proof)
            .await
            .map_err(map_anyhow)?;
        if ok {
            if let Some(store) = &self.store {
                if let Err(e) = store.mark_active(tenant_id, credential_id).await {
                    tracing::warn!(
                        credential_id = %credential_id,
                        error = %e,
                        "totp dual-write mark_active failed"
                    );
                }
            }
        }
        Ok(if ok {
            VerificationOutcome::Success
        } else {
            VerificationOutcome::Rejected
        })
    }

    async fn verify(
        &self,
        user_id: &str,
        tenant_id: &str,
        credential_id: &str,
        proof: &str,
    ) -> Result<VerificationOutcome> {
        // Step-up verification requires a session id; that's a UserFactorService
        // concern (it updates session AAL on success). The trait surface is
        // session-agnostic, so we expose the bare verification: no AAL update
        // is performed here. Callers needing session promotion call the
        // underlying service directly. Documented gap, intentional.
        let factor_type = self
            .inner
            .get_factor_type(user_id, tenant_id, credential_id)
            .await
            .map_err(map_anyhow)?;
        if factor_type != "totp" {
            return Ok(VerificationOutcome::NotEvaluable("wrong_kind"));
        }
        // Delegate raw TOTP comparison via the same path used by enrollment
        // verification (which also handles encrypted-secret unwrapping).
        let ok = self
            .inner
            .verify_enrollment(user_id, tenant_id, credential_id, proof)
            .await
            .map_err(map_anyhow)?;
        if ok {
            if let Some(store) = &self.store {
                if let Err(e) = store.touch_used(tenant_id, credential_id).await {
                    tracing::warn!(
                        credential_id = %credential_id,
                        error = %e,
                        "totp dual-write touch_used failed"
                    );
                }
            }
        }
        Ok(if ok {
            VerificationOutcome::Success
        } else {
            VerificationOutcome::Rejected
        })
    }

    async fn list(&self, user_id: &str, tenant_id: &str) -> Result<Vec<CredentialRecord>> {
        let raw = self
            .inner
            .list_factors(user_id, tenant_id)
            .await
            .map_err(map_anyhow)?;
        Ok(raw
            .into_iter()
            .filter(|f| f.factor_type == "totp")
            .map(to_record)
            .collect())
    }

    async fn delete(&self, user_id: &str, tenant_id: &str, credential_id: &str) -> Result<()> {
        self.inner
            .delete_factor(user_id, tenant_id, credential_id)
            .await
            .map_err(map_anyhow)?;
        if let Some(store) = &self.store {
            if let Err(e) = store.disable(tenant_id, credential_id).await {
                tracing::warn!(
                    credential_id = %credential_id,
                    error = %e,
                    "totp dual-write disable failed"
                );
            }
        }
        Ok(())
    }
}

fn to_record(f: UserFactor) -> CredentialRecord {
    CredentialRecord {
        id: f.id,
        user_id: f.user_id,
        tenant_id: f.tenant_id,
        kind: FactorKind::Totp,
        status: match f.status.as_str() {
            "active" => CredentialStatus::Active,
            "pending" => CredentialStatus::Pending,
            _ => CredentialStatus::Disabled,
        },
        created_at: f.created_at,
        enrolled_at: f.enrolled_at,
        last_used_at: f.last_used_at,
        label: None,
    }
}

fn map_anyhow(e: anyhow::Error) -> AppError {
    AppError::Internal(format!("totp credential: {e}"))
}
