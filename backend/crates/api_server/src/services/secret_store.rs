//! Vault SPI — Pluggable secret store for OAuth2 client secrets.
//!
//! Keycloak parity item #19: tenants can bring their own key management
//! (database hashing, AWS KMS envelope encryption, or HashiCorp Vault KV).
//!
//! # Trait contract
//!
//! - `store_secret(client_id, plaintext)` — called once when a new client secret
//!   is generated. Returns the reference value persisted in `client_secret_hash`.
//!   For the DB backend this is `SHA-256(plaintext)`. For KMS/Vault it is an
//!   opaque reference the backend knows how to resolve.
//!
//! - `verify_secret(client_id, presented, stored_ref)` — called on every token
//!   endpoint request. Must be constant-time for the DB backend.
//!
//! - `delete_secret(client_id)` — called when a client is deleted or its secret
//!   rotated. The DB backend is a no-op (the column is overwritten / row deleted).

use async_trait::async_trait;
use hex;
use sha2::{Digest, Sha256};
use shared_types::{AppError, Result};
use subtle::ConstantTimeEq;
use tracing::{info, warn}; // ─────────────────────────────────────────────────────────────────────────────
                           // Trait
                           // ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Persist a client secret and return the reference to store in the DB column.
    async fn store_secret(&self, client_id: &str, plaintext: &str) -> Result<String>;

    /// Verify a presented secret against the stored reference.
    async fn verify_secret(
        &self,
        client_id: &str,
        presented: &str,
        stored_ref: &str,
    ) -> Result<bool>;

    /// Remove a secret from the external backend on client deletion/rotation.
    /// The DB backend is a no-op — the column is overwritten or the row deleted.
    async fn delete_secret(&self, client_id: &str) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helper
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend 1 — DatabaseSecretStore (current behaviour, always available)
// ─────────────────────────────────────────────────────────────────────────────

/// Stores `SHA-256(plaintext)` as the DB column value.
/// Verification is constant-time to resist timing attacks.
/// No external dependencies required.
#[derive(Clone, Default)]
pub struct DatabaseSecretStore;

#[async_trait]
impl SecretStore for DatabaseSecretStore {
    async fn store_secret(&self, _client_id: &str, plaintext: &str) -> Result<String> {
        Ok(sha256_hex(plaintext))
    }

    async fn verify_secret(
        &self,
        _client_id: &str,
        presented: &str,
        stored_ref: &str,
    ) -> Result<bool> {
        let presented_hash = sha256_hex(presented);
        let equal: bool = presented_hash
            .as_bytes()
            .ct_eq(stored_ref.as_bytes())
            .into();
        Ok(equal)
    }

    async fn delete_secret(&self, _client_id: &str) -> Result<()> {
        // The DB column is overwritten on rotation or dropped on row deletion.
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend 2 — AwsKmsSecretStore (stub — activate by wiring real KMS calls)
// ─────────────────────────────────────────────────────────────────────────────

/// Envelope-encryption backend using AWS KMS.
///
/// # Stub behaviour
/// The stub stores `kms:{sha256}` as the reference and verifies by stripping
/// the `kms:` prefix.  A production implementation would:
/// 1. `store_secret` — call `GenerateDataKey`, encrypt the plaintext with the
///    data key, base64-encode the ciphertext blob, return `kms:{blob}`.
/// 2. `verify_secret` — call `Decrypt` on the stored blob, compare with
///    presented secret (constant-time).
///
/// # Activation
/// Set `SECRET_STORE_BACKEND=aws_kms` and provide `AWS_KMS_KEY_ID` plus
/// standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
/// `AWS_REGION`).
#[derive(Clone)]
pub struct AwsKmsSecretStore {
    pub key_id: String,
    pub region: String,
}

impl AwsKmsSecretStore {
    pub fn from_env() -> Option<Self> {
        let key_id = std::env::var("AWS_KMS_KEY_ID").ok()?;
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into());
        Some(Self { key_id, region })
    }
}

#[async_trait]
impl SecretStore for AwsKmsSecretStore {
    async fn store_secret(&self, client_id: &str, plaintext: &str) -> Result<String> {
        // TODO: replace with real aws-sdk-kms GenerateDataKey + Encrypt call.
        warn!(
            client_id,
            key_id = %self.key_id,
            region = %self.region,
            "AwsKmsSecretStore is in stub mode — using SHA-256 fallback. \
             Implement real envelope encryption for production use."
        );
        Ok(format!("kms:{}", sha256_hex(plaintext)))
    }

    async fn verify_secret(
        &self,
        client_id: &str,
        presented: &str,
        stored_ref: &str,
    ) -> Result<bool> {
        // TODO: replace with real KMS Decrypt call.
        warn!(
            client_id,
            "AwsKmsSecretStore.verify_secret is in stub mode — using SHA-256 fallback."
        );
        let hash = format!("kms:{}", sha256_hex(presented));
        let equal: bool = hash.as_bytes().ct_eq(stored_ref.as_bytes()).into();
        Ok(equal)
    }

    async fn delete_secret(&self, client_id: &str) -> Result<()> {
        // TODO: schedule KMS key deletion / alias removal.
        info!(client_id, "AwsKmsSecretStore.delete_secret (stub — no-op)");
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend 3 — HashiCorpVaultSecretStore (stub — activate by wiring Vault HTTP)
// ─────────────────────────────────────────────────────────────────────────────

/// HashiCorp Vault KV v2 backend.
///
/// # Stub behaviour
/// The stub stores `vault:secret/data/clients/{client_id}` as the reference and
/// verifies by re-hashing.  A production implementation would:
/// 1. `store_secret` — PUT to `{vault_addr}/v1/{mount}/data/clients/{client_id}`
///    with `{ "data": { "secret": plaintext } }`.
/// 2. `verify_secret` — GET the same path, extract `data.secret`, compare.
/// 3. `delete_secret` — DELETE (or soft-delete via metadata endpoint).
///
/// # Activation
/// Set `SECRET_STORE_BACKEND=vault`, `VAULT_ADDR`, and `VAULT_TOKEN`
/// (or configure AppRole/Kubernetes auth for production).
#[derive(Clone)]
pub struct HashiCorpVaultSecretStore {
    pub vault_addr: String,
    pub vault_token: String,
    pub mount: String,
}

impl HashiCorpVaultSecretStore {
    pub fn from_env() -> Option<Self> {
        let vault_addr = std::env::var("VAULT_ADDR").ok()?;
        let vault_token = std::env::var("VAULT_TOKEN").ok()?;
        let mount = std::env::var("VAULT_KV_MOUNT").unwrap_or_else(|_| "secret".into());
        Some(Self {
            vault_addr,
            vault_token,
            mount,
        })
    }
}

#[async_trait]
impl SecretStore for HashiCorpVaultSecretStore {
    /// Store a client secret in Vault KV v2.
    ///
    /// Writes to `{vault_addr}/v1/{mount}/data/clients/{client_id}`.
    /// The stored reference is the Vault path, prefixed with `vault:`.
    async fn store_secret(&self, client_id: &str, plaintext: &str) -> Result<String> {
        let url = format!(
            "{}/v1/{}/data/clients/{}",
            self.vault_addr, self.mount, client_id
        );
        let body = serde_json::json!({ "data": { "secret": plaintext } });

        let response = reqwest::Client::new()
            .put(&url)
            .header("X-Vault-Token", &self.vault_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Vault write error: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Vault write failed ({status}): {text}"
            )));
        }

        info!(client_id, vault_path = %url, "Stored secret in HashiCorp Vault");
        Ok(format!("vault:{}/{}", self.mount, client_id))
    }

    /// Verify a secret by reading it back from Vault KV v2.
    ///
    /// Reads from `{vault_addr}/v1/{mount}/data/clients/{client_id}`.
    /// Comparison is constant-time via `subtle`.
    async fn verify_secret(
        &self,
        client_id: &str,
        presented: &str,
        stored_ref: &str,
    ) -> Result<bool> {
        if !stored_ref.starts_with("vault:") {
            // Not a Vault-managed secret — this backend shouldn't be asked to verify it
            return Ok(false);
        }

        let url = format!(
            "{}/v1/{}/data/clients/{}",
            self.vault_addr, self.mount, client_id
        );

        let response = reqwest::Client::new()
            .get(&url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Vault read error: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !response.status().is_success() {
            let status = response.status();
            return Err(AppError::Internal(format!("Vault read failed ({status})")));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Vault response parse error: {e}")))?;

        let stored_secret = body
            .pointer("/data/data/secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("Vault: missing data.data.secret".into()))?;

        // Constant-time comparison to resist timing attacks
        use subtle::ConstantTimeEq;
        let equal: bool = stored_secret.as_bytes().ct_eq(presented.as_bytes()).into();
        Ok(equal)
    }

    /// Remove a secret from Vault KV v2 by deleting all metadata.
    async fn delete_secret(&self, client_id: &str) -> Result<()> {
        let url = format!(
            "{}/v1/{}/metadata/clients/{}",
            self.vault_addr, self.mount, client_id
        );

        let response = reqwest::Client::new()
            .delete(&url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Vault delete error: {e}")))?;

        // 204 No Content or 404 (already deleted) are both acceptable
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            info!(client_id, vault_path = %url, "Deleted secret from HashiCorp Vault");
            return Ok(());
        }

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(AppError::Internal(format!(
            "Vault delete failed ({status}): {text}"
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

/// Which backend to use, driven by `SECRET_STORE_BACKEND` env var.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStoreBackend {
    /// SHA-256 hash in `client_secret_hash` column (default).
    Database,
    /// AWS KMS envelope encryption.
    AwsKms,
    /// HashiCorp Vault KV v2.
    Vault,
}

impl SecretStoreBackend {
    pub fn from_env() -> Self {
        Self::from_str(&std::env::var("SECRET_STORE_BACKEND").unwrap_or_default())
    }

    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aws_kms" | "kms" => Self::AwsKms,
            "vault" | "hashicorp_vault" => Self::Vault,
            _ => Self::Database,
        }
    }
}

/// Construct the configured `SecretStore` from environment variables.
/// Falls back to `DatabaseSecretStore` if backend-specific config is missing.
pub fn build_secret_store() -> std::sync::Arc<dyn SecretStore> {
    match SecretStoreBackend::from_env() {
        SecretStoreBackend::Database => {
            info!("✅ SecretStore backend: Database (SHA-256)");
            std::sync::Arc::new(DatabaseSecretStore)
        }
        SecretStoreBackend::AwsKms => {
            if let Some(store) = AwsKmsSecretStore::from_env() {
                info!(
                    key_id = %store.key_id,
                    region = %store.region,
                    "✅ SecretStore backend: AWS KMS (stub)"
                );
                std::sync::Arc::new(store)
            } else {
                warn!(
                    "SECRET_STORE_BACKEND=aws_kms but AWS_KMS_KEY_ID is not set — \
                     falling back to Database backend"
                );
                std::sync::Arc::new(DatabaseSecretStore)
            }
        }
        SecretStoreBackend::Vault => {
            if let Some(store) = HashiCorpVaultSecretStore::from_env() {
                info!(
                    vault_addr = %store.vault_addr,
                    mount = %store.mount,
                    "✅ SecretStore backend: HashiCorp Vault KV v2"
                );
                std::sync::Arc::new(store)
            } else {
                warn!(
                    "SECRET_STORE_BACKEND=vault but VAULT_ADDR or VAULT_TOKEN is not set — \
                     falling back to Database backend"
                );
                std::sync::Arc::new(DatabaseSecretStore)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn database_store_round_trip() {
        let store = DatabaseSecretStore;
        let secret = "super-secret-value-abc123";
        let stored = store.store_secret("client_test", secret).await.unwrap();
        assert!(store
            .verify_secret("client_test", secret, &stored)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn database_store_wrong_secret_fails() {
        let store = DatabaseSecretStore;
        let stored = store.store_secret("client_test", "correct").await.unwrap();
        assert!(!store
            .verify_secret("client_test", "wrong", &stored)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn database_store_delete_is_noop() {
        let store = DatabaseSecretStore;
        store.delete_secret("client_test").await.unwrap();
    }

    #[tokio::test]
    async fn kms_stub_round_trip() {
        let store = AwsKmsSecretStore {
            key_id: "alias/test".into(),
            region: "us-east-1".into(),
        };
        let secret = "test-secret";
        let stored = store.store_secret("client_kms", secret).await.unwrap();
        assert!(stored.starts_with("kms:"));
        assert!(store
            .verify_secret("client_kms", secret, &stored)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn kms_stub_wrong_secret_fails() {
        let store = AwsKmsSecretStore {
            key_id: "alias/test".into(),
            region: "us-east-1".into(),
        };
        let stored = store.store_secret("client_kms", "correct").await.unwrap();
        assert!(!store
            .verify_secret("client_kms", "wrong", &stored)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn vault_stub_verify_returns_error_when_real_vault_needed() {
        let store = HashiCorpVaultSecretStore {
            vault_addr: "http://localhost:8200".into(),
            vault_token: "root".into(),
            mount: "secret".into(),
        };
        let stored = store
            .store_secret("client_vault", "my-secret")
            .await
            .unwrap();
        assert!(stored.starts_with("vault:"));
        // Verification should return an explicit error when stored_ref is a Vault path
        assert!(store
            .verify_secret("client_vault", "my-secret", &stored)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn backend_from_env_defaults_to_database() {
        assert_eq!(
            SecretStoreBackend::from_str(""),
            SecretStoreBackend::Database
        );
        assert_eq!(
            SecretStoreBackend::from_str("unknown"),
            SecretStoreBackend::Database
        );
    }

    #[tokio::test]
    async fn backend_from_env_parses_kms() {
        assert_eq!(
            SecretStoreBackend::from_str("aws_kms"),
            SecretStoreBackend::AwsKms
        );
        assert_eq!(
            SecretStoreBackend::from_str("kms"),
            SecretStoreBackend::AwsKms
        );
    }

    #[tokio::test]
    async fn backend_from_env_parses_vault() {
        assert_eq!(
            SecretStoreBackend::from_str("vault"),
            SecretStoreBackend::Vault
        );
        assert_eq!(
            SecretStoreBackend::from_str("hashicorp_vault"),
            SecretStoreBackend::Vault
        );
    }
}
