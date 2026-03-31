#![allow(dead_code)]
//! SSO Client Secret Encryption (MEDIUM-6)
//!
//! OAuth client secrets stored in `sso_connections.client_secret` are sensitive
//! credentials. If the database is compromised, plaintext secrets allow attackers
//! to impersonate the SP to any configured IdP.
//!
//! This module provides AES-256-GCM encryption/decryption for SSO client secrets.
//! The encryption key is loaded from the `SSO_ENCRYPTION_KEY` environment variable
//! (32 bytes, base64url-encoded), which must be set in production.
//!
//! ## Encrypted Format
//! Encrypted values are stored as: `enc:v1:<base64url(nonce || ciphertext || tag)>`
//! The `enc:v1:` prefix allows future key rotation and distinguishes encrypted from
//! legacy plaintext values during migration.
//!
//! ## Key Rotation
//! To rotate keys:
//! 1. Set `SSO_ENCRYPTION_KEY_OLD` to the old key
//! 2. Set `SSO_ENCRYPTION_KEY` to the new key
//! 3. Run the migration script to re-encrypt all secrets
//! 4. Remove `SSO_ENCRYPTION_KEY_OLD`

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Prefix for encrypted values — allows detection and future versioning
const ENCRYPTED_PREFIX: &str = "enc:v1:";

/// AES-256-GCM nonce size (96 bits)
const NONCE_SIZE: usize = 12;

/// SSO secret encryption/decryption service
#[derive(Clone)]
pub struct SsoEncryption {
    cipher: Option<Aes256Gcm>,
}

impl SsoEncryption {
    /// Create a new SsoEncryption from the `SSO_ENCRYPTION_KEY` environment variable.
    ///
    /// If the env var is not set, encryption is disabled and secrets are stored as-is.
    /// This allows gradual rollout but logs a warning in production.
    pub fn from_env() -> Self {
        match std::env::var("SSO_ENCRYPTION_KEY") {
            Ok(key_b64) => {
                match URL_SAFE_NO_PAD.decode(key_b64.as_bytes()) {
                    Ok(key_bytes) => {
                        match key_bytes.try_into() as Result<[u8; 32], _> {
                            Ok(key_arr) => {
                                let key = Key::<Aes256Gcm>::from(key_arr);
                                let cipher = Aes256Gcm::new(&key);
                                tracing::info!("SSO encryption initialized with AES-256-GCM");
                                Self { cipher: Some(cipher) }
                            }
                            Err(_) => {
                                tracing::error!("SSO_ENCRYPTION_KEY must be exactly 32 bytes — SSO encryption DISABLED");
                                Self { cipher: None }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("SSO_ENCRYPTION_KEY invalid base64: {} — SSO encryption DISABLED", e);
                        Self { cipher: None }
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    "SSO_ENCRYPTION_KEY not set — SSO client secrets stored in plaintext. \
                     Set SSO_ENCRYPTION_KEY (32 bytes, base64url) for production."
                );
                Self { cipher: None }
            }
        }
    }

    /// Create with an explicit key (for testing)
    pub fn new(key: [u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from(key);
        let cipher = Aes256Gcm::new(&key);
        Self { cipher: Some(cipher) }
    }

    /// Encrypt a client secret for storage.
    ///
    /// Returns `enc:v1:<base64url(nonce || ciphertext || tag)>` if encryption is enabled,
    /// or the plaintext value if encryption is not configured.
    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
        let cipher = match &self.cipher {
            Some(c) => c,
            None => return Ok(plaintext.to_string()),
        };

        // Already encrypted — don't double-encrypt
        if plaintext.starts_with(ENCRYPTED_PREFIX) {
            return Ok(plaintext.to_string());
        }

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("SSO secret encryption failed: {e:?}"))?;

        // Concatenate nonce || ciphertext (tag is appended by aes-gcm)
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(format!("{}{}", ENCRYPTED_PREFIX, URL_SAFE_NO_PAD.encode(&combined)))
    }

    /// Decrypt a client secret from storage.
    ///
    /// Handles both encrypted (`enc:v1:...`) and legacy plaintext values transparently.
    pub fn decrypt(&self, stored: &str) -> anyhow::Result<String> {
        // Not encrypted (legacy plaintext or encryption disabled)
        if !stored.starts_with(ENCRYPTED_PREFIX) {
            return Ok(stored.to_string());
        }

        let cipher = match &self.cipher {
            Some(c) => c,
            None => {
                return Err(anyhow::anyhow!(
                    "SSO secret is encrypted but SSO_ENCRYPTION_KEY is not set"
                ));
            }
        };

        let encoded = &stored[ENCRYPTED_PREFIX.len()..];
        let combined = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| anyhow::anyhow!("Invalid encrypted SSO secret: {e}"))?;

        if combined.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Encrypted SSO secret too short"));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("SSO secret decryption failed — wrong key or corrupted data"))?;

        String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("Decrypted SSO secret is not valid UTF-8: {e}"))
    }

    /// Check if a value is encrypted
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENCRYPTED_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let enc = SsoEncryption::new(key);
        let secret = "my-super-secret-oauth-client-secret";

        let encrypted = enc.encrypt(secret).unwrap();
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        assert_ne!(encrypted, secret);

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_plaintext_passthrough_when_disabled() {
        let enc = SsoEncryption { cipher: None };
        let secret = "plaintext-secret";

        let stored = enc.encrypt(secret).unwrap();
        assert_eq!(stored, secret);

        let retrieved = enc.decrypt(secret).unwrap();
        assert_eq!(retrieved, secret);
    }

    #[test]
    fn test_no_double_encryption() {
        let key = [42u8; 32];
        let enc = SsoEncryption::new(key);
        let secret = "my-secret";

        let encrypted_once = enc.encrypt(secret).unwrap();
        let encrypted_twice = enc.encrypt(&encrypted_once).unwrap();
        assert_eq!(encrypted_once, encrypted_twice);
    }
}

// Made with Bob
