//! Factor secret encryption using AES-256-GCM
//!
//! Encrypts TOTP secrets before storage and decrypts during verification.
//! Uses a 32-byte key from the `FACTOR_ENCRYPTION_KEY` environment variable.
//! If no key is configured, falls back to plaintext (with a loud warning).
//!
//! ## Key Format
//!
//! `FACTOR_ENCRYPTION_KEY` must be a **base64url-encoded** (no padding) 32-byte secret.
//!
//! Generate with:
//! ```sh
//! openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
//! ```
//!
//! This matches the format expected by `MfaService::new_with_encryption()` so that
//! both services can share the same key material from the same environment variable.
//!
//! ## Legacy hex format
//!
//! The original implementation accepted a 64-character hex string. This is still
//! supported for backward compatibility: if the value is exactly 64 hex characters,
//! it is decoded as hex. Otherwise, base64url decoding is attempted.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rand::RngCore;

/// Handles encryption/decryption of factor secrets (TOTP keys, etc.)
#[derive(Clone)]
pub struct FactorEncryption {
    cipher: Option<Aes256Gcm>,
}

impl FactorEncryption {
    /// Create from a base64url-encoded (or legacy hex-encoded) 32-byte key.
    ///
    /// Accepts `None` for plaintext fallback (development only).
    ///
    /// ## Key format priority
    /// 1. If the value is exactly 64 hex characters → decoded as hex (legacy support)
    /// 2. Otherwise → decoded as base64url (no padding) — the canonical format
    ///
    /// Returns a `FactorEncryption` with `cipher = None` (plaintext fallback) if:
    /// - `key_encoded` is `None`
    /// - The value is empty
    /// - Decoding fails (logs an error)
    /// - The decoded key is not exactly 32 bytes (logs an error)
    pub fn new(key_encoded: Option<&str>) -> Self {
        let cipher = key_encoded.and_then(|raw| {
            if raw.is_empty() {
                return None;
            }

            // Attempt hex decode first (legacy: 64 hex chars = 32 bytes)
            let key_bytes: Option<Vec<u8>> =
                if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
                    hex::decode(raw).ok()
                } else {
                    // Canonical format: base64url, no padding
                    URL_SAFE_NO_PAD.decode(raw.as_bytes()).ok().or_else(|| {
                        // Also try standard base64 (with padding) as a fallback
                        STANDARD.decode(raw.as_bytes()).ok()
                    })
                };

            let key_bytes = match key_bytes {
                Some(b) => b,
                None => {
                    tracing::error!(
                        "FACTOR_ENCRYPTION_KEY could not be decoded. \
                         Expected base64url (no padding) or 64-char hex string. \
                         Generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='"
                    );
                    return None;
                }
            };

            if key_bytes.len() != 32 {
                tracing::error!(
                    "FACTOR_ENCRYPTION_KEY must decode to exactly 32 bytes, got {} bytes. \
                     Generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='",
                    key_bytes.len()
                );
                return None;
            }

            // unwrap: we just verified the slice is 32 bytes
            Some(Aes256Gcm::new_from_slice(&key_bytes).unwrap())
        });

        if cipher.is_none() && key_encoded.is_some() {
            // Key was provided but invalid — already logged above
        } else if cipher.is_none() {
            tracing::warn!(
                "⚠️  FACTOR_ENCRYPTION_KEY not set — TOTP secrets stored in PLAINTEXT \
                 (insecure for production)"
            );
        }

        Self { cipher }
    }

    /// Encrypt a secret string. Returns base64-encoded `nonce:ciphertext`.
    pub fn encrypt(&self, plaintext: &str) -> String {
        match &self.cipher {
            Some(cipher) => {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext.as_bytes())
                    .expect("AES-GCM encryption should not fail");

                // Format: base64(nonce) + ":" + base64(ciphertext)
                format!(
                    "enc:{}:{}",
                    STANDARD.encode(nonce_bytes),
                    STANDARD.encode(ciphertext)
                )
            }
            None => plaintext.to_string(), // Plaintext fallback
        }
    }

    /// Decrypt a secret string. Handles both encrypted (`enc:...`) and plaintext formats.
    pub fn decrypt(&self, stored: &str) -> Result<String, String> {
        if !stored.starts_with("enc:") {
            // Plaintext (legacy or no encryption configured)
            return Ok(stored.to_string());
        }

        let cipher = self.cipher.as_ref().ok_or_else(|| {
            "Encrypted secret found but FACTOR_ENCRYPTION_KEY not configured".to_string()
        })?;

        let parts: Vec<&str> = stored.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err("Invalid encrypted format".to_string());
        }

        let nonce_bytes = STANDARD
            .decode(parts[1])
            .map_err(|e| format!("Invalid nonce base64: {e}"))?;
        let ciphertext = STANDARD
            .decode(parts[2])
            .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Decryption failed — wrong key or corrupted data".to_string())?;

        String::from_utf8(plaintext).map_err(|e| format!("Decrypted data is not valid UTF-8: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // 32 bytes = 64 hex chars
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc = FactorEncryption::new(Some(key));

        let secret = "JBSWY3DPEHPK3PXP";
        let encrypted = enc.encrypt(secret);
        assert!(encrypted.starts_with("enc:"));
        assert_ne!(encrypted, secret);

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_plaintext_fallback() {
        let enc = FactorEncryption::new(None);
        let secret = "JBSWY3DPEHPK3PXP";
        let stored = enc.encrypt(secret);
        assert_eq!(stored, secret); // No encryption

        let decrypted = enc.decrypt(&stored).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_decrypt_legacy_plaintext() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc = FactorEncryption::new(Some(key));

        // Legacy plaintext secret (no "enc:" prefix)
        let decrypted = enc.decrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decrypted, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let enc1 = FactorEncryption::new(Some(key1));
        let enc2 = FactorEncryption::new(Some(key2));

        let encrypted = enc1.encrypt("secret");
        assert!(enc2.decrypt(&encrypted).is_err());
    }
}
