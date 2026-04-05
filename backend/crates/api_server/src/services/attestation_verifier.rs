#![allow(dead_code)]
//! Attestation Verifier Service
//!
//! Implements cryptographic verification of EIAA attestation signatures.
//! Uses Ed25519 for signature verification.
//!
//! ## Design Pattern: Strategy
//! The verification strategy is abstracted to allow future HSM integration.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during attestation verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Attestation has expired")]
    Expired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unknown key ID: {0}")]
    UnknownKeyId(String),
    #[error("Malformed attestation: {0}")]
    MalformedAttestation(String),
    #[error("Decision hash mismatch")]
    DecisionHashMismatch,
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

/// Result type for verification operations.
pub type VerificationResult<T> = Result<T, VerificationError>;

/// Attestation body structure (matches EIAA runtime output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    pub capsule_hash_b64: String,
    pub decision_hash_b64: String,
    pub executed_at_unix: i64,
    pub expires_at_unix: i64,
    pub nonce_b64: String,
    pub runtime_kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_hash_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_hash_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lowering_version: Option<String>,
}

/// Complete attestation with signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub body: AttestationBody,
    pub signature_b64: String,
}

/// EIAA: Structured requirement from capsule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Requirement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_assurance: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub acceptable_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub disallowed_capabilities: Vec<String>,
    #[serde(default)]
    pub require_phishing_resistant: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub session_restrictions: Vec<String>,
}

/// Decision structure for hash verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<Requirement>,
}

/// Attestation Verifier Service.
///
/// Verifies Ed25519 signatures on EIAA attestations using cached public keys.
#[derive(Clone)]
pub struct AttestationVerifier {
    /// Cached runtime public keys (kid -> VerifyingKey).
    key_cache: Arc<RwLock<HashMap<String, VerifyingKey>>>,
}

impl AttestationVerifier {
    /// Create a new verifier with an empty key cache.
    pub fn new() -> Self {
        Self {
            key_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a verifier with pre-loaded keys.
    pub fn with_keys(keys: HashMap<String, VerifyingKey>) -> Self {
        Self {
            key_cache: Arc::new(RwLock::new(keys)),
        }
    }

    /// Load a public key into the cache.
    pub async fn load_key(&self, kid: String, key: VerifyingKey) {
        let mut cache = self.key_cache.write().await;
        cache.insert(kid, key);
    }

    /// Load multiple keys from base64-encoded public keys.
    pub async fn load_keys_b64(&self, keys: Vec<(String, String)>) -> VerificationResult<()> {
        let mut cache = self.key_cache.write().await;
        for (kid, pk_b64) in keys {
            let pk_bytes = URL_SAFE_NO_PAD.decode(&pk_b64)?;
            let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| {
                VerificationError::MalformedAttestation("Invalid key length".into())
            })?;
            let key = VerifyingKey::from_bytes(&pk_array).map_err(|_| {
                VerificationError::MalformedAttestation("Invalid Ed25519 key".into())
            })?;
            cache.insert(kid, key);
        }
        Ok(())
    }

    /// Verify an attestation.
    ///
    /// Checks:
    /// 1. Attestation has not expired.
    /// 2. Decision hash matches the attestation body.
    /// 3. Ed25519 signature is valid.
    pub async fn verify(
        &self,
        attestation: &Attestation,
        decision: &Decision,
        now: DateTime<Utc>,
    ) -> VerificationResult<()> {
        // 1. Check expiry
        if now.timestamp() > attestation.body.expires_at_unix {
            return Err(VerificationError::Expired);
        }

        // 2. Verify decision hash
        let expected_hash = hash_decision(decision);
        if expected_hash != attestation.body.decision_hash_b64 {
            return Err(VerificationError::DecisionHashMismatch);
        }

        // 3. Get public key
        let cache = self.key_cache.read().await;
        let key = cache
            .get(&attestation.body.runtime_kid)
            .ok_or_else(|| VerificationError::UnknownKeyId(attestation.body.runtime_kid.clone()))?;

        // 4. Verify signature
        self.verify_signature(attestation, key)
    }

    /// Verify the Ed25519 signature.
    fn verify_signature(
        &self,
        attestation: &Attestation,
        key: &VerifyingKey,
    ) -> VerificationResult<()> {
        // Decode signature
        let sig_bytes = URL_SAFE_NO_PAD.decode(&attestation.signature_b64)?;
        let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
            VerificationError::MalformedAttestation("Invalid signature format".into())
        })?;

        // Serialize body for verification
        let body_json = serde_json::to_vec(&attestation.body)
            .map_err(|e| VerificationError::MalformedAttestation(format!("JSON error: {e}")))?;

        // Verify
        key.verify(&body_json, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

/// Hash a decision for verification.
pub fn hash_decision(decision: &Decision) -> String {
    let json = serde_json::to_vec(decision).unwrap_or_else(|e| {
        tracing::error!("Failed to serialize decision for hashing: {e}");
        Vec::new()
    });
    let mut hasher = Sha256::new();
    hasher.update(&json);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn create_test_attestation(
        signing_key: &SigningKey,
        decision: &Decision,
        expired: bool,
    ) -> Attestation {
        let now = Utc::now().timestamp();
        let body = AttestationBody {
            capsule_hash_b64: "test_hash".to_string(),
            decision_hash_b64: hash_decision(decision),
            executed_at_unix: now,
            expires_at_unix: if expired { now - 100 } else { now + 100 },
            nonce_b64: "test_nonce".to_string(),
            runtime_kid: "test_kid".to_string(),
            ast_hash_b64: None,
            wasm_hash_b64: None,
            lowering_version: None,
        };

        let body_json = serde_json::to_vec(&body).unwrap();
        let signature = signing_key.sign(&body_json);
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Attestation {
            body,
            signature_b64,
        }
    }

    #[tokio::test]
    async fn test_verify_valid_attestation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let decision = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };
        let attestation = create_test_attestation(&signing_key, &decision, false);

        let verifier = AttestationVerifier::new();
        verifier
            .load_key("test_kid".to_string(), verifying_key)
            .await;

        let result = verifier.verify(&attestation, &decision, Utc::now()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_expired_attestation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let decision = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };
        let attestation = create_test_attestation(&signing_key, &decision, true);

        let verifier = AttestationVerifier::new();
        verifier
            .load_key("test_kid".to_string(), verifying_key)
            .await;

        let result = verifier.verify(&attestation, &decision, Utc::now()).await;
        assert!(matches!(result, Err(VerificationError::Expired)));
    }

    #[tokio::test]
    async fn test_verify_invalid_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();

        let decision = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };
        let attestation = create_test_attestation(&signing_key, &decision, false);

        let verifier = AttestationVerifier::new();
        verifier.load_key("test_kid".to_string(), wrong_key).await;

        let result = verifier.verify(&attestation, &decision, Utc::now()).await;
        assert!(matches!(result, Err(VerificationError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_verify_decision_hash_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let decision = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };
        let attestation = create_test_attestation(&signing_key, &decision, false);

        // Verify with different decision
        let wrong_decision = Decision {
            allow: false,
            reason: Some("denied".to_string()),
            requirement: None,
        };

        let verifier = AttestationVerifier::new();
        verifier
            .load_key("test_kid".to_string(), verifying_key)
            .await;

        let result = verifier
            .verify(&attestation, &wrong_decision, Utc::now())
            .await;
        assert!(matches!(
            result,
            Err(VerificationError::DecisionHashMismatch)
        ));
    }

    #[test]
    fn test_hash_decision_deterministic() {
        let d1 = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };
        let d2 = Decision {
            allow: true,
            reason: None,
            requirement: None,
        };

        assert_eq!(hash_decision(&d1), hash_decision(&d2));
    }
}
