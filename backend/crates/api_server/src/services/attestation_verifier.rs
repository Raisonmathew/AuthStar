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
    #[allow(dead_code)] // alternative constructor for testing and key pre-loading
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
    #[allow(dead_code)] // batch key loader — awaiting integration with key rotation
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
        // Use the same canonical hash function as the runtime (attestation::hash_decision)
        // to ensure the hash algorithm (blake3) and JSON serialization (BTreeMap with
        // explicit null for reason) match exactly.
        let runtime_decision = attestation::Decision {
            allow: decision.allow,
            reason: decision.reason.clone(),
        };
        let expected_hash = attestation::hash_decision(&runtime_decision);
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

        // Reconstruct the runtime's AttestationBody and use the same canonical
        // serialization (body_to_bytes) that was used when signing. The runtime
        // uses a BTreeMap with lexicographic key ordering, so we must match that
        // exactly — not the verifier's own serde_json::to_vec which may differ.
        let runtime_body = attestation::AttestationBody {
            capsule_hash_b64: attestation.body.capsule_hash_b64.clone(),
            decision_hash_b64: attestation.body.decision_hash_b64.clone(),
            executed_at_unix: attestation.body.executed_at_unix,
            expires_at_unix: attestation.body.expires_at_unix,
            nonce_b64: attestation.body.nonce_b64.clone(),
            runtime_kid: attestation.body.runtime_kid.clone(),
            ast_hash_b64: attestation.body.ast_hash_b64.clone().unwrap_or_default(),
            lowering_version: attestation.body.lowering_version.clone().unwrap_or_default(),
            wasm_hash_b64: attestation.body.wasm_hash_b64.clone().unwrap_or_default(),
        };
        let body_bytes = attestation::body_to_bytes(&runtime_body);

        // Verify
        key.verify(&body_bytes, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }
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
        // Use the same canonical hash as the runtime (blake3 + BTreeMap)
        let runtime_decision = attestation::Decision {
            allow: decision.allow,
            reason: decision.reason.clone(),
        };
        let body = AttestationBody {
            capsule_hash_b64: "test_hash".to_string(),
            decision_hash_b64: attestation::hash_decision(&runtime_decision),
            executed_at_unix: now,
            expires_at_unix: if expired { now - 100 } else { now + 100 },
            nonce_b64: "test_nonce".to_string(),
            runtime_kid: "test_kid".to_string(),
            ast_hash_b64: Some("test_ast_hash".to_string()),
            wasm_hash_b64: Some("test_wasm_hash".to_string()),
            lowering_version: Some("1.0".to_string()),
        };

        // Sign using the same canonical serialization as the runtime
        let runtime_body = attestation::AttestationBody {
            capsule_hash_b64: body.capsule_hash_b64.clone(),
            decision_hash_b64: body.decision_hash_b64.clone(),
            executed_at_unix: body.executed_at_unix,
            expires_at_unix: body.expires_at_unix,
            nonce_b64: body.nonce_b64.clone(),
            runtime_kid: body.runtime_kid.clone(),
            ast_hash_b64: body.ast_hash_b64.clone().unwrap_or_default(),
            lowering_version: body.lowering_version.clone().unwrap_or_default(),
            wasm_hash_b64: body.wasm_hash_b64.clone().unwrap_or_default(),
        };
        let body_bytes = attestation::body_to_bytes(&runtime_body);
        let signature = signing_key.sign(&body_bytes);
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
        let d1 = attestation::Decision {
            allow: true,
            reason: None,
        };
        let d2 = attestation::Decision {
            allow: true,
            reason: None,
        };

        assert_eq!(
            attestation::hash_decision(&d1),
            attestation::hash_decision(&d2)
        );
    }
}
