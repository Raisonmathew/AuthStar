use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake3::hash as blake3_hash;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey, Verifier as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    pub capsule_hash_b64: String,
    pub decision_hash_b64: String,
    pub executed_at_unix: i64,
    pub expires_at_unix: i64,
    pub nonce_b64: String,
    pub runtime_kid: String,
    
    // EIAA New Fields
    pub ast_hash_b64: String,
    pub lowering_version: String,
    pub wasm_hash_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(flatten)]
    pub body: AttestationBody,
    pub signature_b64: String,
}

pub fn hash_decision(decision: &Decision) -> String {
    let bytes = bincode::serialize(decision).expect("serialize decision");
    let h = blake3_hash(&bytes);
    URL_SAFE_NO_PAD.encode(h.as_bytes())
}

pub fn body_to_bytes(body: &AttestationBody) -> Vec<u8> {
    // Canonical serialization for signing
    bincode::serialize(body).expect("serialize attestation body")
}

pub fn sign_attestation(
    body: AttestationBody,
    sign_fn: &dyn Fn(&[u8]) -> Result<Signature>,
) -> Result<Attestation> {
    let bytes = body_to_bytes(&body);
    let sig = sign_fn(&bytes)?;
    Ok(Attestation {
        body,
        signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    })
}

pub fn verify_attestation(
    att: &Attestation,
    key_lookup: &dyn Fn(&str) -> Option<VerifyingKey>,
    now: DateTime<Utc>,
) -> Result<()> {
    if att.body.expires_at_unix < now.timestamp() {
        return Err(anyhow!("attestation expired"));
    }
    let pk = key_lookup(&att.body.runtime_kid).ok_or_else(|| anyhow!("unknown kid"))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(att.signature_b64.as_bytes())
        .map_err(|_| anyhow!("bad signature encoding"))?;
    let sig = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| anyhow!("bad signature length"))?,
    );
    let bytes = body_to_bytes(&att.body);
    pk.verify(&bytes, &sig).map_err(|_| anyhow!("signature verify failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    fn create_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_test_body(expires_offset: i64) -> AttestationBody {
        let now = Utc::now().timestamp();
        AttestationBody {
            capsule_hash_b64: "test_capsule_hash".to_string(),
            decision_hash_b64: "test_decision_hash".to_string(),
            executed_at_unix: now,
            expires_at_unix: now + expires_offset,
            nonce_b64: "test_nonce".to_string(),
            runtime_kid: "test_kid".to_string(),
            ast_hash_b64: "test_ast_hash".to_string(),
            lowering_version: "1.0".to_string(),
            wasm_hash_b64: "test_wasm_hash".to_string(),
        }
    }

    #[test]
    fn test_hash_decision_deterministic() {
        let decision = Decision {
            allow: true,
            reason: Some("test".to_string()),
        };
        
        let hash1 = hash_decision(&decision);
        let hash2 = hash_decision(&decision);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_decision_different_for_different_decisions() {
        let decision1 = Decision { allow: true, reason: None };
        let decision2 = Decision { allow: false, reason: None };
        
        let hash1 = hash_decision(&decision1);
        let hash2 = hash_decision(&decision2);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sign_and_verify_attestation() {
        let (signing_key, verifying_key) = create_test_keypair();
        let body = create_test_body(3600); // Expires in 1 hour
        
        let attestation = sign_attestation(body, &|bytes| {
            Ok(signing_key.sign(bytes))
        }).unwrap();
        
        let key_lookup = |kid: &str| {
            if kid == "test_kid" {
                Some(verifying_key)
            } else {
                None
            }
        };
        
        let result = verify_attestation(&attestation, &key_lookup, Utc::now());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_attestation_expired() {
        let (signing_key, verifying_key) = create_test_keypair();
        let body = create_test_body(-3600); // Expired 1 hour ago
        
        let attestation = sign_attestation(body, &|bytes| {
            Ok(signing_key.sign(bytes))
        }).unwrap();
        
        let key_lookup = |kid: &str| {
            if kid == "test_kid" {
                Some(verifying_key)
            } else {
                None
            }
        };
        
        let result = verify_attestation(&attestation, &key_lookup, Utc::now());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_verify_attestation_unknown_kid() {
        let (signing_key, _) = create_test_keypair();
        let body = create_test_body(3600);
        
        let attestation = sign_attestation(body, &|bytes| {
            Ok(signing_key.sign(bytes))
        }).unwrap();
        
        // Key lookup returns None for all kids
        let key_lookup = |_: &str| None;
        
        let result = verify_attestation(&attestation, &key_lookup, Utc::now());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown kid"));
    }

    #[test]
    fn test_verify_attestation_wrong_key() {
        let (signing_key, _) = create_test_keypair();
        let (_, wrong_verifying_key) = create_test_keypair(); // Different key pair
        let body = create_test_body(3600);
        
        let attestation = sign_attestation(body, &|bytes| {
            Ok(signing_key.sign(bytes))
        }).unwrap();
        
        let key_lookup = |kid: &str| {
            if kid == "test_kid" {
                Some(wrong_verifying_key)
            } else {
                None
            }
        };
        
        let result = verify_attestation(&attestation, &key_lookup, Utc::now());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature verify failed"));
    }

    #[test]
    fn test_verify_attestation_bad_signature_encoding() {
        let (_, verifying_key) = create_test_keypair();
        let body = create_test_body(3600);
        
        let attestation = Attestation {
            body,
            signature_b64: "not-valid-base64!!!".to_string(),
        };
        
        let key_lookup = |kid: &str| {
            if kid == "test_kid" {
                Some(verifying_key)
            } else {
                None
            }
        };
        
        let result = verify_attestation(&attestation, &key_lookup, Utc::now());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad signature encoding"));
    }

    #[test]
    fn test_body_to_bytes_deterministic() {
        let body = create_test_body(3600);
        let bytes1 = body_to_bytes(&body);
        let bytes2 = body_to_bytes(&body);
        
        assert_eq!(bytes1, bytes2);
    }
}
