use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake3::hash as blake3_hash;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey, Signature};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand::SeedableRng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

#[derive(Clone)]
pub struct PublicKey {
    pub kid: KeyId,
    pub key: VerifyingKey,
}

pub trait Signer: Send + Sync {
    fn kid(&self) -> &KeyId;
    fn public_key(&self) -> &VerifyingKey;
    fn sign(&self, msg: &[u8]) -> Signature;
}

pub trait Keystore: Send + Sync {
    fn generate_ed25519(&self) -> Result<KeyId>;
    fn import_ed25519(&self, sk_bytes: &[u8]) -> Result<KeyId>;
    fn public_key(&self, kid: &KeyId) -> Result<PublicKey>;
    fn sign(&self, kid: &KeyId, msg: &[u8]) -> Result<Signature>;
    fn list_public_keys(&self) -> Vec<PublicKey>;
}

pub fn compute_kid(pk: &VerifyingKey) -> KeyId {
    let digest = blake3_hash(pk.as_bytes());
    KeyId(URL_SAFE_NO_PAD.encode(digest.as_bytes()))
}

struct Ed25519Entry {
    kid: KeyId,
    sk: SigningKey,
    pk: VerifyingKey,
}

#[derive(Clone, Default)]
pub struct InMemoryKeystore {
    inner: Arc<RwLock<HashMap<String, Ed25519Entry>>>,
}

impl InMemoryKeystore {
    pub fn ephemeral() -> Self {
        Self::default()
    }

    pub fn from_seed(seed: [u8; 32], count: usize) -> Result<Self> {
        let ks = Self::default();
        let mut rng = ChaCha20Rng::from_seed(seed);
        for _ in 0..count {
            let _ = ks.generate_ed25519_inner(&mut rng)?;
        }
        Ok(ks)
    }

    fn generate_ed25519_inner(&self, rng: &mut ChaCha20Rng) -> Result<KeyId> {
        let sk = SigningKey::generate(rng);
        let pk = sk.verifying_key();
        let kid = compute_kid(&pk);
        let entry = Ed25519Entry { kid: kid.clone(), sk, pk };
        let mut map = self.inner.write().map_err(|_| anyhow!("keystore poisoned"))?;
        map.insert(entry.kid.0.clone(), entry);
        Ok(kid)
    }
}

impl Keystore for InMemoryKeystore {
    fn generate_ed25519(&self) -> Result<KeyId> {
        let mut seed = [0u8; 32];
        ChaCha20Rng::from_entropy().fill_bytes(&mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        self.generate_ed25519_inner(&mut rng)
    }

    fn import_ed25519(&self, sk_bytes: &[u8]) -> Result<KeyId> {
        let sk = SigningKey::from_bytes(sk_bytes.try_into().map_err(|_| anyhow!("bad key len"))?);
        let pk = sk.verifying_key();
        let kid = compute_kid(&pk);
        let entry = Ed25519Entry { kid: kid.clone(), sk, pk };
        let mut map = self.inner.write().map_err(|_| anyhow!("keystore poisoned"))?;
        map.insert(entry.kid.0.clone(), entry);
        Ok(kid)
    }

    fn public_key(&self, kid: &KeyId) -> Result<PublicKey> {
        let map = self.inner.read().map_err(|_| anyhow!("keystore poisoned"))?;
        let entry = map.get(&kid.0).ok_or_else(|| anyhow!("unknown kid"))?;
        Ok(PublicKey { kid: entry.kid.clone(), key: entry.pk })
    }

    fn sign(&self, kid: &KeyId, msg: &[u8]) -> Result<Signature> {
        let map = self.inner.read().map_err(|_| anyhow!("keystore poisoned"))?;
        let entry = map.get(&kid.0).ok_or_else(|| anyhow!("unknown kid"))?;
        Ok(entry.sk.sign(msg))
    }

    fn list_public_keys(&self) -> Vec<PublicKey> {
        let map = self.inner.read().ok();
        if let Some(map) = map {
            map.values()
                .map(|e| PublicKey { kid: e.kid.clone(), key: e.pk })
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_keystore_generate_ed25519() {
        let ks = InMemoryKeystore::ephemeral();
        
        let kid = ks.generate_ed25519().unwrap();
        
        // Key ID should not be empty
        assert!(!kid.0.is_empty());
        
        // Should be able to retrieve the public key
        let pk = ks.public_key(&kid).unwrap();
        assert_eq!(pk.kid, kid);
    }

    #[test]
    fn test_keystore_generate_multiple_keys() {
        let ks = InMemoryKeystore::ephemeral();
        
        let kid1 = ks.generate_ed25519().unwrap();
        let kid2 = ks.generate_ed25519().unwrap();
        let kid3 = ks.generate_ed25519().unwrap();
        
        // Each key should be unique
        assert_ne!(kid1.0, kid2.0);
        assert_ne!(kid2.0, kid3.0);
        assert_ne!(kid1.0, kid3.0);
        
        // All keys should be listed
        let keys = ks.list_public_keys();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_keystore_sign_and_verify() {
        let ks = InMemoryKeystore::ephemeral();
        let kid = ks.generate_ed25519().unwrap();
        
        let message = b"test message to sign";
        
        // Sign the message
        let signature = ks.sign(&kid, message).unwrap();
        
        // Get the public key
        let pk = ks.public_key(&kid).unwrap();
        
        // Verify the signature
        assert!(pk.key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keystore_sign_wrong_message_fails() {
        let ks = InMemoryKeystore::ephemeral();
        let kid = ks.generate_ed25519().unwrap();
        
        let message = b"original message";
        let wrong_message = b"wrong message";
        
        let signature = ks.sign(&kid, message).unwrap();
        let pk = ks.public_key(&kid).unwrap();
        
        // Verification should fail for wrong message
        assert!(pk.key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_keystore_unknown_kid_fails() {
        let ks = InMemoryKeystore::ephemeral();
        
        let unknown_kid = KeyId("unknown_key_id".to_string());
        
        assert!(ks.public_key(&unknown_kid).is_err());
        assert!(ks.sign(&unknown_kid, b"message").is_err());
    }

    #[test]
    fn test_keystore_import_ed25519() {
        let ks = InMemoryKeystore::ephemeral();
        
        // Generate a known secret key (32 bytes)
        let sk_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        
        let kid = ks.import_ed25519(&sk_bytes).unwrap();
        
        // Should be able to sign with imported key
        let signature = ks.sign(&kid, b"test").unwrap();
        let pk = ks.public_key(&kid).unwrap();
        assert!(pk.key.verify(b"test", &signature).is_ok());
    }

    #[test]
    fn test_keystore_import_invalid_key_fails() {
        let ks = InMemoryKeystore::ephemeral();
        
        // Wrong length
        let short_key = [0u8; 16]; // Should be 32
        assert!(ks.import_ed25519(&short_key).is_err());
    }

    #[test]
    fn test_keystore_from_seed_deterministic() {
        let seed = [0u8; 32];
        
        let ks1 = InMemoryKeystore::from_seed(seed, 2).unwrap();
        let ks2 = InMemoryKeystore::from_seed(seed, 2).unwrap();
        
        let keys1 = ks1.list_public_keys();
        let keys2 = ks2.list_public_keys();
        
        assert_eq!(keys1.len(), 2);
        assert_eq!(keys2.len(), 2);
        
        // Same seed should produce same keys (compare as sets since HashMap order is non-deterministic)
        let kids1: std::collections::HashSet<_> = keys1.iter().map(|k| k.kid.0.clone()).collect();
        let kids2: std::collections::HashSet<_> = keys2.iter().map(|k| k.kid.0.clone()).collect();
        assert_eq!(kids1, kids2);
    }

    #[test]
    fn test_compute_kid_deterministic() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        
        let kid1 = compute_kid(&pk);
        let kid2 = compute_kid(&pk);
        
        assert_eq!(kid1.0, kid2.0);
        assert!(!kid1.0.is_empty());
    }

    #[test]
    fn test_compute_kid_base64_encoded() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();
        
        let kid = compute_kid(&pk);
        
        // Should be valid URL-safe base64 (no +, /, or =)
        assert!(!kid.0.contains('+'));
        assert!(!kid.0.contains('/'));
    }

    #[test]
    fn test_keystore_thread_safe() {
        use std::thread;
        
        let ks = InMemoryKeystore::ephemeral();
        
        let handles: Vec<_> = (0..10).map(|_| {
            let ks_clone = ks.clone();
            thread::spawn(move || {
                ks_clone.generate_ed25519().unwrap()
            })
        }).collect();
        
        let kids: Vec<KeyId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        
        // All keys should be unique
        let unique: std::collections::HashSet<_> = kids.iter().map(|k| &k.0).collect();
        assert_eq!(unique.len(), 10);
        
        // All keys should be in the keystore
        assert_eq!(ks.list_public_keys().len(), 10);
    }
}
