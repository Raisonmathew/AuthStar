#![allow(dead_code)]
//! Runtime Key Cache Service
//!
//! Implements Cache-Aside pattern for EIAA runtime public keys.
//! Keys are cached with a TTL to balance security and performance.
//!
//! ## Design Pattern: Cache-Aside
//! 1. Check cache first.
//! 2. On miss, fetch from runtime.
//! 3. Populate cache for future requests.
//!
//! ## Distributed Invalidation
//! When running multiple replicas, invalidation messages are broadcast via
//! InvalidationBus to ensure cache consistency across all instances.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::cache::{InvalidationBus, InvalidationScope};

/// Errors from key cache operations.
#[derive(Debug, Error)]
pub enum KeyCacheError {
    #[error("Failed to fetch keys from runtime: {0}")]
    FetchError(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
}

/// Cached key entry with expiry.
struct CachedKey {
    key: VerifyingKey,
    expires_at: DateTime<Utc>,
}

/// Runtime Key Cache Service.
///
/// Caches Ed25519 public keys from the EIAA runtime to reduce gRPC calls.
/// Supports distributed invalidation when running multiple replicas.
#[derive(Clone)]
pub struct RuntimeKeyCache {
    /// Key cache (kid -> CachedKey)
    cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    /// Cache TTL in seconds (default: 300s = 5 minutes)
    ttl_seconds: i64,
    /// Optional invalidation bus for distributed cache coordination
    invalidation_bus: Option<Arc<InvalidationBus>>,
}

impl RuntimeKeyCache {
    /// Create a new cache with default TTL (5 minutes).
    pub fn new() -> Self {
        Self::with_ttl(300)
    }

    /// Create a new cache with custom TTL.
    pub fn with_ttl(ttl_seconds: i64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_seconds,
            invalidation_bus: None,
        }
    }

    /// Create a new cache with distributed invalidation support.
    ///
    /// When invalidation_bus is provided, all invalidate operations will
    /// broadcast to other replicas via Redis pub/sub.
    pub fn new_with_invalidation(ttl_seconds: i64, invalidation_bus: Arc<InvalidationBus>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_seconds,
            invalidation_bus: Some(invalidation_bus),
        }
    }

    /// Get a key from cache, returns None if not found or expired.
    pub async fn get(&self, kid: &str) -> Option<VerifyingKey> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(kid) {
            if Utc::now() < entry.expires_at {
                return Some(entry.key);
            }
        }
        None
    }

    /// Check if a key exists and is not expired.
    pub async fn contains(&self, kid: &str) -> bool {
        self.get(kid).await.is_some()
    }

    /// Insert a key into the cache.
    pub async fn insert(&self, kid: String, key: VerifyingKey) {
        let entry = CachedKey {
            key,
            expires_at: Utc::now() + Duration::seconds(self.ttl_seconds),
        };
        let mut cache = self.cache.write().await;
        cache.insert(kid, entry);
    }

    /// Bulk insert keys from base64-encoded format.
    pub async fn insert_batch(&self, keys: Vec<(String, String)>) -> Result<(), KeyCacheError> {
        let mut cache = self.cache.write().await;
        let expires_at = Utc::now() + Duration::seconds(self.ttl_seconds);

        for (kid, pk_b64) in keys {
            let pk_bytes = URL_SAFE_NO_PAD
                .decode(&pk_b64)
                .map_err(|e| KeyCacheError::InvalidKeyFormat(format!("Base64 error: {e}")))?;

            let pk_array: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| KeyCacheError::InvalidKeyFormat("Key must be 32 bytes".into()))?;

            let key = VerifyingKey::from_bytes(&pk_array)
                .map_err(|e| KeyCacheError::InvalidKeyFormat(format!("Ed25519 error: {e}")))?;

            cache.insert(kid, CachedKey { key, expires_at });
        }
        Ok(())
    }

    /// Invalidate a specific key.
    ///
    /// If distributed invalidation is enabled, broadcasts to all replicas.
    pub async fn invalidate(&self, kid: &str) {
        debug!("Invalidating runtime key: {}", kid);

        // Local invalidation
        {
            let mut cache = self.cache.write().await;
            cache.remove(kid);
        }

        // Distributed invalidation
        if let Some(bus) = &self.invalidation_bus {
            let scope = InvalidationScope::RuntimeKey {
                key_id: kid.to_string(),
            };
            if let Err(e) = bus.publish(scope).await {
                warn!("Failed to publish runtime key invalidation: {}", e);
            }
        }
    }

    /// Invalidate all cached keys.
    ///
    /// If distributed invalidation is enabled, broadcasts to all replicas.
    pub async fn invalidate_all(&self) {
        debug!("Invalidating all runtime keys");

        // Local invalidation
        {
            let mut cache = self.cache.write().await;
            cache.clear();
        }

        // Distributed invalidation
        if let Some(bus) = &self.invalidation_bus {
            let scope = InvalidationScope::AllRuntimeKeys;
            if let Err(e) = bus.publish(scope).await {
                warn!("Failed to publish all runtime keys invalidation: {}", e);
            }
        }
    }

    /// Spawn a background task to handle remote invalidation messages.
    ///
    /// This should be called once during application startup if distributed
    /// invalidation is enabled.
    pub fn spawn_invalidation_handler(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let Some(bus) = &self.invalidation_bus else {
                warn!("RuntimeKeyCache: No invalidation bus configured");
                return;
            };

            let mut rx = bus.subscribe();
            debug!("RuntimeKeyCache: Listening for invalidation messages");

            while let Ok(msg) = rx.recv().await {
                match msg.scope {
                    InvalidationScope::RuntimeKey { key_id } => {
                        debug!("RuntimeKeyCache: Remote invalidation for key: {}", key_id);
                        let mut cache = self.cache.write().await;
                        cache.remove(&key_id);
                    }
                    InvalidationScope::AllRuntimeKeys => {
                        debug!("RuntimeKeyCache: Remote invalidation for all keys");
                        let mut cache = self.cache.write().await;
                        cache.clear();
                    }
                    _ => {
                        // Ignore other scopes (capsule-related)
                    }
                }
            }

            warn!("RuntimeKeyCache: Invalidation handler stopped");
        })
    }

    /// Remove expired entries (background cleanup).
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut cache = self.cache.write().await;
        cache.retain(|_, entry| entry.expires_at > now);
    }

    /// Get all cached key IDs.
    pub async fn list_keys(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        cache.keys().cloned().collect()
    }

    /// Get the number of cached keys.
    pub async fn len(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Check if cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

impl Default for RuntimeKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_insert_and_get() {
        let cache = RuntimeKeyCache::new();
        let key = SigningKey::generate(&mut OsRng).verifying_key();

        cache.insert("kid_1".to_string(), key).await;

        let retrieved = cache.get("kid_1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_bytes(), key.as_bytes());
    }

    #[tokio::test]
    async fn test_missing_key() {
        let cache = RuntimeKeyCache::new();
        let retrieved = cache.get("nonexistent").await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_expired_key() {
        // Create cache with 0 TTL (immediate expiry)
        let cache = RuntimeKeyCache::with_ttl(0);
        let key = SigningKey::generate(&mut OsRng).verifying_key();

        cache.insert("kid_1".to_string(), key).await;

        // Small delay to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let retrieved = cache.get("kid_1").await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = RuntimeKeyCache::new();
        let key = SigningKey::generate(&mut OsRng).verifying_key();

        cache.insert("kid_1".to_string(), key).await;
        assert!(cache.contains("kid_1").await);

        cache.invalidate("kid_1").await;
        assert!(!cache.contains("kid_1").await);
    }

    #[tokio::test]
    async fn test_batch_insert() {
        let cache = RuntimeKeyCache::new();
        let key1 = SigningKey::generate(&mut OsRng).verifying_key();
        let key2 = SigningKey::generate(&mut OsRng).verifying_key();

        let keys = vec![
            ("kid_1".to_string(), URL_SAFE_NO_PAD.encode(key1.as_bytes())),
            ("kid_2".to_string(), URL_SAFE_NO_PAD.encode(key2.as_bytes())),
        ];

        cache.insert_batch(keys).await.unwrap();

        assert!(cache.contains("kid_1").await);
        assert!(cache.contains("kid_2").await);
        assert_eq!(cache.len().await, 2);
    }
}
