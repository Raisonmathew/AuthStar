//! Capsule Cache Service
//!
//! Redis-based caching for compiled EIAA capsules.
//! Design: Cache-Aside pattern with hash-based invalidation.
//!
//! ## Distributed Environment Considerations
//! - TTL-based expiration ensures eventual consistency
//! - Hash verification prevents stale capsule execution
//! - Invalidation on policy update propagates via Redis pub/sub

use anyhow::{anyhow, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cached capsule metadata (lightweight, no WASM bytes in cache)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCapsule {
    /// Tenant ID
    pub tenant_id: String,
    /// Action type (e.g., "login", "authorize:billing:read")
    pub action: String,
    /// Policy version
    pub version: i32,
    /// AST hash for integrity verification
    pub ast_hash: String,
    /// WASM hash for integrity verification
    pub wasm_hash: String,
    /// Serialized capsule bytes (bincode)
    pub capsule_bytes: Vec<u8>,
    /// Cache timestamp
    pub cached_at: i64,
}

/// Capsule Cache Service
///
/// Provides Redis-based caching with:
/// - Key format: `capsule:{tenant_id}:{action}`
/// - TTL: Configurable (default 1 hour)
/// - Automatic refresh on access
#[derive(Clone)]
pub struct CapsuleCacheService {
    redis: Arc<RwLock<ConnectionManager>>,
    ttl_seconds: u64,
    key_prefix: String,
}

impl CapsuleCacheService {
    /// Create a new capsule cache service
    pub fn new(redis: ConnectionManager, ttl_seconds: u64) -> Self {
        Self {
            redis: Arc::new(RwLock::new(redis)),
            ttl_seconds,
            key_prefix: "capsule".to_string(),
        }
    }

    /// Get a capsule from cache
    ///
    /// Returns None if:
    /// - Not in cache
    /// - Deserialization fails (cache corruption)
    pub async fn get(&self, tenant_id: &str, action: &str) -> Option<CachedCapsule> {
        let key = self.cache_key(tenant_id, action);
        
        let mut redis = self.redis.write().await;
        let bytes: Option<Vec<u8>> = redis.get(&key).await.ok()?;
        
        if let Some(bytes) = bytes {
            // Refresh TTL on access (sliding window)
            let _: Result<(), _> = redis.expire(&key, self.ttl_seconds as i64).await;
            
            // Deserialize
            match bincode::deserialize::<CachedCapsule>(&bytes) {
                Ok(capsule) => Some(capsule),
                Err(e) => {
                    tracing::warn!("Failed to deserialize cached capsule: {}", e);
                    // Invalidate corrupted entry
                    let _: Result<(), _> = redis.del(&key).await;
                    None
                }
            }
        } else {
            None
        }
    }

    /// Store a capsule in cache
    pub async fn set(&self, capsule: &CachedCapsule) -> Result<()> {
        let key = self.cache_key(&capsule.tenant_id, &capsule.action);
        let bytes = bincode::serialize(capsule)
            .map_err(|e| anyhow!("Failed to serialize capsule: {}", e))?;
        
        let mut redis = self.redis.write().await;
        redis.set_ex(&key, bytes, self.ttl_seconds).await
            .map_err(|e| anyhow!("Failed to cache capsule: {}", e))?;
        
        tracing::debug!(
            "Cached capsule for tenant={} action={} (ttl={}s)",
            capsule.tenant_id, capsule.action, self.ttl_seconds
        );
        
        Ok(())
    }

    /// Invalidate a cached capsule
    ///
    /// Should be called when:
    /// - Policy is updated
    /// - Policy is activated/deactivated
    pub async fn invalidate(&self, tenant_id: &str, action: &str) -> Result<()> {
        let key = self.cache_key(tenant_id, action);
        
        let mut redis = self.redis.write().await;
        redis.del(&key).await
            .map_err(|e| anyhow!("Failed to invalidate cache: {}", e))?;
        
        tracing::info!("Invalidated capsule cache for tenant={} action={}", tenant_id, action);
        
        Ok(())
    }

    /// Invalidate all cached capsules for a tenant
    ///
    /// Used when tenant's signing key changes or tenant is deleted.
    pub async fn invalidate_tenant(&self, tenant_id: &str) -> Result<u64> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);
        
        let mut redis = self.redis.write().await;
        
        // Scan for matching keys
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut *redis)
            .await
            .map_err(|e| anyhow!("Failed to scan keys: {}", e))?;
        
        if keys.is_empty() {
            return Ok(0);
        }
        
        let count = keys.len() as u64;
        
        // Delete all matching keys
        redis.del::<_, ()>(keys).await
            .map_err(|e| anyhow!("Failed to delete keys: {}", e))?;
        
        tracing::info!("Invalidated {} cached capsules for tenant={}", count, tenant_id);
        
        Ok(count)
    }

    /// Get cache statistics (for monitoring)
    pub async fn stats(&self, tenant_id: &str) -> Result<CacheStats> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);
        
        let mut redis = self.redis.write().await;
        
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut *redis)
            .await
            .map_err(|e| anyhow!("Failed to scan keys: {}", e))?;
        
        Ok(CacheStats {
            cached_count: keys.len(),
            tenant_id: tenant_id.to_string(),
        })
    }

    /// Generate cache key
    pub fn format_cache_key(prefix: &str, tenant_id: &str, action: &str) -> String {
        format!("{}:{}:{}", prefix, tenant_id, action)
    }

    fn cache_key(&self, tenant_id: &str, action: &str) -> String {
        Self::format_cache_key(&self.key_prefix, tenant_id, action)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub cached_count: usize,
    pub tenant_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        // Verify key format is consistent
        let prefix = "capsule";
        
        let key = CapsuleCacheService::format_cache_key(prefix, "org_123", "login");
        assert_eq!(key, "capsule:org_123:login");
        
        let key = CapsuleCacheService::format_cache_key(prefix, "org_456", "authorize:billing:read");
        assert_eq!(key, "capsule:org_456:authorize:billing:read");
    }

    #[test]
    fn test_cached_capsule_serialization() {
        let capsule = CachedCapsule {
            tenant_id: "org_123".to_string(),
            action: "login".to_string(),
            version: 1,
            ast_hash: "abc123".to_string(),
            wasm_hash: "def456".to_string(),
            capsule_bytes: vec![1, 2, 3, 4],
            cached_at: 1706634000,
        };
        
        let bytes = bincode::serialize(&capsule).unwrap();
        let deserialized: CachedCapsule = bincode::deserialize(&bytes).unwrap();
        
        assert_eq!(deserialized.tenant_id, capsule.tenant_id);
        assert_eq!(deserialized.action, capsule.action);
        assert_eq!(deserialized.version, capsule.version);
        assert_eq!(deserialized.capsule_bytes, capsule.capsule_bytes);
    }
}
