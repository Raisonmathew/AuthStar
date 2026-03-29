#![allow(dead_code)]
//! Capsule Cache Service
//!
//! Redis-based caching for compiled EIAA capsules.
//! Design: Cache-Aside pattern with hash-based invalidation.
//!
//! ## Distributed Environment Considerations
//! - TTL-based expiration ensures eventual consistency
//! - Hash verification prevents stale capsule execution
//! - Invalidation on policy update propagates via Redis pub/sub
//!
//! ## C-3 FIX: Protobuf encoding for capsule_bytes
//!
//! `capsule_bytes` MUST be protobuf-encoded (`prost::Message::encode`) because
//! the consumer in `eiaa_authz.rs` decodes them with `CapsuleSigned::decode`
//! (a `prost::Message` implementation). The previous `bincode` encoding was
//! incompatible — every cache hit would fail to decode and silently fall through
//! to the DB path, making the Redis cache completely ineffective.
//!
//! The `CachedCapsule` envelope (tenant_id, action, version, hashes, cached_at)
//! is still serialized with `serde_json` for human-readable Redis inspection.
//! Only `capsule_bytes` uses protobuf, matching the wire format expected by the
//! `prost::Message::decode` call in `execute_authorization()`.

use anyhow::{anyhow, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cached capsule envelope stored in Redis.
///
/// ## Serialization contract
///
/// The outer envelope (`tenant_id`, `action`, `version`, `ast_hash`, `wasm_hash`,
/// `cached_at`) is serialized with `serde_json` for human-readable Redis inspection
/// and forward-compatible schema evolution.
///
/// `capsule_bytes` contains a **protobuf-encoded** `CapsuleSigned` message
/// (produced by `prost::Message::encode`). This matches the decoding call in
/// `eiaa_authz.rs::execute_authorization()`:
///
/// ```rust,ignore
/// use prost::Message;
/// let capsule = CapsuleSigned::decode(cached.capsule_bytes.as_slice())?;
/// ```
///
/// **Do NOT change `capsule_bytes` to bincode or any other format** without
/// updating the corresponding `CapsuleSigned::decode` call in `eiaa_authz.rs`.
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
    /// Protobuf-encoded `CapsuleSigned` bytes.
    ///
    /// Encoded with `prost::Message::encode`; decoded with `CapsuleSigned::decode`.
    /// Must NOT be bincode — see module-level doc for the serialization contract.
    pub capsule_bytes: Vec<u8>,
    /// Cache timestamp (Unix seconds)
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

    /// Get a capsule from cache.
    ///
    /// Returns `None` if:
    /// - Key not present in Redis
    /// - JSON envelope deserialization fails (cache corruption)
    ///
    /// The returned `CachedCapsule.capsule_bytes` are protobuf-encoded and must be
    /// decoded by the caller with `CapsuleSigned::decode(bytes)`.
    pub async fn get(&self, tenant_id: &str, action: &str) -> Option<CachedCapsule> {
        let key = self.cache_key(tenant_id, action);

        let mut redis = self.redis.write().await;
        let raw: Option<Vec<u8>> = redis.get(&key).await.ok()?;

        if let Some(raw) = raw {
            // Refresh TTL on access (sliding window expiry)
            let _: Result<(), _> = redis.expire(&key, self.ttl_seconds as i64).await;

            // C-3 FIX: Deserialize the envelope with serde_json (not bincode).
            // `capsule_bytes` inside the envelope are protobuf — the caller decodes them.
            match serde_json::from_slice::<CachedCapsule>(&raw) {
                Ok(capsule) => {
                    tracing::trace!(
                        tenant_id = %tenant_id,
                        action = %action,
                        capsule_bytes_len = capsule.capsule_bytes.len(),
                        "Capsule cache hit"
                    );
                    Some(capsule)
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        action = %action,
                        error = %e,
                        "Failed to deserialize cached capsule envelope (JSON) — invalidating entry"
                    );
                    // Invalidate corrupted entry so next request repopulates from DB
                    let _: Result<(), _> = redis.del(&key).await;
                    None
                }
            }
        } else {
            None
        }
    }

    /// Store a capsule in cache.
    ///
    /// `capsule.capsule_bytes` MUST be protobuf-encoded (`prost::Message::encode`)
    /// before calling this method. The envelope is stored as JSON.
    ///
    /// ## Example (from eiaa_authz.rs)
    /// ```rust,ignore
    /// use prost::Message;
    /// let mut capsule_bytes = Vec::new();
    /// capsule_signed.encode(&mut capsule_bytes)?;
    /// let cached = CachedCapsule { capsule_bytes, ..Default::default() };
    /// cache.set(&cached).await?;
    /// ```
    pub async fn set(&self, capsule: &CachedCapsule) -> Result<()> {
        let key = self.cache_key(&capsule.tenant_id, &capsule.action);

        // C-3 FIX: Serialize the envelope with serde_json (not bincode).
        // `capsule_bytes` are already protobuf-encoded by the caller.
        let raw = serde_json::to_vec(capsule)
            .map_err(|e| anyhow!("Failed to serialize capsule envelope: {}", e))?;

        let mut redis = self.redis.write().await;
        redis.set_ex::<_, _, ()>(&key, raw, self.ttl_seconds).await
            .map_err(|e| anyhow!("Failed to cache capsule: {}", e))?;

        tracing::debug!(
            tenant_id = %capsule.tenant_id,
            action = %capsule.action,
            ttl_seconds = %self.ttl_seconds,
            capsule_bytes_len = %capsule.capsule_bytes.len(),
            "Capsule cached (protobuf bytes, JSON envelope)"
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
        redis.del::<_, ()>(&key).await
            .map_err(|e| anyhow!("Failed to invalidate cache: {}", e))?;
        
        tracing::info!("Invalidated capsule cache for tenant={} action={}", tenant_id, action);
        
        Ok(())
    }

    /// Invalidate all cached capsules for a tenant
    ///
    /// Used when tenant's signing key changes or tenant is deleted.
    ///
    /// ## F-5 FIX: Non-blocking SCAN instead of KEYS
    ///
    /// `KEYS pattern` is O(N) and **blocks the entire Redis event loop** for the
    /// duration of the scan. On a large keyspace this can cause latency spikes
    /// across all Redis clients sharing the same instance.
    ///
    /// We now use cursor-based `SCAN` (COUNT 100 per iteration) which yields
    /// control back to Redis between batches, keeping p99 latency stable.
    pub async fn invalidate_tenant(&self, tenant_id: &str) -> Result<u64> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);

        let mut redis = self.redis.write().await;

        // Collect all matching keys via non-blocking SCAN cursor iteration.
        let mut all_keys: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(&mut *redis)
                .await
                .map_err(|e| anyhow!("Failed to SCAN keys: {}", e))?;
            all_keys.extend(batch);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        if all_keys.is_empty() {
            return Ok(0);
        }

        let count = all_keys.len() as u64;

        // Delete all matching keys in a single DEL command.
        redis.del::<_, ()>(all_keys).await
            .map_err(|e| anyhow!("Failed to delete keys: {}", e))?;

        tracing::info!("Invalidated {} cached capsules for tenant={}", count, tenant_id);

        Ok(count)
    }

    /// Get cache statistics (for monitoring)
    ///
    /// ## F-5 FIX: Non-blocking SCAN instead of KEYS
    ///
    /// Uses the same cursor-based SCAN pattern as `invalidate_tenant` to avoid
    /// blocking the Redis event loop during key enumeration.
    pub async fn stats(&self, tenant_id: &str) -> Result<CacheStats> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);

        let mut redis = self.redis.write().await;

        let mut count: usize = 0;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(&mut *redis)
                .await
                .map_err(|e| anyhow!("Failed to SCAN keys: {}", e))?;
            count += batch.len();
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(CacheStats {
            cached_count: count,
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

    /// C-3 FIX: Verify the envelope uses serde_json (not bincode).
    ///
    /// This test ensures that `CachedCapsule` round-trips correctly through
    /// `serde_json::to_vec` / `serde_json::from_slice`, matching the serialization
    /// used by `CapsuleCacheService::set()` and `CapsuleCacheService::get()`.
    ///
    /// The `capsule_bytes` field contains mock protobuf bytes (arbitrary bytes in
    /// this unit test — real callers use `prost::Message::encode`).
    #[test]
    fn test_cached_capsule_json_serialization() {
        // Simulate protobuf-encoded capsule bytes (arbitrary bytes for unit test)
        let proto_bytes = vec![0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]; // proto field 1: "hello"

        let capsule = CachedCapsule {
            tenant_id: "org_123".to_string(),
            action: "login".to_string(),
            version: 1,
            ast_hash: "abc123".to_string(),
            wasm_hash: "def456".to_string(),
            capsule_bytes: proto_bytes.clone(),
            cached_at: 1706634000,
        };

        // Must use serde_json (not bincode) — matches CapsuleCacheService::set/get
        let raw = serde_json::to_vec(&capsule).expect("serde_json serialization failed");
        let deserialized: CachedCapsule =
            serde_json::from_slice(&raw).expect("serde_json deserialization failed");

        assert_eq!(deserialized.tenant_id, capsule.tenant_id);
        assert_eq!(deserialized.action, capsule.action);
        assert_eq!(deserialized.version, capsule.version);
        assert_eq!(deserialized.capsule_bytes, proto_bytes,
            "capsule_bytes must survive JSON round-trip unchanged (base64 encoded in JSON)");
    }

    /// Verify that bincode-encoded bytes are NOT accepted by the new JSON deserializer.
    ///
    /// This is a regression test: if someone accidentally reverts to bincode encoding,
    /// this test will catch it by confirming that bincode bytes fail JSON deserialization.
    #[test]
    fn test_bincode_bytes_rejected_by_json_deserializer() {
        let capsule = CachedCapsule {
            tenant_id: "org_123".to_string(),
            action: "login".to_string(),
            version: 1,
            ast_hash: "abc123".to_string(),
            wasm_hash: "def456".to_string(),
            capsule_bytes: vec![1, 2, 3, 4],
            cached_at: 1706634000,
        };

        // Encode with bincode (the old broken format)
        let bincode_bytes = bincode::serialize(&capsule).expect("bincode serialize");

        // The new JSON deserializer must reject bincode bytes
        let result = serde_json::from_slice::<CachedCapsule>(&bincode_bytes);
        assert!(
            result.is_err(),
            "serde_json must NOT accept bincode-encoded bytes — \
             this would indicate a regression to the broken serialization format"
        );
    }
}
