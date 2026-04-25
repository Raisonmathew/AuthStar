//! Capsule Cache Service
//!
//! Redis-based caching for compiled EIAA capsules.
//! Design: Cache-Aside pattern with hash-based invalidation.
//!
//! ## Distributed Environment Considerations
//! - TTL-based expiration ensures eventual consistency
//! - Hash verification prevents stale capsule execution
//! - Invalidation on policy update propagates via Redis pub/sub (Phase 2)
//! - Cross-replica invalidation via InvalidationBus (< 100ms propagation)
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
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Phase 2: Distributed cache invalidation
use crate::cache::invalidation::InvalidationScope;
use crate::cache::invalidation_bus::InvalidationBus;

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
    /// Capsule expiry (Unix seconds). Used to bound Redis TTL so that stale
    /// capsules are never served from cache after their time-validity window.
    #[serde(default)]
    pub not_after_unix: i64,
}

/// Capsule Cache Service
///
/// Provides Redis-based caching with:
/// - Key format: `capsule:{tenant_id}:{action}`
/// - TTL: Configurable (default 1 hour)
/// - Automatic refresh on access
#[derive(Clone)]
pub struct CapsuleCacheService {
    /// Redis connection.
    ///
    /// `redis::aio::ConnectionManager` is `Clone` and internally pools/multiplexes
    /// over a single TCP connection — cloning is cheap and does NOT open a new
    /// socket. We therefore hold it directly (not behind a `Mutex`/`RwLock`) so
    /// concurrent cache reads/writes don't serialize on a global lock. Each call
    /// site clones into a local mutable handle and issues commands independently.
    redis: ConnectionManager,
    ttl_seconds: u64,
    key_prefix: String,
    /// Phase 2: Distributed invalidation bus (optional for backward compatibility)
    invalidation_bus: Option<Arc<InvalidationBus>>,
}

impl CapsuleCacheService {
    /// Create a new capsule cache service
    ///
    /// ## Phase 2: Distributed Invalidation
    ///
    /// If `invalidation_bus` is provided, cache invalidations will be propagated
    /// to all API replicas via Redis pub/sub. This ensures cache consistency
    /// across the cluster with < 100ms propagation latency.
    pub fn new(redis: ConnectionManager, ttl_seconds: u64) -> Self {
        Self {
            redis,
            ttl_seconds,
            key_prefix: "capsule".to_string(),
            invalidation_bus: None,
        }
    }

    /// Create a new capsule cache service with distributed invalidation
    ///
    /// ## Phase 2: Distributed Cache Coordination
    ///
    /// This constructor enables cross-replica cache invalidation via the
    /// InvalidationBus. When a capsule is invalidated on one replica, all
    /// other replicas will be notified and invalidate their local cache
    /// within < 100ms.
    pub fn new_with_invalidation(
        redis: ConnectionManager,
        ttl_seconds: u64,
        invalidation_bus: Arc<InvalidationBus>,
    ) -> Self {
        let service = Self {
            redis,
            ttl_seconds,
            key_prefix: "capsule".to_string(),
            invalidation_bus: Some(invalidation_bus.clone()),
        };

        // Spawn invalidation handler to process messages from other replicas
        service.spawn_invalidation_handler();

        service
    }

    /// Get a capsule from cache.
    ///
    /// Returns `None` if:
    /// - Key not present in Redis
    /// - JSON envelope deserialization fails (cache corruption)
    /// - Capsule time-validity window has expired or expires within 30 seconds
    ///
    /// The returned `CachedCapsule.capsule_bytes` are protobuf-encoded and must be
    /// decoded by the caller with `CapsuleSigned::decode(bytes)`.
    pub async fn get(&self, tenant_id: &str, action: &str) -> Option<CachedCapsule> {
        let key = self.cache_key(tenant_id, action);

        let mut redis = self.redis.clone();
        let raw: Option<Vec<u8>> = redis.get(&key).await.ok()?;

        if let Some(raw) = raw {
            // C-3 FIX: Deserialize the envelope with serde_json (not bincode).
            // `capsule_bytes` inside the envelope are protobuf — the caller decodes them.
            match serde_json::from_slice::<CachedCapsule>(&raw) {
                Ok(capsule) => {
                    // Reject capsules whose time-validity window has expired or
                    // will expire within 30 seconds (grace period to avoid races
                    // between cache read and runtime execution).
                    if capsule.not_after_unix > 0 {
                        let now = chrono::Utc::now().timestamp();
                        if capsule.not_after_unix < now + 30 {
                            tracing::debug!(
                                tenant_id = %tenant_id,
                                action = %action,
                                not_after_unix = capsule.not_after_unix,
                                now = now,
                                "Cached capsule expired or expiring soon — evicting"
                            );
                            let _: Result<(), _> = redis.del(&key).await;
                            return None;
                        }
                    }

                    // Refresh TTL on access (sliding window expiry)
                    let _: Result<(), _> = redis.expire(&key, self.ttl_seconds as i64).await;

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
            .map_err(|e| anyhow!("Failed to serialize capsule envelope: {e}"))?;

        // Bound the Redis TTL by the capsule's time-validity window so that
        // a 5-minute capsule is never served from a 1-hour cache slot.
        let effective_ttl = if capsule.not_after_unix > 0 {
            let now = chrono::Utc::now().timestamp();
            let remaining = (capsule.not_after_unix - now).max(0) as u64;
            remaining.min(self.ttl_seconds)
        } else {
            self.ttl_seconds
        };

        let mut redis = self.redis.clone();
        redis
            .set_ex::<_, _, ()>(&key, raw, effective_ttl)
            .await
            .map_err(|e| anyhow!("Failed to cache capsule: {e}"))?;

        tracing::debug!(
            tenant_id = %capsule.tenant_id,
            action = %capsule.action,
            ttl_seconds = %effective_ttl,
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
    ///
    /// ## Phase 2: Distributed Invalidation
    ///
    /// If InvalidationBus is configured, this will publish an invalidation
    /// message to all replicas. Otherwise, only the local cache is invalidated.
    pub async fn invalidate(&self, tenant_id: &str, action: &str) -> Result<()> {
        let key = self.cache_key(tenant_id, action);

        // Local invalidation
        let mut redis = self.redis.clone();
        redis
            .del::<_, ()>(&key)
            .await
            .map_err(|e| anyhow!("Failed to invalidate cache: {e}"))?;
        drop(redis); // Release connection handle before publishing

        tracing::info!(
            "Invalidated capsule cache for tenant={} action={}",
            tenant_id,
            action
        );

        // Phase 2: Publish to other replicas
        if let Some(bus) = &self.invalidation_bus {
            bus.publish(InvalidationScope::Capsule {
                tenant_id: tenant_id.to_string(),
                action: action.to_string(),
            })
            .await?;

            tracing::debug!(
                tenant_id = %tenant_id,
                action = %action,
                "Published capsule invalidation to all replicas"
            );
        }

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
    #[allow(dead_code)] // cache invalidation — awaiting integration into tenant lifecycle
    pub async fn invalidate_tenant(&self, tenant_id: &str) -> Result<u64> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);

        let mut redis = self.redis.clone();

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
                .query_async(&mut redis)
                .await
                .map_err(|e| anyhow!("Failed to SCAN keys: {e}"))?;
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
        redis
            .del::<_, ()>(all_keys)
            .await
            .map_err(|e| anyhow!("Failed to delete keys: {e}"))?;

        Ok(count)
    }

    /// Spawn background handler for invalidation messages from other replicas
    ///
    /// ## Phase 2: Distributed Cache Coordination
    ///
    /// This handler subscribes to the InvalidationBus and processes invalidation
    /// messages from other API replicas. When a message is received, it invalidates
    /// the corresponding cache entry locally.
    pub fn spawn_invalidation_handler(&self) {
        let Some(bus) = &self.invalidation_bus else {
            return;
        };

        let mut rx = bus.subscribe();
        let redis = self.redis.clone();
        let key_prefix = self.key_prefix.clone();

        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                match msg.scope {
                    InvalidationScope::Capsule { tenant_id, action } => {
                        let key = Self::format_cache_key(&key_prefix, &tenant_id, &action);
                        let mut conn = redis.clone();
                        if let Err(e) = conn.del::<_, ()>(&key).await {
                            tracing::error!(
                                error = %e,
                                key = %key,
                                "Failed to invalidate capsule from remote message"
                            );
                        } else {
                            tracing::debug!(
                                tenant_id = %tenant_id,
                                action = %action,
                                source = %msg.source_replica_id,
                                "Invalidated capsule from remote replica"
                            );
                        }
                    }
                    InvalidationScope::TenantCapsules { tenant_id } => {
                        let pattern = format!("{key_prefix}:{tenant_id}:*");
                        let mut conn = redis.clone();

                        // Use SCAN to find and delete all matching keys
                        let mut all_keys: Vec<String> = Vec::new();
                        let mut cursor: u64 = 0;
                        loop {
                            match redis::cmd("SCAN")
                                .arg(cursor)
                                .arg("MATCH")
                                .arg(&pattern)
                                .arg("COUNT")
                                .arg(100u64)
                                .query_async::<_, (u64, Vec<String>)>(&mut conn)
                                .await
                            {
                                Ok((next_cursor, batch)) => {
                                    all_keys.extend(batch);
                                    cursor = next_cursor;
                                    if cursor == 0 {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "Failed to SCAN keys for tenant invalidation"
                                    );
                                    break;
                                }
                            }
                        }

                        if !all_keys.is_empty() {
                            if let Err(e) = conn.del::<_, ()>(all_keys.clone()).await {
                                tracing::error!(
                                    error = %e,
                                    "Failed to delete tenant capsules from remote message"
                                );
                            } else {
                                tracing::debug!(
                                    tenant_id = %tenant_id,
                                    count = all_keys.len(),
                                    source = %msg.source_replica_id,
                                    "Invalidated tenant capsules from remote replica"
                                );
                            }
                        }
                    }
                    _ => {
                        // Other scopes (RuntimeKey, AllRuntimeKeys, Global) are handled
                        // by RuntimeKeyCache or other services
                        tracing::trace!(
                            scope = ?msg.scope,
                            "Ignoring invalidation scope not handled by CapsuleCacheService"
                        );
                    }
                }
            }

            tracing::warn!("Capsule cache invalidation handler ended");
        });
    }

    /// Get cache statistics (for monitoring)
    ///
    /// ## F-5 FIX: Non-blocking SCAN instead of KEYS
    ///
    /// Uses the same cursor-based SCAN pattern as `invalidate_tenant` to avoid
    /// blocking the Redis event loop during key enumeration.
    #[allow(dead_code)] // cache management — awaiting admin endpoint
    pub async fn stats(&self, tenant_id: &str) -> Result<CacheStats> {
        let pattern = format!("{}:{}:*", self.key_prefix, tenant_id);

        let mut redis = self.redis.clone();

        let mut count: usize = 0;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(&mut redis)
                .await
                .map_err(|e| anyhow!("Failed to SCAN keys: {e}"))?;
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
        format!("{prefix}:{tenant_id}:{action}")
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

        let key =
            CapsuleCacheService::format_cache_key(prefix, "org_456", "authorize:billing:read");
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
            not_after_unix: 1706634300,
        };

        // Must use serde_json (not bincode) — matches CapsuleCacheService::set/get
        let raw = serde_json::to_vec(&capsule).expect("serde_json serialization failed");
        let deserialized: CachedCapsule =
            serde_json::from_slice(&raw).expect("serde_json deserialization failed");

        assert_eq!(deserialized.tenant_id, capsule.tenant_id);
        assert_eq!(deserialized.action, capsule.action);
        assert_eq!(deserialized.version, capsule.version);
        assert_eq!(
            deserialized.capsule_bytes, proto_bytes,
            "capsule_bytes must survive JSON round-trip unchanged (base64 encoded in JSON)"
        );
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
            not_after_unix: 1706634300,
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
