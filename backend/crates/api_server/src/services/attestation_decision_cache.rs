//! Attestation Decision Cache
//!
//! Caches authorization decisions based on action risk level to reduce
//! capsule execution overhead while maintaining security guarantees.
//!
//! ## Cache Key Format
//! `{user_id}:{tenant_id}:{action}:{context_hash}`
//!
//! ## TTL Strategy (Attestation Frequency Matrix)
//! | Risk Level | TTL |
//! |------------|-----|
//! | High | 0s (no cache) |
//! | Medium | 15s |
//! | Low | 60s |
//! | Internal | 60s |
//!
//! ## HIGH-EIAA-4 Fix: Attestation Verification on Cache Hit
//!
//! The `CachedDecision` now stores the full `AttestationBody` alongside the
//! signature. When a cache hit occurs, the middleware re-verifies the Ed25519
//! signature against the stored body before returning the cached decision.
//!
//! This prevents a compromised or tampered cache entry from bypassing
//! authorization. The verification cost is O(1) Ed25519 verify (~50µs),
//! far cheaper than a full capsule execution (~5ms).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::middleware::action_risk::ActionRiskLevel;
use crate::services::attestation_verifier::AttestationBody;

/// Cached authorization decision
///
/// HIGH-EIAA-4 FIX: Now stores the full `AttestationBody` so the middleware
/// can re-verify the Ed25519 signature on every cache hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDecision {
    /// The authorization decision (true = allow)
    pub allowed: bool,
    /// Reason string from capsule execution
    pub reason: String,
    /// Original attestation signature (for re-verification on cache hit)
    pub attestation_signature_b64: Option<String>,
    /// Full attestation body (for re-verification on cache hit).
    ///
    /// HIGH-EIAA-4 FIX: Previously only the signature was stored, making it
    /// impossible to re-verify the signature on cache hit (you need both the
    /// body bytes and the signature to call Ed25519 verify). Now we store the
    /// full body so the middleware can call `verifier.verify()` on every hit.
    pub attestation_body: Option<AttestationBody>,
    /// When the cache entry was created
    pub cached_at: DateTime<Utc>,
    /// When the cache entry expires
    pub expires_at: DateTime<Utc>,
    /// Context hash used for cache invalidation
    pub context_hash: String,
}

impl CachedDecision {
    /// Check if this cached decision is still valid
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

/// Attestation decision cache with variable TTL based on action risk
#[derive(Clone)]
pub struct AttestationDecisionCache {
    cache: Arc<RwLock<HashMap<String, CachedDecision>>>,
}

impl AttestationDecisionCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate cache key from decision parameters
    pub fn cache_key(
        user_id: &str,
        tenant_id: &str,
        action: &str,
        context_hash: &str,
    ) -> String {
        format!("{}:{}:{}:{}", user_id, tenant_id, action, context_hash)
    }

    /// Hash context for cache key (IP, risk score, etc.)
    pub fn hash_context(ip: Option<&str>, risk_score: f64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ip.unwrap_or("unknown").as_bytes());
        hasher.update(format!("{:.0}", risk_score).as_bytes());
        let hash = hasher.finalize();
        URL_SAFE_NO_PAD.encode(&hash[..8]) // First 8 bytes = 64 bits
    }

    /// Get a cached decision if valid
    pub async fn get(
        &self,
        user_id: &str,
        tenant_id: &str,
        action: &str,
        context_hash: &str,
        risk_level: ActionRiskLevel,
    ) -> Option<CachedDecision> {
        // High-risk actions never use cache
        if !risk_level.allows_caching() {
            return None;
        }

        let key = Self::cache_key(user_id, tenant_id, action, context_hash);
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(&key) {
            let now = Utc::now();
            if entry.is_valid(now) && entry.context_hash == context_hash {
                tracing::debug!(
                    action = %action,
                    risk_level = ?risk_level,
                    ttl_remaining_secs = (entry.expires_at - now).num_seconds(),
                    "Cache hit for attestation decision"
                );
                return Some(entry.clone());
            }
        }

        None
    }

    /// Store a decision in the cache
    ///
    /// HIGH-EIAA-4 FIX: Now accepts the full `AttestationBody` so it can be
    /// stored alongside the signature for re-verification on cache hit.
    pub async fn set(
        &self,
        user_id: &str,
        tenant_id: &str,
        action: &str,
        context_hash: &str,
        risk_level: ActionRiskLevel,
        allowed: bool,
        reason: &str,
        attestation_signature_b64: Option<&str>,
        attestation_body: Option<AttestationBody>,
    ) {
        // High-risk actions never cached
        if !risk_level.allows_caching() {
            return;
        }

        let ttl_secs = risk_level.cache_ttl_seconds();
        if ttl_secs == 0 {
            return;
        }

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);
        
        let entry = CachedDecision {
            allowed,
            reason: reason.to_string(),
            attestation_signature_b64: attestation_signature_b64.map(String::from),
            attestation_body,
            cached_at: now,
            expires_at,
            context_hash: context_hash.to_string(),
        };

        let key = Self::cache_key(user_id, tenant_id, action, context_hash);
        let mut cache = self.cache.write().await;
        cache.insert(key, entry);

        tracing::debug!(
            action = %action,
            risk_level = ?risk_level,
            ttl_secs = ttl_secs,
            "Cached attestation decision"
        );
    }

    /// Invalidate all cached decisions for a user
    pub async fn invalidate_user(&self, user_id: &str) {
        let mut cache = self.cache.write().await;
        cache.retain(|key, _| !key.starts_with(&format!("{}:", user_id)));
    }

    /// Invalidate all cached decisions for an action type
    pub async fn invalidate_action(&self, action: &str) {
        let mut cache = self.cache.write().await;
        cache.retain(|key, _| !key.contains(&format!(":{}:", action)));
    }

    /// Remove all expired entries (call periodically)
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut cache = self.cache.write().await;
        cache.retain(|_, entry| entry.is_valid(now));
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let now = Utc::now();
        let total = cache.len();
        let valid = cache.values().filter(|e| e.is_valid(now)).count();
        CacheStats {
            total_entries: total,
            valid_entries: valid,
            expired_entries: total - valid,
        }
    }
}

impl Default for AttestationDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_miss_for_high_risk() {
        let cache = AttestationDecisionCache::new();
        cache.set(
            "user1", "tenant1", "org:delete", "ctx123",
            ActionRiskLevel::High, true, "allowed", None, None,
        ).await;
        
        // High-risk should never be cached
        let result = cache.get(
            "user1", "tenant1", "org:delete", "ctx123",
            ActionRiskLevel::High,
        ).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_hit_for_low_risk() {
        let cache = AttestationDecisionCache::new();
        cache.set(
            "user1", "tenant1", "dashboard:read", "ctx123",
            ActionRiskLevel::Low, true, "allowed", Some("sig123"), None,
        ).await;
        
        let result = cache.get(
            "user1", "tenant1", "dashboard:read", "ctx123",
            ActionRiskLevel::Low,
        ).await;
        
        assert!(result.is_some());
        let decision = result.unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.attestation_signature_b64, Some("sig123".to_string()));
    }

    #[tokio::test]
    async fn test_context_hash_invalidates_cache() {
        let cache = AttestationDecisionCache::new();
        cache.set(
            "user1", "tenant1", "device:list", "ctx_old",
            ActionRiskLevel::Low, true, "allowed", None, None,
        ).await;
        
        // Different context hash should miss
        let result = cache.get(
            "user1", "tenant1", "device:list", "ctx_new",
            ActionRiskLevel::Low,
        ).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_user_invalidation() {
        let cache = AttestationDecisionCache::new();
        cache.set("user1", "tenant1", "action1", "ctx", ActionRiskLevel::Low, true, "ok", None, None).await;
        cache.set("user1", "tenant1", "action2", "ctx", ActionRiskLevel::Low, true, "ok", None, None).await;
        cache.set("user2", "tenant1", "action1", "ctx", ActionRiskLevel::Low, true, "ok", None, None).await;
        
        cache.invalidate_user("user1").await;
        
        let stats = cache.stats().await;
        assert_eq!(stats.valid_entries, 1); // Only user2's entry remains
    }
}
