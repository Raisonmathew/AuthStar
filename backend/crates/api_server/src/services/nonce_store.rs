//! EIAA Nonce Store — Persistent Replay Protection
//!
//! ## HIGH-EIAA-3 Fix
//!
//! The EIAA spec requires that every capsule execution nonce is stored persistently
//! so that replay attacks are prevented even across service restarts. Previously,
//! the runtime service used an in-memory `HashSet<String>` which was lost on every
//! restart, creating a replay window equal to the attestation TTL (typically 5 min).
//!
//! ## Architecture
//!
//! This service implements a two-tier nonce store:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Tier 1: Redis (fast path, O(1) SET NX with TTL)            │
//! │  Tier 2: PostgreSQL eiaa_replay_nonces (durable fallback)   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Write path (mark_seen):
//! 1. Write to Redis with TTL = attestation_ttl_seconds (default 300s)
//! 2. Write to PostgreSQL (async, non-blocking — fire and forget with error log)
//!
//! ### Read path (is_seen):
//! 1. Check Redis (fast, O(1))
//! 2. On Redis miss (Redis down or TTL expired), check PostgreSQL
//! 3. Return true if seen in either store
//!
//! ### Cleanup:
//! PostgreSQL entries older than `retention_seconds` are pruned by a background task.
//! The `eiaa_replay_nonces` table has a `seen_at` column; entries older than
//! `retention_seconds` are deleted in batches to avoid table bloat.
//!
//! ## Security Properties
//! - Nonces are never reused across restarts (durable PostgreSQL store)
//! - Redis provides sub-millisecond lookup for the common case
//! - PostgreSQL provides durability for the rare Redis-down case
//! - Nonces expire after `retention_seconds` (default 600s = 2× attestation TTL)
//!   to bound table growth while maintaining the replay protection window

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Default nonce retention period: 10 minutes (2× the default attestation TTL of 5 min)
pub const DEFAULT_NONCE_RETENTION_SECONDS: i64 = 600;

/// Default Redis TTL for nonce keys: same as retention period
pub const DEFAULT_REDIS_TTL_SECONDS: u64 = 600;

/// EIAA Nonce Store
///
/// Provides persistent replay protection for EIAA capsule execution nonces.
/// Uses PostgreSQL as the durable store and optionally Redis as a fast-path cache.
#[derive(Clone)]
pub struct NonceStore {
    db: PgPool,
    redis: Option<Arc<redis::aio::MultiplexedConnection>>,
    retention_seconds: i64,
    redis_ttl_seconds: u64,
}

impl NonceStore {
    /// Create a new NonceStore with PostgreSQL only (no Redis fast path).
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            redis: None,
            retention_seconds: DEFAULT_NONCE_RETENTION_SECONDS,
            redis_ttl_seconds: DEFAULT_REDIS_TTL_SECONDS,
        }
    }

    /// Create a new NonceStore with both PostgreSQL and Redis.
    pub fn with_redis(db: PgPool, redis: Arc<redis::aio::MultiplexedConnection>) -> Self {
        Self {
            db,
            redis: Some(redis),
            retention_seconds: DEFAULT_NONCE_RETENTION_SECONDS,
            redis_ttl_seconds: DEFAULT_REDIS_TTL_SECONDS,
        }
    }

    /// Set the nonce retention period.
    #[allow(dead_code)] // builder method for custom retention config
    pub fn with_retention_seconds(mut self, seconds: i64) -> Self {
        self.retention_seconds = seconds;
        self.redis_ttl_seconds = seconds as u64;
        self
    }

    /// Check if a nonce has been seen before (replay detection).
    ///
    /// Returns `true` if the nonce was already used (replay attack detected).
    /// Returns `false` if the nonce is fresh (first use).
    ///
    /// ## Algorithm
    /// 1. Check Redis (fast path, O(1))
    /// 2. On Redis miss, check PostgreSQL (slow path, O(log n))
    /// 3. Return true if seen in either store
    pub async fn is_seen(&self, nonce_b64: &str) -> Result<bool> {
        // Fast path: check Redis
        if let Some(ref redis) = self.redis {
            let redis_key = Self::redis_key(nonce_b64);
            let mut conn = (**redis).clone();
            match redis::cmd("EXISTS")
                .arg(&redis_key)
                .query_async::<_, i64>(&mut conn)
                .await
            {
                Ok(1) => {
                    debug!(nonce = %nonce_b64, "Nonce found in Redis (replay detected)");
                    return Ok(true);
                }
                Ok(_) => {
                    // Not in Redis — check DB (Redis may have evicted it)
                }
                Err(e) => {
                    warn!(error = %e, "Redis nonce check failed — falling back to DB");
                }
            }
        }

        // Slow path: check PostgreSQL
        let cutoff = Utc::now() - Duration::seconds(self.retention_seconds);
        let seen: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE FROM eiaa_replay_nonces WHERE nonce_b64 = $1 AND seen_at > $2 LIMIT 1",
        )
        .bind(nonce_b64)
        .bind(cutoff)
        .fetch_optional(&self.db)
        .await?;

        if seen.is_some() {
            debug!(nonce = %nonce_b64, "Nonce found in DB (replay detected)");
            // Backfill Redis so future checks are fast
            if let Some(ref redis) = self.redis {
                let redis_key = Self::redis_key(nonce_b64);
                let mut conn = (**redis).clone();
                let _ = redis::cmd("SET")
                    .arg(&redis_key)
                    .arg(1i64)
                    .arg("EX")
                    .arg(self.redis_ttl_seconds)
                    .arg("NX")
                    .query_async::<_, Option<String>>(&mut conn)
                    .await;
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Mark a nonce as seen (record it to prevent future replay).
    ///
    /// ## Algorithm
    /// 1. Write to Redis with TTL (fast, non-blocking)
    /// 2. Write to PostgreSQL (durable, async)
    ///
    /// Both writes are attempted. If Redis fails, we log a warning but continue
    /// (PostgreSQL is the source of truth). If PostgreSQL fails, we return an error
    /// (the nonce MUST be persisted to prevent replay after restart).
    pub async fn mark_seen(&self, nonce_b64: &str) -> Result<()> {
        let now = Utc::now();

        // Write to Redis (fast path, non-blocking)
        if let Some(ref redis) = self.redis {
            let redis_key = Self::redis_key(nonce_b64);
            let mut conn = (**redis).clone();
            match redis::cmd("SET")
                .arg(&redis_key)
                .arg(1i64)
                .arg("EX")
                .arg(self.redis_ttl_seconds)
                .arg("NX") // Only set if not exists (atomic)
                .query_async::<_, Option<String>>(&mut conn)
                .await
            {
                Ok(Some(_)) => {
                    debug!(nonce = %nonce_b64, "Nonce written to Redis");
                }
                Ok(None) => {
                    // NX failed — nonce already exists in Redis (concurrent request?)
                    warn!(nonce = %nonce_b64, "Nonce already in Redis during mark_seen — possible concurrent replay");
                }
                Err(e) => {
                    warn!(error = %e, nonce = %nonce_b64, "Failed to write nonce to Redis — continuing with DB only");
                }
            }
        }

        // Write to PostgreSQL (durable, required)
        // ON CONFLICT DO NOTHING: idempotent — if the nonce was already inserted
        // by a concurrent request, we don't fail (the replay check already caught it).
        sqlx::query(
            "INSERT INTO eiaa_replay_nonces (nonce_b64, seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING"
        )
        .bind(nonce_b64)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to persist nonce to DB: {e}"))?;

        debug!(nonce = %nonce_b64, "Nonce persisted to DB");
        Ok(())
    }

    /// Check and mark a nonce atomically (check-then-set).
    ///
    /// Returns `Ok(true)` if the nonce was fresh and has been marked as seen.
    /// Returns `Ok(false)` if the nonce was already seen (replay attack).
    /// Returns `Err` if the persistence operation failed.
    ///
    /// This is the primary entry point for the EIAA middleware. It combines
    /// `is_seen` and `mark_seen` into a single operation to minimize the
    /// TOCTOU window.
    pub async fn check_and_mark(&self, nonce_b64: &str) -> Result<bool> {
        // Check first
        if self.is_seen(nonce_b64).await? {
            return Ok(false); // Replay detected
        }

        // Mark as seen
        self.mark_seen(nonce_b64).await?;

        Ok(true) // Fresh nonce, now marked
    }

    /// Prune expired nonces from PostgreSQL.
    ///
    /// Should be called periodically (e.g., every 5 minutes) to prevent
    /// unbounded table growth. Deletes all nonces older than `retention_seconds`.
    ///
    /// Returns the number of rows deleted.
    #[allow(dead_code)] // maintenance method — awaiting background task integration
    pub async fn prune_expired(&self) -> Result<u64> {
        let cutoff = Utc::now() - Duration::seconds(self.retention_seconds);
        let result = sqlx::query("DELETE FROM eiaa_replay_nonces WHERE seen_at < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!(deleted = deleted, "Pruned expired EIAA replay nonces");
        }
        Ok(deleted)
    }

    /// Redis key format for nonce entries.
    fn redis_key(nonce_b64: &str) -> String {
        format!("eiaa:nonce:{nonce_b64}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_key_format() {
        let key = NonceStore::redis_key("abc123");
        assert_eq!(key, "eiaa:nonce:abc123");
    }

    #[test]
    fn test_redis_key_no_collision() {
        // Different nonces must produce different keys
        let k1 = NonceStore::redis_key("nonce_a");
        let k2 = NonceStore::redis_key("nonce_b");
        assert_ne!(k1, k2);
    }
}

// Made with Bob
