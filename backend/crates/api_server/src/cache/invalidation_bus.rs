//! Distributed Cache Invalidation Bus
//!
//! Redis pub/sub-based message bus for propagating cache invalidation events
//! across all API replicas in real-time.
//!
//! ## Architecture
//!
//! ```text
//! API Replica 1          API Replica 2          API Replica 3
//!      │                      │                      │
//!      │ publish              │ subscribe            │ subscribe
//!      ▼                      ▼                      ▼
//!  ┌────────────────────────────────────────────────────┐
//!  │         Redis Pub/Sub (cache:invalidate)          │
//!  └────────────────────────────────────────────────────┘
//!           │                  │                  │
//!           └──────────────────┴──────────────────┘
//!                    Broadcast to all
//! ```
//!
//! ## Deduplication
//!
//! Messages are deduplicated using an LRU cache of recent message IDs to prevent
//! processing the same invalidation multiple times (e.g., when a replica receives
//! its own published message).

use crate::cache::invalidation::{InvalidationMessage, InvalidationScope};
use crate::cache::metrics::CACHE_METRICS;
use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use lru::LruCache;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

const CHANNEL_NAME: &str = "cache:invalidate";
const DEDUP_CACHE_SIZE: usize = 10000;
const SUBSCRIBER_BUFFER_SIZE: usize = 1000;

/// Distributed cache invalidation bus
///
/// Publishes invalidation messages to Redis pub/sub and subscribes to receive
/// messages from other replicas.
#[derive(Clone)]
pub struct InvalidationBus {
    redis: ConnectionManager,
    redis_client: Client,
    replica_id: String,
    /// Local broadcast channel for subscribers within this replica
    tx: broadcast::Sender<InvalidationMessage>,
    /// Recent message IDs for deduplication
    recent_messages: Arc<RwLock<LruCache<Uuid, ()>>>,
}

impl InvalidationBus {
    /// Create a new invalidation bus
    ///
    /// Automatically spawns a background subscriber task that listens for
    /// invalidation messages on the Redis pub/sub channel.
    pub async fn new(redis: ConnectionManager, redis_client: Client, replica_id: String) -> Result<Self> {
        let (tx, _rx) = broadcast::channel(SUBSCRIBER_BUFFER_SIZE);
        let recent_messages = Arc::new(RwLock::new(
            LruCache::new(NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap()),
        ));

        let bus = Self {
            redis: redis.clone(),
            redis_client: redis_client.clone(),
            replica_id: replica_id.clone(),
            tx: tx.clone(),
            recent_messages: recent_messages.clone(),
        };

        // Spawn subscriber task
        bus.spawn_subscriber();

        tracing::info!(
            replica_id = %replica_id,
            channel = CHANNEL_NAME,
            "Cache invalidation bus initialized"
        );

        Ok(bus)
    }

    /// Publish an invalidation message to all replicas
    ///
    /// The message will be received by all replicas (including this one),
    /// but will be deduplicated on the receiving end.
    pub async fn publish(&self, scope: InvalidationScope) -> Result<()> {
        let msg = InvalidationMessage::new(scope, self.replica_id.clone());

        // Add to dedup cache (don't process our own messages)
        self.recent_messages
            .write()
            .await
            .put(msg.message_id, ());

        // Serialize and publish
        let payload = msg.to_json()?;
        let mut conn = self.redis.clone();
        
        let subscriber_count: i32 = conn
            .publish(CHANNEL_NAME, payload)
            .await
            .map_err(|e| anyhow!("Failed to publish invalidation: {}", e))?;

        CACHE_METRICS.invalidation_published.inc();

        tracing::debug!(
            message_id = %msg.message_id,
            scope = ?msg.scope,
            subscribers = subscriber_count,
            "Published cache invalidation"
        );

        Ok(())
    }

    /// Subscribe to invalidation messages
    ///
    /// Returns a broadcast receiver that will receive all invalidation messages
    /// from other replicas (excluding messages published by this replica).
    pub fn subscribe(&self) -> broadcast::Receiver<InvalidationMessage> {
        self.tx.subscribe()
    }

    /// Spawn background subscriber task
    ///
    /// Listens for messages on the Redis pub/sub channel and broadcasts them
    /// to local subscribers after deduplication.
    fn spawn_subscriber(&self) {
        let redis_client = self.redis_client.clone();
        let tx = self.tx.clone();
        let recent_messages = self.recent_messages.clone();
        let replica_id = self.replica_id.clone();

        tokio::spawn(async move {
            loop {
                match Self::run_subscriber(
                    redis_client.clone(),
                    tx.clone(),
                    recent_messages.clone(),
                    replica_id.clone(),
                )
                .await
                {
                    Ok(_) => {
                        tracing::warn!("Invalidation subscriber ended normally, restarting...");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Invalidation subscriber failed, restarting in 5s..."
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    async fn run_subscriber(
        redis_client: Client,
        tx: broadcast::Sender<InvalidationMessage>,
        recent_messages: Arc<RwLock<LruCache<Uuid, ()>>>,
        replica_id: String,
    ) -> Result<()> {
        let conn = redis_client
            .get_async_connection()
            .await
            .map_err(|e| anyhow!("Failed to get Redis connection for pub/sub: {}", e))?;
        
        let mut pubsub = conn.into_pubsub();
        
        pubsub
            .subscribe(CHANNEL_NAME)
            .await
            .map_err(|e| anyhow!("Failed to subscribe to {}: {}", CHANNEL_NAME, e))?;

        tracing::info!(
            channel = CHANNEL_NAME,
            replica_id = %replica_id,
            "Subscribed to cache invalidation channel"
        );

        let mut stream = pubsub.on_message();
        
        while let Some(msg) = stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "Invalid message payload");
                    CACHE_METRICS.invalidation_errors.inc();
                    continue;
                }
            };

            let inv_msg: InvalidationMessage = match InvalidationMessage::from_json(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to deserialize invalidation message");
                    CACHE_METRICS.invalidation_errors.inc();
                    continue;
                }
            };

            // Deduplication check
            {
                let mut cache = recent_messages.write().await;
                if cache.contains(&inv_msg.message_id) {
                    // Already processed (our own message or duplicate)
                    tracing::trace!(
                        message_id = %inv_msg.message_id,
                        "Skipping duplicate invalidation message"
                    );
                    continue;
                }
                cache.put(inv_msg.message_id, ());
            }

            CACHE_METRICS.invalidation_received.inc();

            tracing::info!(
                message_id = %inv_msg.message_id,
                source = %inv_msg.source_replica_id,
                scope = ?inv_msg.scope,
                reason = ?inv_msg.reason,
                "Received cache invalidation"
            );

            // Broadcast to local subscribers
            // Ignore send errors (no subscribers is OK)
            let _ = tx.send(inv_msg);
        }

        Ok(())
    }

    /// Get the replica ID
    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_cache_size() {
        // Verify LRU cache can be created with the configured size
        let cache: LruCache<Uuid, ()> =
            LruCache::new(NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap());
        assert_eq!(cache.cap().get(), DEDUP_CACHE_SIZE);
    }

    #[test]
    fn test_channel_name() {
        assert_eq!(CHANNEL_NAME, "cache:invalidate");
    }
}

// Made with Bob
