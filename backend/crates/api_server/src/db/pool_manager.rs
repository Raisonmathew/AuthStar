//! Database pool manager with read replica support
//!
//! Provides automatic load balancing across read replicas using round-robin.
//! Falls back to primary pool if replicas are unavailable.

use crate::config::DatabaseConfig;
use crate::db::metrics::DB_POOL_METRICS;
use anyhow::Result;
use sqlx::postgres::{PgPoolOptions, PgPool};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Pool type for query routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    /// Use primary pool (read-write)
    Primary,
    /// Use read replica pool (read-only)
    Replica,
}

/// Database pools manager
///
/// Manages primary and read replica connection pools with automatic
/// load balancing and graceful degradation.
#[derive(Clone)]
pub struct DatabasePools {
    /// Primary database pool (read-write)
    primary: PgPool,
    /// Read replica pools (read-only)
    replicas: Arc<Vec<PgPool>>,
    /// Round-robin counter for replica selection
    replica_counter: Arc<AtomicUsize>,
    /// Whether read replicas are enabled
    replicas_enabled: bool,
}

impl DatabasePools {
    /// Create new database pools from configuration
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        // Create primary pool
        tracing::info!("Creating primary database pool...");
        let primary = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .connect(&config.url)
            .await?;
        
        tracing::info!(
            "✅ Primary pool created (max: {}, min: {})",
            config.max_connections,
            config.min_connections
        );

        // Create read replica pools if configured
        let (replicas, replicas_enabled) = if config.has_read_replicas() {
            let replica_urls = config.read_replica_urls.as_ref().unwrap();
            let max_conn_per_replica = config
                .max_connections_per_replica
                .unwrap_or(config.max_connections);
            
            tracing::info!(
                "Creating {} read replica pool(s) (max: {} each)...",
                replica_urls.len(),
                max_conn_per_replica
            );

            let mut pools = Vec::with_capacity(replica_urls.len());
            for (idx, url) in replica_urls.iter().enumerate() {
                match PgPoolOptions::new()
                    .max_connections(max_conn_per_replica)
                    .min_connections(config.min_connections)
                    .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
                    .connect(url)
                    .await
                {
                    Ok(pool) => {
                        tracing::info!("✅ Read replica {} connected", idx);
                        pools.push(pool);
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            replica_index = idx,
                            "⚠️  Failed to connect to read replica {} — will use primary for reads",
                            idx
                        );
                    }
                }
            }

            if pools.is_empty() {
                tracing::warn!(
                    "⚠️  No read replicas available — all queries will use primary pool"
                );
                (Arc::new(Vec::new()), false)
            } else {
                tracing::info!(
                    "✅ {} read replica(s) ready (round-robin load balancing)",
                    pools.len()
                );
                (Arc::new(pools), true)
            }
        } else {
            tracing::info!("Read replicas not configured — using primary pool only");
            (Arc::new(Vec::new()), false)
        };

        Ok(Self {
            primary,
            replicas,
            replica_counter: Arc::new(AtomicUsize::new(0)),
            replicas_enabled,
        })
    }

    /// Get a connection pool based on the requested type
    ///
    /// For `PoolType::Replica`, uses round-robin load balancing across replicas.
    /// Falls back to primary if no replicas are available.
    pub fn get_pool(&self, pool_type: PoolType) -> &PgPool {
        match pool_type {
            PoolType::Primary => {
                DB_POOL_METRICS.primary_queries_total.inc();
                &self.primary
            }
            PoolType::Replica => {
                if self.replicas_enabled && !self.replicas.is_empty() {
                    // Round-robin selection
                    let idx = self.replica_counter.fetch_add(1, Ordering::Relaxed);
                    let replica_idx = idx % self.replicas.len();
                    
                    DB_POOL_METRICS
                        .replica_queries_total
                        .with_label_values(&[&replica_idx.to_string()])
                        .inc();
                    
                    &self.replicas[replica_idx]
                } else {
                    // Fallback to primary
                    tracing::trace!("No replicas available, using primary for read query");
                    DB_POOL_METRICS.primary_queries_total.inc();
                    &self.primary
                }
            }
        }
    }

    /// Get the primary pool directly
    pub fn primary(&self) -> &PgPool {
        &self.primary
    }

    /// Check if read replicas are enabled and available
    pub fn has_replicas(&self) -> bool {
        self.replicas_enabled && !self.replicas.is_empty()
    }

    /// Get the number of available read replicas
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }

    /// Update connection pool metrics
    ///
    /// Should be called periodically (e.g., every 10 seconds) to update
    /// Prometheus metrics with current pool statistics.
    pub fn update_metrics(&self) {
        // Primary pool metrics
        let primary_size = self.primary.size() as usize;
        let primary_idle = self.primary.num_idle();
        DB_POOL_METRICS
            .primary_idle_connections
            .set(primary_idle as i64);
        DB_POOL_METRICS
            .primary_active_connections
            .set((primary_size.saturating_sub(primary_idle)) as i64);

        // Replica pool metrics
        for (idx, replica) in self.replicas.iter().enumerate() {
            let idx_str = idx.to_string();
            let replica_size = replica.size() as usize;
            let replica_idle = replica.num_idle();
            DB_POOL_METRICS
                .replica_idle_connections
                .with_label_values(&[&idx_str])
                .set(replica_idle as i64);
            DB_POOL_METRICS
                .replica_active_connections
                .with_label_values(&[&idx_str])
                .set((replica_size.saturating_sub(replica_idle)) as i64);
        }
    }

    /// Spawn a background task to update metrics periodically
    pub fn spawn_metrics_updater(self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                self.update_metrics();
            }
        });
    }
}

// Made with Bob
