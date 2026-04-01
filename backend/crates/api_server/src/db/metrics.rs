//! Prometheus metrics for database connection pools

use once_cell::sync::Lazy;
use prometheus::{IntGauge, IntGaugeVec, Opts, Registry};

pub struct DbPoolMetrics {
    /// Number of idle connections in the primary pool
    pub primary_idle_connections: IntGauge,
    /// Number of active connections in the primary pool
    pub primary_active_connections: IntGauge,
    /// Number of idle connections per read replica
    pub replica_idle_connections: IntGaugeVec,
    /// Number of active connections per read replica
    pub replica_active_connections: IntGaugeVec,
    /// Total queries routed to primary
    pub primary_queries_total: IntGauge,
    /// Total queries routed to replicas
    pub replica_queries_total: IntGaugeVec,
}

impl DbPoolMetrics {
    pub fn new() -> Self {
        Self {
            primary_idle_connections: IntGauge::with_opts(
                Opts::new(
                    "db_pool_primary_idle_connections",
                    "Number of idle connections in the primary database pool",
                )
            )
            .unwrap(),
            primary_active_connections: IntGauge::with_opts(
                Opts::new(
                    "db_pool_primary_active_connections",
                    "Number of active connections in the primary database pool",
                )
            )
            .unwrap(),
            replica_idle_connections: IntGaugeVec::new(
                Opts::new(
                    "db_pool_replica_idle_connections",
                    "Number of idle connections per read replica pool",
                ),
                &["replica_index"],
            )
            .unwrap(),
            replica_active_connections: IntGaugeVec::new(
                Opts::new(
                    "db_pool_replica_active_connections",
                    "Number of active connections per read replica pool",
                ),
                &["replica_index"],
            )
            .unwrap(),
            primary_queries_total: IntGauge::with_opts(
                Opts::new(
                    "db_pool_primary_queries_total",
                    "Total number of queries routed to primary database",
                )
            )
            .unwrap(),
            replica_queries_total: IntGaugeVec::new(
                Opts::new(
                    "db_pool_replica_queries_total",
                    "Total number of queries routed to read replicas",
                ),
                &["replica_index"],
            )
            .unwrap(),
        }
    }

    pub fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.primary_idle_connections.clone()))?;
        registry.register(Box::new(self.primary_active_connections.clone()))?;
        registry.register(Box::new(self.replica_idle_connections.clone()))?;
        registry.register(Box::new(self.replica_active_connections.clone()))?;
        registry.register(Box::new(self.primary_queries_total.clone()))?;
        registry.register(Box::new(self.replica_queries_total.clone()))?;
        Ok(())
    }
}

pub static DB_POOL_METRICS: Lazy<DbPoolMetrics> = Lazy::new(DbPoolMetrics::new);

// Made with Bob
