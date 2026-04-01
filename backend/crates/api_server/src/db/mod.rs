//! Database connection management with read replica support
//!
//! This module provides:
//! - Primary pool for write operations
//! - Read replica pools for read-heavy queries
//! - Automatic load balancing across replicas (round-robin)
//! - Connection pool metrics (Prometheus)
//! - Graceful degradation (falls back to primary if replicas unavailable)

pub mod pool_manager;
pub mod metrics;

pub use pool_manager::{DatabasePools, PoolType};
pub use metrics::DB_POOL_METRICS;

// Made with Bob
