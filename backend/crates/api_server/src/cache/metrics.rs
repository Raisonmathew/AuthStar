//! Cache Invalidation Metrics
//!
//! Prometheus metrics for monitoring distributed cache invalidation performance
//! and health.

use once_cell::sync::Lazy;
use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};

/// Cache invalidation metrics
pub struct CacheMetrics {
    /// Total number of invalidation messages published
    pub invalidation_published: IntCounter,

    /// Total number of invalidation messages received
    pub invalidation_received: IntCounter,

    /// Total number of invalidation errors
    pub invalidation_errors: IntCounter,

    /// Latency of cache invalidation propagation (seconds)
    pub invalidation_latency: Histogram,
}

impl CacheMetrics {
    fn new() -> Self {
        Self {
            invalidation_published: register_int_counter!(
                "cache_invalidation_published_total",
                "Total number of cache invalidation messages published"
            )
            .unwrap(),

            invalidation_received: register_int_counter!(
                "cache_invalidation_received_total",
                "Total number of cache invalidation messages received"
            )
            .unwrap(),

            invalidation_errors: register_int_counter!(
                "cache_invalidation_errors_total",
                "Total number of cache invalidation errors"
            )
            .unwrap(),

            invalidation_latency: register_histogram!(
                "cache_invalidation_latency_seconds",
                "Latency of cache invalidation propagation across replicas",
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
            )
            .unwrap(),
        }
    }
}

/// Global cache metrics instance
pub static CACHE_METRICS: Lazy<CacheMetrics> = Lazy::new(CacheMetrics::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        // Verify metrics can be accessed
        let _ = &CACHE_METRICS.invalidation_published;
        let _ = &CACHE_METRICS.invalidation_received;
        let _ = &CACHE_METRICS.invalidation_errors;
        let _ = &CACHE_METRICS.invalidation_latency;
    }
}

// Made with Bob
