//! D-2: Prometheus Metrics Scrape Endpoint
//!
//! Exposes `GET /metrics` in the standard Prometheus text exposition format.
//! This endpoint is intentionally unauthenticated — it should be protected at
//! the network layer (Kubernetes NetworkPolicy / nginx `allow` directive) so
//! only the Prometheus scraper can reach it.
//!
//! ## Metrics exposed
//!
//! ### HTTP layer (recorded by `metrics_middleware`)
//! - `http_requests_total{method, path, status}` — counter
//! - `http_request_duration_seconds{method, path, status}` — histogram
//! - `http_requests_in_flight{method, path}` — gauge
//!
//! ### EIAA / auth layer (recorded at call sites)
//! - `auth_flow_initiated_total{org_id}` — counter
//! - `auth_flow_completed_total{org_id, aal}` — counter
//! - `auth_flow_expired_total` — counter
//! - `auth_step_failed_total{capability}` — counter
//! - `circuit_breaker_open` — gauge (1 = open, 0 = closed)
//!
//! ### Audit Writer (GAP-2 FIX — recorded by `services/audit_writer.rs`)
//!
//! These metrics surface the audit writer's internal backpressure state to
//! Prometheus so that silent audit record loss is detectable in Grafana/PagerDuty.
//!
//! | Metric | Type | Alert threshold |
//! |--------|------|-----------------|
//! | `audit_writer_dropped_total` | Counter | > 0 for 1m → PAGE |
//! | `audit_writer_channel_pending` | Gauge | > 8000 for 1m → WARN |
//! | `audit_writer_channel_fill_pct` | Gauge | > 80% for 1m → WARN; > 95% for 30s → CRIT |
//! | `audit_writer_flush_total` | Counter | — (throughput tracking) |
//! | `audit_writer_flush_errors_total` | Counter | > 0 for 1m → WARN |
//! | `audit_writer_flush_duration_seconds` | Histogram | p99 > 1s → WARN |
//!
//! The channel fill gauges are updated every 10 seconds by the backpressure
//! monitor background task. The drop counter is incremented on every dropped
//! record (immediately visible). Flush metrics are recorded per DB batch write.
//!
//! ### Infrastructure
//! - `db_pool_size` — gauge (current pool size)
//! - `db_pool_idle` — gauge (idle connections)

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics_exporter_prometheus::PrometheusHandle;
use prometheus::{Encoder, TextEncoder};

/// Axum handler: render the current Prometheus metrics snapshot.
///
/// The `PrometheusHandle` is stored in `AppState` and passed here via
/// `axum::Extension`. It renders all registered metrics in the standard
/// Prometheus text format (Content-Type: text/plain; version=0.0.4).
///
/// Also includes metrics from the `prometheus` crate's default registry
/// (DB pool metrics, cache invalidation metrics) which use that crate directly.
pub async fn metrics_handler(
    axum::Extension(handle): axum::Extension<PrometheusHandle>,
) -> Response {
    // Render metrics-crate metrics (HTTP layer, auth counters, etc.)
    let mut body = handle.render();

    // Also render prometheus-crate metrics (db pool, cache invalidation, etc.)
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut prom_buf = Vec::new();
    if encoder.encode(&metric_families, &mut prom_buf).is_ok() {
        if let Ok(prom_text) = String::from_utf8(prom_buf) {
            body.push_str(&prom_text);
        }
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

// Made with Bob
