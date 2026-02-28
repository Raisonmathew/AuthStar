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
//! ### Infrastructure
//! - `db_pool_size` — gauge (current pool size)
//! - `db_pool_idle` — gauge (idle connections)

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics_exporter_prometheus::PrometheusHandle;

/// Axum handler: render the current Prometheus metrics snapshot.
///
/// The `PrometheusHandle` is stored in `AppState` and passed here via
/// `axum::Extension`. It renders all registered metrics in the standard
/// Prometheus text format (Content-Type: text/plain; version=0.0.4).
pub async fn metrics_handler(
    axum::Extension(handle): axum::Extension<PrometheusHandle>,
) -> Response {
    let body = handle.render();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

// Made with Bob
