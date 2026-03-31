//! D-2: HTTP Metrics Middleware
//!
//! Tower middleware that records per-request Prometheus metrics using the
//! `metrics` crate facade. The actual storage and rendering is handled by
//! the `PrometheusRecorder` installed in `main.rs`.
//!
//! ## Metrics recorded per request
//!
//! | Metric | Type | Labels |
//! |--------|------|--------|
//! | `http_requests_total` | Counter | method, path, status |
//! | `http_request_duration_seconds` | Histogram | method, path, status |
//! | `http_requests_in_flight` | Gauge | method, path |
//!
//! ## Path normalization
//!
//! Raw paths like `/api/v1/flows/flow_abc123/submit` are normalized to
//! `/api/v1/flows/:flow_id/submit` to prevent cardinality explosion.
//! The normalization rules are applied in `normalize_path()`.

use axum::{
    body::Body,
    extract::MatchedPath,
    http::{Request, Response},
    middleware::Next,
};
use std::time::Instant;

/// RAII guard that decrements the in-flight gauge on drop (including panics).
/// Without this, a panic in a downstream handler would leave the gauge permanently
/// elevated, causing misleading monitoring alerts and capacity calculations.
struct InFlightGuard {
    method: String,
    path: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        metrics::gauge!(
            "http_requests_in_flight",
            "method" => self.method.clone(),
            "path" => self.path.clone(),
        )
        .decrement(1.0);
    }
}

/// Axum `from_fn` middleware — records HTTP metrics for every request.
///
/// Usage in router.rs:
/// ```rust,ignore
/// use axum::middleware::from_fn;
/// use crate::middleware::metrics_middleware::track_metrics;
///
/// let app = Router::new()
///     // ... routes ...
///     .layer(from_fn(track_metrics));
/// ```
pub async fn track_metrics(
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = req.method().to_string();

    // Use the matched route pattern (e.g. "/api/v1/flows/:flow_id/submit")
    // rather than the raw path to avoid cardinality explosion.
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| normalize_path(req.uri().path()));

    // Increment in-flight gauge before processing.
    // The RAII guard ensures decrement on drop (including panics).
    metrics::gauge!("http_requests_in_flight", "method" => method.clone(), "path" => path.clone())
        .increment(1.0);
    let _in_flight = InFlightGuard {
        method: method.clone(),
        path: path.clone(),
    };

    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();

    // Guard is dropped at end of scope (or on panic), decrementing the gauge.

    let status = response.status().as_u16().to_string();

    // Increment request counter
    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status.clone(),
    )
    .increment(1);

    // Record request duration histogram
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "path" => path,
        "status" => status,
    )
    .record(elapsed);

    response
}

/// Normalize a raw URI path to a low-cardinality label value.
///
/// Replaces path segments that look like IDs (prefixed IDs, UUIDs, numeric IDs)
/// with placeholder tokens so Prometheus doesn't create a new time series for
/// every unique resource ID.
///
/// Examples:
/// - `/api/v1/flows/flow_abc123/submit` → `/api/v1/flows/:id/submit`
/// - `/api/v1/users/usr_xyz789` → `/api/v1/users/:id`
/// - `/api/v1/orgs/550e8400-e29b-41d4-a716-446655440000` → `/api/v1/orgs/:id`
fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.is_empty() {
                return segment.to_owned();
            }
            // Prefixed IDs: flow_abc123, usr_xyz, org_abc, dec_flow_xyz, etc.
            if segment.contains('_') && segment.len() > 8 {
                let parts: Vec<&str> = segment.splitn(2, '_').collect();
                if parts.len() == 2 && parts[0].chars().all(|c| c.is_ascii_alphabetic()) {
                    return ":id".to_owned();
                }
            }
            // UUID v4: 8-4-4-4-12 hex chars
            if is_uuid(segment) {
                return ":id".to_owned();
            }
            // Pure numeric IDs
            if segment.chars().all(|c| c.is_ascii_digit()) && segment.len() > 4 {
                return ":id".to_owned();
            }
            segment.to_owned()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_prefixed_id() {
        assert_eq!(
            normalize_path("/api/v1/flows/flow_abc123xyz/submit"),
            "/api/v1/flows/:id/submit"
        );
    }

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path("/api/v1/orgs/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v1/orgs/:id"
        );
    }

    #[test]
    fn test_normalize_path_static() {
        assert_eq!(
            normalize_path("/api/v1/health"),
            "/api/v1/health"
        );
    }

    #[test]
    fn test_normalize_path_numeric() {
        assert_eq!(
            normalize_path("/api/v1/items/12345"),
            "/api/v1/items/:id"
        );
    }
}

// Made with Bob
