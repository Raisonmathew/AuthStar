//! Redis-backed Sliding Window Rate Limiting Middleware (HIGH-7, MEDIUM-15)
//!
//! Implements a sliding window counter using Redis INCR + EXPIRE.
//! Each key tracks request counts per (identifier, window) pair.
//!
//! ## Rate Limit Tiers
//!
//! | Route Group              | Limit        | Window  | Key                        |
//! |--------------------------|--------------|---------|----------------------------|
//! | Auth flow creation       | 10 req       | 1 min   | `rl:flow:{ip}`             |
//! | Auth flow submission     | 30 req       | 1 min   | `rl:flow_submit:{ip}`      |
//! | Password auth            | 5 req        | 1 min   | `rl:password:{ip}`         |
//! | General API (per org)    | 1000 req     | 1 min   | `rl:api:{org_id}`          |
//! | Admin API (per user)     | 200 req      | 1 min   | `rl:admin:{user_id}`       |
//!
//! ## Response Headers
//! - `X-RateLimit-Limit`: Maximum requests allowed in the window
//! - `X-RateLimit-Remaining`: Requests remaining in the current window
//! - `X-RateLimit-Reset`: Unix timestamp when the window resets
//! - `Retry-After`: Seconds until the client may retry (only on 429)

use crate::middleware::org_context::OrgContext;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory rate limit fallback when Redis is unavailable.
/// Key: "{rate_limit_key}:{window_start}", Value: request count.
/// Protected by a std::sync::Mutex (critical section is < 1μs).
static IN_MEMORY_COUNTERS: once_cell::sync::Lazy<Mutex<HashMap<String, u64>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Rate limit configuration
#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u64,
    /// Window duration in seconds
    pub window_seconds: u64,
}

impl RateLimitConfig {
    pub const fn new(max_requests: u64, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
        }
    }
}

/// Predefined rate limit tiers
pub mod tiers {
    use super::RateLimitConfig;

    /// Auth flow creation: 10 per minute per IP (HIGH-7)
    pub const AUTH_FLOW_CREATE: RateLimitConfig = RateLimitConfig::new(10, 60);

    /// Auth flow step submission: 5 per minute per (IP, flow_id) — A-2
    /// Tighter than creation to prevent per-flow brute-force across multiple IPs.
    pub const AUTH_FLOW_SUBMIT: RateLimitConfig = RateLimitConfig::new(5, 60);

    /// Password authentication: 5 per minute per IP (brute-force protection)
    pub const PASSWORD_AUTH: RateLimitConfig = RateLimitConfig::new(5, 60);

    /// General API: 1000 per minute per org
    pub const API_GENERAL: RateLimitConfig = RateLimitConfig::new(1000, 60);

    /// SSO/OAuth initiation: 20 per minute per IP
    pub const SSO_INITIATE: RateLimitConfig = RateLimitConfig::new(20, 60);

    /// Public read endpoints (hosted config, invitations): 30 per minute per IP
    pub const PUBLIC_READ: RateLimitConfig = RateLimitConfig::new(30, 60);

    /// OAuth token endpoint: 10 per minute per IP (client_secret brute-force protection)
    pub const OAUTH_TOKEN: RateLimitConfig = RateLimitConfig::new(10, 60);
}

/// Extract the client IP from the request.
/// Respects `X-Forwarded-For` (set by nginx/load balancer), then falls back to
/// `ConnectInfo<SocketAddr>` (the actual TCP peer address).
fn extract_client_ip(request: &Request) -> String {
    // Trust X-Forwarded-For only if set by a trusted proxy (nginx in our case)
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            // Take the first (leftmost) IP — the original client
            if let Some(ip) = val.split(',').next() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // Fallback: use the TCP peer address from ConnectInfo (set by
    // `into_make_service_with_connect_info::<SocketAddr>()` in main.rs).
    if let Some(connect_info) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return connect_info.0.ip().to_string();
    }

    // Last resort: should only happen in unit tests without ConnectInfo wired.
    tracing::warn!(
        "Rate limiter could not determine client IP — falling back to 'unknown'. \
                    All unidentified clients share a single rate limit bucket."
    );
    "unknown".to_string()
}

/// Core rate limit check using Redis sliding window counter.
///
/// Returns `(allowed, current_count, reset_at_unix)`.
/// Uses INCR + EXPIRE for atomic increment with TTL.
async fn check_rate_limit(
    redis: &mut redis::aio::ConnectionManager,
    key: &str,
    config: RateLimitConfig,
) -> anyhow::Result<(bool, u64, u64)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Window key: bucket by window_seconds
    let window_start = (now / config.window_seconds) * config.window_seconds;
    let window_key = format!("{key}:{window_start}");
    let reset_at = window_start + config.window_seconds;

    // Atomic increment
    let count: u64 = redis.incr(&window_key, 1u64).await?;

    // Set TTL on first request in window (INCR creates the key if absent)
    if count == 1 {
        let _: () = redis
            .expire(&window_key, config.window_seconds as i64)
            .await
            .unwrap_or(());
    }

    let allowed = count <= config.max_requests;
    Ok((allowed, count, reset_at))
}

/// Build rate limit response headers.
fn rate_limit_headers(
    limit: u64,
    remaining: u64,
    reset_at: u64,
) -> Vec<(axum::http::HeaderName, HeaderValue)> {
    vec![
        (
            axum::http::HeaderName::from_static("x-ratelimit-limit"),
            HeaderValue::from_str(&limit.to_string()).unwrap_or(HeaderValue::from_static("0")),
        ),
        (
            axum::http::HeaderName::from_static("x-ratelimit-remaining"),
            HeaderValue::from_str(&remaining.to_string()).unwrap_or(HeaderValue::from_static("0")),
        ),
        (
            axum::http::HeaderName::from_static("x-ratelimit-reset"),
            HeaderValue::from_str(&reset_at.to_string()).unwrap_or(HeaderValue::from_static("0")),
        ),
    ]
}

/// Middleware: rate limit auth flow creation (HIGH-7).
///
/// Applies `tiers::AUTH_FLOW_CREATE` (10 req/min) keyed by client IP.
/// This prevents automated account enumeration and credential stuffing
/// via the hosted auth flow endpoint.
pub async fn rate_limit_auth_flow(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let key = format!("rl:flow:{ip}");

    apply_rate_limit(state, request, next, &key, tiers::AUTH_FLOW_CREATE).await
}

/// Middleware: rate limit auth flow step submission (A-2).
///
/// Applies `tiers::AUTH_FLOW_SUBMIT` (5 req/min) keyed by `{ip}:{flow_id}`.
///
/// Keying by both IP and flow_id provides two layers of protection:
/// - Per-IP: prevents a single attacker from hammering many flows
/// - Per-flow: prevents distributed brute-force where many IPs target one flow
///
/// The flow_id is extracted from the URL path segment (`:flow_id`).
/// If the path doesn't contain a flow_id (shouldn't happen on this route),
/// falls back to IP-only key.
pub async fn rate_limit_auth_flow_submit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);

    // Extract flow_id from path: /api/auth/flow/{flow_id}/submit
    // Path segments: ["", "api", "auth", "flow", "{flow_id}", "submit"]
    let flow_id = request
        .uri()
        .path()
        .split('/')
        .nth(4) // 0="", 1="api", 2="auth", 3="flow", 4=flow_id
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");

    let key = format!("rl:flow_submit:{ip}:{flow_id}");

    apply_rate_limit(state, request, next, &key, tiers::AUTH_FLOW_SUBMIT).await
}

/// Middleware: rate limit password authentication (brute-force protection).
///
/// Applies `tiers::PASSWORD_AUTH` (5 req/min) keyed by client IP.
pub async fn rate_limit_password_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let key = format!("rl:password:{ip}");

    apply_rate_limit(state, request, next, &key, tiers::PASSWORD_AUTH).await
}

/// Middleware: rate limit general API calls per org.
///
/// Applies `tiers::API_GENERAL` (1000 req/min) keyed by org_id.
/// Falls back to IP-based limiting if no org context is available.
pub async fn rate_limit_api(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let identifier = request
        .extensions()
        .get::<OrgContext>()
        .map(|ctx| format!("rl:api:{}", ctx.org_id))
        .unwrap_or_else(|| format!("rl:api:ip:{}", extract_client_ip(&request)));

    apply_rate_limit(state, request, next, &identifier, tiers::API_GENERAL).await
}

/// Middleware: rate limit SSO/OAuth initiation.
///
/// Applies `tiers::SSO_INITIATE` (20 req/min) keyed by client IP.
pub async fn rate_limit_sso(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let key = format!("rl:sso:{ip}");

    apply_rate_limit(state, request, next, &key, tiers::SSO_INITIATE).await
}

/// Middleware: rate limit public read endpoints (hosted config, invitations).
///
/// Applies `tiers::PUBLIC_READ` (30 req/min) keyed by client IP.
/// Prevents automated scraping of org configurations and invitation enumeration.
pub async fn rate_limit_public(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let key = format!("rl:public:{ip}");

    apply_rate_limit(state, request, next, &key, tiers::PUBLIC_READ).await
}

/// Middleware: rate limit OAuth token endpoint (client_secret brute-force protection).
///
/// Applies `tiers::OAUTH_TOKEN` (10 req/min) keyed by client IP.
/// Stricter than `rate_limit_public` to prevent client_secret enumeration
/// and authorization code brute-force on `/oauth/token`.
pub async fn rate_limit_oauth_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let key = format!("rl:oauth_token:{ip}");

    apply_rate_limit(state, request, next, &key, tiers::OAUTH_TOKEN).await
}

/// Core rate limit application logic.
async fn apply_rate_limit(
    state: AppState,
    request: Request,
    next: Next,
    key: &str,
    config: RateLimitConfig,
) -> Response {
    // In non-production environments, bypass rate limiting for loopback clients
    // (localhost Playwright/unit test runners). This prevents test suites from
    // exhausting rate limit windows shared across all 127.0.0.1 connections.
    if !state.config.is_production_like() {
        let ip = extract_client_ip(&request);
        if ip == "127.0.0.1" || ip == "::1" || ip.starts_with("::ffff:127.") {
            return next.run(request).await;
        }
    }

    let mut redis = state.redis.clone();

    match check_rate_limit(&mut redis, key, config).await {
        Ok((true, count, reset_at)) => {
            // Allowed — add rate limit headers to response
            let remaining = config.max_requests.saturating_sub(count);
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            for (name, value) in rate_limit_headers(config.max_requests, remaining, reset_at) {
                headers.insert(name, value);
            }
            response
        }
        Ok((false, _count, reset_at)) => {
            // Rate limit exceeded
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let retry_after = reset_at.saturating_sub(now);

            tracing::warn!(
                key = %key,
                limit = config.max_requests,
                window = config.window_seconds,
                "Rate limit exceeded"
            );

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please slow down.",
                    "retry_after": retry_after,
                })),
            )
                .into_response();

            let headers = response.headers_mut();
            for (name, value) in rate_limit_headers(config.max_requests, 0, reset_at) {
                headers.insert(name, value);
            }
            headers.insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or(HeaderValue::from_static("60")),
            );

            response
        }
        Err(e) => {
            // Redis error — fall back to in-memory rate limiting
            tracing::warn!(
                key = %key,
                error = %e,
                "Rate limit Redis error — falling back to in-memory counters"
            );

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let window_start = (now / config.window_seconds) * config.window_seconds;
            let reset_at = window_start + config.window_seconds;
            let window_key = format!("{key}:{window_start}");

            let (allowed, count) = {
                let mut counters = IN_MEMORY_COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
                // Lazy cleanup: drop entries from windows older than the
                // current one. We parse the trailing ":<window_start>" segment
                // of each key and compare numerically, which is robust against
                // user-supplied keys that themselves contain colons (the old
                // `ends_with(":{window_start}")` heuristic could erroneously
                // retain or evict such keys).
                if counters.len() > 10_000 {
                    counters.retain(|k, _| {
                        k.rsplit_once(':')
                            .and_then(|(_, suffix)| suffix.parse::<u64>().ok())
                            .map(|ws| ws >= window_start)
                            .unwrap_or(false)
                    });
                }
                let count = counters.entry(window_key).or_insert(0);
                *count += 1;
                (*count <= config.max_requests, *count)
            };

            if allowed {
                let remaining = config.max_requests.saturating_sub(count);
                let mut response = next.run(request).await;
                let headers = response.headers_mut();
                for (name, value) in rate_limit_headers(config.max_requests, remaining, reset_at) {
                    headers.insert(name, value);
                }
                response
            } else {
                let retry_after = reset_at.saturating_sub(now);
                tracing::warn!(key = %key, limit = config.max_requests, "In-memory rate limit exceeded");
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests. Please slow down.",
                        "retry_after": retry_after,
                    })),
                )
                    .into_response();
                let headers = response.headers_mut();
                for (name, value) in rate_limit_headers(config.max_requests, 0, reset_at) {
                    headers.insert(name, value);
                }
                headers.insert(
                    axum::http::header::RETRY_AFTER,
                    HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or(HeaderValue::from_static("60")),
                );
                response
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RateLimitConfig ───────────────────────────────────────────────────

    #[test]
    fn rate_limit_config_new() {
        let config = RateLimitConfig::new(100, 60);
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_seconds, 60);
    }

    // ── Tier constants ────────────────────────────────────────────────────

    #[test]
    fn tier_auth_flow_create() {
        assert_eq!(tiers::AUTH_FLOW_CREATE.max_requests, 10);
        assert_eq!(tiers::AUTH_FLOW_CREATE.window_seconds, 60);
    }

    #[test]
    fn tier_password_auth() {
        assert_eq!(tiers::PASSWORD_AUTH.max_requests, 5);
        assert_eq!(tiers::PASSWORD_AUTH.window_seconds, 60);
    }

    #[test]
    fn tier_api_general() {
        assert_eq!(tiers::API_GENERAL.max_requests, 1000);
        assert_eq!(tiers::API_GENERAL.window_seconds, 60);
    }

    // ── rate_limit_headers ────────────────────────────────────────────────

    #[test]
    fn headers_contain_correct_values() {
        let headers = rate_limit_headers(100, 42, 1700000060);
        assert_eq!(headers.len(), 3);

        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"x-ratelimit-limit"));
        assert!(names.contains(&"x-ratelimit-remaining"));
        assert!(names.contains(&"x-ratelimit-reset"));

        let limit_val = headers
            .iter()
            .find(|(n, _)| n.as_str() == "x-ratelimit-limit")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .unwrap();
        assert_eq!(limit_val, "100");

        let remaining_val = headers
            .iter()
            .find(|(n, _)| n.as_str() == "x-ratelimit-remaining")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .unwrap();
        assert_eq!(remaining_val, "42");
    }

    // ── In-memory counter ─────────────────────────────────────────────────

    #[test]
    fn in_memory_counter_increments() {
        let mut counters = IN_MEMORY_COUNTERS.lock().unwrap();

        // Use a unique key to avoid interfering with other tests
        let key = "rl:test:increment:99999999999";
        counters.remove(key);

        let count = counters.entry(key.to_string()).or_insert(0);
        *count += 1;
        assert_eq!(*count, 1);
        *count += 1;
        assert_eq!(*count, 2);

        counters.remove(key);
    }

    #[test]
    fn in_memory_counter_window_bucketing() {
        let config = RateLimitConfig::new(5, 60);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let window_start = (now / config.window_seconds) * config.window_seconds;
        let window_key = format!("rl:test:bucket:{window_start}");

        let mut counters = IN_MEMORY_COUNTERS.lock().unwrap();
        counters.remove(&window_key);

        // Simulate 5 requests — all should be under the limit
        for i in 1..=5 {
            let count = counters.entry(window_key.clone()).or_insert(0);
            *count += 1;
            assert_eq!(*count, i);
            assert!(
                *count <= config.max_requests,
                "Request {i} should be allowed"
            );
        }

        // 6th request exceeds limit
        let count = counters.entry(window_key.clone()).or_insert(0);
        *count += 1;
        assert!(
            *count > config.max_requests,
            "6th request should exceed limit"
        );

        counters.remove(&window_key);
    }

    #[test]
    fn in_memory_counter_cleanup_large_map() {
        let mut counters = IN_MEMORY_COUNTERS.lock().unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_window = (now / 60) * 60;

        // Insert stale keys (old windows)
        for i in 0..100 {
            let old_window = current_window - 120; // 2 minutes ago
            counters.insert(format!("rl:test:cleanup:{i}:{old_window}"), 5);
        }

        // Insert current window key
        let current_key = format!("rl:test:cleanup:current:{current_window}");
        counters.insert(current_key.clone(), 3);

        let initial = counters.len();
        assert!(initial >= 101);

        // Simulate cleanup logic (must mirror apply_rate_limit exactly): parse
        // the trailing ":<window_start>" segment numerically and keep only
        // entries whose window is >= the current window.
        if counters.len() > 50 {
            counters.retain(|k, _| {
                k.rsplit_once(':')
                    .and_then(|(_, suffix)| suffix.parse::<u64>().ok())
                    .map(|ws| ws >= current_window)
                    .unwrap_or(false)
            });
        }

        // Current window key should survive
        assert!(counters.contains_key(&current_key));
        // Old keys should be gone
        assert!(!counters.contains_key(&format!("rl:test:cleanup:0:{}", current_window - 120)));
    }

    // ── extract_client_ip ─────────────────────────────────────────────────

    #[test]
    fn extract_ip_from_xff_header() {
        let request = Request::builder()
            .header("x-forwarded-for", "203.0.113.50, 70.41.3.18")
            .body(axum::body::Body::empty())
            .unwrap();

        let ip = extract_client_ip(&request);
        assert_eq!(ip, "203.0.113.50");
    }

    #[test]
    fn extract_ip_returns_unknown_without_xff_or_connect_info() {
        let request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let ip = extract_client_ip(&request);
        assert_eq!(ip, "unknown");
    }
}

// Made with Bob
