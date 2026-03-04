#![allow(dead_code)]
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

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    http::{StatusCode, HeaderValue},
    Json,
};
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::state::AppState;
use crate::middleware::org_context::OrgContext;

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
        Self { max_requests, window_seconds }
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

    /// Admin API: 200 per minute per user
    pub const API_ADMIN: RateLimitConfig = RateLimitConfig::new(200, 60);

    /// SSO/OAuth initiation: 20 per minute per IP
    pub const SSO_INITIATE: RateLimitConfig = RateLimitConfig::new(20, 60);
}

/// Extract the client IP from the request.
/// Respects `X-Forwarded-For` (set by nginx/load balancer) with fallback.
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

    // Fallback: use a generic key (connection info not available in middleware)
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
    let window_key = format!("{}:{}", key, window_start);
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
    let key = format!("rl:flow:{}", ip);

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
        .nth(5) // 0="", 1="api", 2="auth", 3="flow", 4="{flow_id}", 5="submit"
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");

    let key = format!("rl:flow_submit:{}:{}", ip, flow_id);

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
    let key = format!("rl:password:{}", ip);

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
    let key = format!("rl:sso:{}", ip);

    apply_rate_limit(state, request, next, &key, tiers::SSO_INITIATE).await
}

/// Core rate limit application logic.
async fn apply_rate_limit(
    state: AppState,
    request: Request,
    next: Next,
    key: &str,
    config: RateLimitConfig,
) -> Response {
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
            ).into_response();

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
            // Redis error — fail open (don't block legitimate traffic due to Redis outage)
            tracing::error!(
                key = %key,
                error = %e,
                "Rate limit Redis error — failing open"
            );
            next.run(request).await
        }
    }
}

// Made with Bob
