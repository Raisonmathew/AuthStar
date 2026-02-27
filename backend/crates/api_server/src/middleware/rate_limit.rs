//! IP-Based Rate Limiting Middleware
//!
//! Provides configurable rate limiting using the `governor` crate.
//! Different rate limits can be applied to different endpoint categories.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
    middleware::Next,
};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;

/// Rate limiter configuration
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Requests per period
    pub requests_per_period: u32,
    /// Period duration
    pub period: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_period: 100,
            period: Duration::from_secs(60),
        }
    }
}

#[allow(dead_code)]
impl RateLimitConfig {
    pub fn strict() -> Self {
        Self {
            requests_per_period: 10,
            period: Duration::from_secs(60),
        }
    }

    pub fn moderate() -> Self {
        Self {
            requests_per_period: 60,
            period: Duration::from_secs(60),
        }
    }

    pub fn relaxed() -> Self {
        Self {
            requests_per_period: 200,
            period: Duration::from_secs(60),
        }
    }
}

/// Per-IP rate limiter state
#[allow(dead_code)]
pub type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Rate limiter store (per-IP)
#[derive(Clone)]
pub struct RateLimiterStore {
    limiters: Arc<RwLock<HashMap<String, Arc<IpRateLimiter>>>>,
    config: RateLimitConfig,
}

impl RateLimiterStore {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or create a rate limiter for an IP
    async fn get_limiter(&self, ip: &str) -> Arc<IpRateLimiter> {
        // Try read lock first
        {
            let limiters = self.limiters.read().await;
            if let Some(limiter) = limiters.get(ip) {
                return Arc::clone(limiter);
            }
        }

        // Need to create new limiter
        let mut limiters = self.limiters.write().await;
        
        // Double-check after acquiring write lock
        if let Some(limiter) = limiters.get(ip) {
            return Arc::clone(limiter);
        }

        let quota = Quota::with_period(self.config.period)
            .unwrap()
            .allow_burst(NonZeroU32::new(self.config.requests_per_period).unwrap());

        let limiter = Arc::new(RateLimiter::direct(quota));
        limiters.insert(ip.to_string(), Arc::clone(&limiter));
        limiter
    }

    /// Check if request is allowed
    pub async fn check(&self, ip: &str) -> bool {
        let limiter = self.get_limiter(ip).await;
        limiter.check().is_ok()
    }

    /// Clean up old entries (call periodically)
    #[allow(dead_code)]
    pub async fn cleanup(&self) {
        let mut limiters = self.limiters.write().await;
        // Keep only entries that have been used recently
        // For simplicity, this just clears entries over a threshold
        if limiters.len() > 10000 {
            limiters.clear();
        }
    }
}

/// Rate limiting middleware for auth endpoints (strict: 10/min)
#[allow(dead_code)]
pub async fn rate_limit_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    // Use a static store for auth endpoints
    static AUTH_STORE: std::sync::OnceLock<RateLimiterStore> = std::sync::OnceLock::new();
    let store = AUTH_STORE.get_or_init(|| RateLimiterStore::new(RateLimitConfig::strict()));

    let ip = addr.ip().to_string();
    
    if !store.check(&ip).await {
        tracing::warn!(ip = %ip, "Rate limit exceeded for auth endpoint");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.".to_string(),
        ));
    }

    Ok(next.run(request).await)
}

/// Rate limiting middleware for API endpoints (moderate: 60/min)
#[allow(dead_code)]
pub async fn rate_limit_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    static API_STORE: std::sync::OnceLock<RateLimiterStore> = std::sync::OnceLock::new();
    let store = API_STORE.get_or_init(|| RateLimiterStore::new(RateLimitConfig::moderate()));

    let ip = addr.ip().to_string();
    
    if !store.check(&ip).await {
        tracing::warn!(ip = %ip, "Rate limit exceeded for API endpoint");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.".to_string(),
        ));
    }

    Ok(next.run(request).await)
}

/// Rate limiting middleware for public endpoints (relaxed: 200/min)
#[allow(dead_code)]
pub async fn rate_limit_public(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    static PUBLIC_STORE: std::sync::OnceLock<RateLimiterStore> = std::sync::OnceLock::new();
    let store = PUBLIC_STORE.get_or_init(|| RateLimiterStore::new(RateLimitConfig::relaxed()));

    let ip = addr.ip().to_string();
    
    if !store.check(&ip).await {
        tracing::warn!(ip = %ip, "Rate limit exceeded for public endpoint");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.".to_string(),
        ));
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_store() {
        let store = RateLimiterStore::new(RateLimitConfig {
            requests_per_period: 3,
            period: Duration::from_secs(60),
        });

        let ip = "127.0.0.1";

        // First 3 requests should pass
        assert!(store.check(ip).await);
        assert!(store.check(ip).await);
        assert!(store.check(ip).await);

        // 4th request should be rate limited
        assert!(!store.check(ip).await);
    }
}
