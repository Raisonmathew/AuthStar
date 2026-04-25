//! IPLocate.io Client
//!
//! HTTP client for the IPLocate.io geolocation and threat intelligence API.
//! Free tier: 1,000 requests/day with full feature access.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// IPLocate API response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpLocateResponse {
    pub ip: String,

    // Geolocation
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub continent: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub time_zone: Option<String>,
    pub postal_code: Option<String>,

    // Network
    pub asn: Option<u32>,
    pub org: Option<String>,
    #[serde(default)]
    pub isp: Option<String>,

    // Threat detection
    #[serde(default)]
    pub is_datacenter: Option<bool>,
    #[serde(default)]
    pub is_tor: Option<bool>,
    #[serde(default)]
    pub is_vpn: Option<bool>,
    #[serde(default)]
    pub is_proxy: Option<bool>,
    #[serde(default)]
    pub is_relay: Option<bool>,
    #[serde(default)]
    pub threat_score: Option<u32>,
}

/// Cached entry with expiration
#[derive(Clone)]
struct CacheEntry {
    response: IpLocateResponse,
    expires_at: DateTime<Utc>,
}

/// IPLocate.io client with caching
#[derive(Clone)]
pub struct IpLocateClient {
    http: reqwest::Client,
    api_key: Option<String>,
    base_url: String,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
    enabled: bool,
}

impl IpLocateClient {
    /// Create a new IPLocate client
    pub fn new(api_key: Option<String>, enabled: bool) -> Self {
        // Tight timeouts: GeoIP is on the auth hot path and a slow upstream
        // (or DNS hiccup) used to add up to 5s of latency per request. We
        // fail fast and let the caller fall back to a "no geo" decision.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_millis(1500))
            .build()
            .expect("Failed to build HTTP client");

        let base_url = std::env::var("IPLOCATE_API_URL")
            .unwrap_or_else(|_| "https://www.iplocate.io/api/lookup".to_string());

        Self {
            http,
            api_key,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(600), // 10 minute cache
            enabled,
        }
    }

    /// Create a disabled client (returns None for lookups)
    pub fn disabled() -> Self {
        Self::new(None, false)
    }

    /// Lookup IP address, returns None on error or if disabled
    pub async fn lookup(&self, ip: IpAddr) -> Option<IpLocateResponse> {
        if !self.enabled {
            return None;
        }

        let ip_str = ip.to_string();

        // Check cache first
        if let Some(cached) = self.get_cached(&ip_str).await {
            return Some(cached);
        }

        // Make API request
        match self.fetch_from_api(&ip_str).await {
            Ok(response) => {
                // Cache the response
                self.cache_response(&ip_str, response.clone()).await;
                Some(response)
            }
            Err(e) => {
                tracing::warn!(ip = %ip_str, error = %e, "IPLocate lookup failed");
                None
            }
        }
    }

    async fn get_cached(&self, ip: &str) -> Option<IpLocateResponse> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(ip) {
            if entry.expires_at > Utc::now() {
                return Some(entry.response.clone());
            }
        }
        None
    }

    async fn cache_response(&self, ip: &str, response: IpLocateResponse) {
        let mut cache = self.cache.write().await;
        cache.insert(
            ip.to_string(),
            CacheEntry {
                response,
                expires_at: Utc::now()
                    + chrono::Duration::from_std(self.cache_ttl).unwrap_or_default(),
            },
        );

        // Prune expired entries if cache is large
        if cache.len() > 1000 {
            let now = Utc::now();
            cache.retain(|_, v| v.expires_at > now);
        }
    }

    async fn fetch_from_api(&self, ip: &str) -> Result<IpLocateResponse, reqwest::Error> {
        let mut url = format!("{}/{}", self.base_url, ip);

        // Add API key if available
        if let Some(ref key) = self.api_key {
            url = format!("{url}?apikey={key}");
        }

        let response = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json::<IpLocateResponse>()
            .await?;

        Ok(response)
    }

    /// Check if client is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set params for testing
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }
}

impl Default for IpLocateClient {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_disabled_client_returns_none() {
        let client = IpLocateClient::disabled();
        let ip = IpAddr::from_str("8.8.8.8").unwrap();

        let result = client.lookup(ip).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{
            "ip": "8.8.8.8",
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "asn": 15169,
            "org": "GOOGLE",
            "is_datacenter": true,
            "is_vpn": false,
            "is_proxy": false,
            "is_tor": false
        }"#;

        let response: IpLocateResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.ip, "8.8.8.8");
        assert_eq!(response.country_code, Some("US".to_string()));
        assert_eq!(response.asn, Some(15169));
        assert_eq!(response.is_datacenter, Some(true));
        assert_eq!(response.is_vpn, Some(false));
    }
}
