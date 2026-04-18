//! HaveIBeenPwned k-Anonymity Client
//!
//! Checks passwords against the HIBP Pwned Passwords API using the
//! k-Anonymity range model:
//!
//! 1. SHA-1 hash the password
//! 2. Send only the first 5 hex characters to the API
//! 3. API returns all suffixes matching that prefix
//! 4. Check locally if our full hash is in the returned list
//!
//! This design ensures the full password hash never leaves the server.
//! See: <https://haveibeenpwned.com/API/v3#PwnedPasswords>

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Cached prefix → (suffix_uppercase → count)
#[derive(Clone)]
struct CacheEntry {
    suffixes: HashMap<String, u64>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// HIBP Pwned Passwords client with prefix caching.
#[derive(Clone)]
pub struct HibpClient {
    http: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
    enabled: bool,
}

impl HibpClient {
    /// Create a new HIBP client.
    pub fn new(enabled: bool) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("IDaaS-BreachedPasswordCheck/1.0")
            .build()
            .expect("Failed to build HIBP HTTP client");

        Self {
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(3600), // 1 hour cache (breach data changes slowly)
            enabled,
        }
    }

    /// Create a disabled client (always returns 0).
    pub fn disabled() -> Self {
        Self::new(false)
    }

    /// Check if a password appears in the HIBP database.
    /// Returns the number of times it was found (0 = not breached).
    pub async fn check_password(&self, password: &str) -> u64 {
        if !self.enabled {
            return 0;
        }

        let hash = sha1_hex(password);
        let prefix = &hash[..5];
        let suffix = &hash[5..];

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(prefix) {
                if entry.expires_at > chrono::Utc::now() {
                    return entry.suffixes.get(suffix).copied().unwrap_or(0);
                }
            }
        }

        // Fetch from API
        match self.fetch_range(prefix).await {
            Ok(suffixes) => {
                let count = suffixes.get(suffix).copied().unwrap_or(0);

                // Cache the result
                let entry = CacheEntry {
                    suffixes,
                    expires_at: chrono::Utc::now()
                        + chrono::Duration::from_std(self.cache_ttl)
                            .unwrap_or(chrono::Duration::hours(1)),
                };

                let mut cache = self.cache.write().await;
                // LRU pruning: if cache exceeds 5000 prefixes, clear older entries
                if cache.len() > 5000 {
                    let now = chrono::Utc::now();
                    cache.retain(|_, v| v.expires_at > now);
                }
                cache.insert(prefix.to_string(), entry);

                count
            }
            Err(e) => {
                warn!("HIBP API request failed for prefix {prefix}: {e}");
                // Fail open: if we can't reach HIBP, don't block the user
                0
            }
        }
    }

    /// Fetch all suffixes for a given 5-char SHA-1 prefix.
    async fn fetch_range(&self, prefix: &str) -> anyhow::Result<HashMap<String, u64>> {
        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

        let response = self
            .http
            .get(&url)
            .header("Add-Padding", "true") // Padding prevents response-length analysis
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        debug!("HIBP range/{prefix}: {} bytes", response.len());

        let mut suffixes = HashMap::new();
        for line in response.lines() {
            // Format: SUFFIX:COUNT
            if let Some((suffix, count_str)) = line.split_once(':') {
                let count: u64 = count_str.trim().parse().unwrap_or(0);
                // Skip padded entries (count = 0)
                if count > 0 {
                    suffixes.insert(suffix.to_uppercase(), count);
                }
            }
        }

        Ok(suffixes)
    }
}

/// SHA-1 hash a password and return uppercase hex.
fn sha1_hex(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode_upper(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hex_known_value() {
        // "password" → 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn test_prefix_suffix_split() {
        let hash = sha1_hex("password");
        assert_eq!(&hash[..5], "5BAA6");
        assert_eq!(&hash[5..], "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }
}
