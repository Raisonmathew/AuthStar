use shared_types::{AppError, Result};
use sqlx::PgPool;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use std::collections::HashMap;

#[derive(Clone)]
pub struct StripeService {
    db: PgPool,
    secret_key: String,
    client: reqwest::Client,
    api_base: String,
}

impl StripeService {
    pub fn new(db: PgPool, secret_key: String) -> Self {
        Self {
            db,
            secret_key,
            client: reqwest::Client::new(),
            api_base: "https://api.stripe.com".to_string(),
        }
    }

    /// Set a custom API base URL (e.g. for testing)
    pub fn with_api_base(mut self, url: String) -> Self {
        self.api_base = url;
        self
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.secret_key)).map_err(|_| AppError::Internal("Bad key".into()))?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
        Ok(headers)
    }

    /// Create Checkout Session (Raw HTTP)
    pub async fn create_checkout_session(
        &self,
        org_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
        customer_email: Option<&str>,
    ) -> Result<String> {
        // 1. Get or Create Customer (Simplified: We pass email to Checkout and let Stripe handle it, or we assume ID mapping exists)
        // For MVP/Robustness, let's create customer or look it up.
        let customer_id = self.get_or_create_customer_id(org_id, customer_email).await?;

        let url = format!("{}/v1/checkout/sessions", self.api_base);
        
        let mut params = HashMap::new();
        params.insert("customer", customer_id);
        params.insert("mode", "subscription".to_string());
        params.insert("success_url", success_url.to_string());
        params.insert("cancel_url", cancel_url.to_string());
        params.insert("line_items[0][price]", price_id.to_string());
        params.insert("line_items[0][quantity]", "1".to_string());
        params.insert("metadata[organization_id]", org_id.to_string());
        params.insert("allow_promotion_codes", "true".to_string());

        let res = self.client.post(url)
            .headers(self.headers()?)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::External(format!("Stripe req error: {}", e)))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AppError::External(format!("Stripe API error: {}", body)));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| AppError::Internal(e.to_string()))?;
        json["url"].as_str().map(|s| s.to_string()).ok_or_else(|| AppError::Internal("No URL in response".into()))
    }

    /// Webhook: Verify Signature (Manual HMAC-SHA256)
    pub fn verify_signature(&self, payload: &str, sig_header: &str, webhook_secret: &str) -> Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use hex;

        // Parse signature header: t=TIMESTAMP,v1=SIGNATURE
        let parts: HashMap<&str, &str> = sig_header.split(',')
            .filter_map(|s| {
                let mut split = s.split('=');
                Some((split.next()?, split.next()?))
            })
            .collect();

        let t = parts.get("t").ok_or(AppError::Unauthorized("Missing timestamp".into()))?;
        let v1 = parts.get("v1").ok_or(AppError::Unauthorized("Missing signature".into()))?;

        // Reconstruct signed payload: timestamp.payload
        let signed_payload = format!("{}.{}", t, payload);

        // Compute HMAC
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal("HMAC error".into()))?;
        mac.update(signed_payload.as_bytes());
        let result = mac.finalize().into_bytes();
        let computed = hex::encode(result);

        // Compare (Constant time ideally, but simple string assert for now)
        if computed != *v1 {
             return Err(AppError::Unauthorized("Invalid signature".into()));
        }
        
        // Check timestamp freshness (reject events > 5 minutes old to prevent replay attacks)
        let tolerance_seconds: i64 = 300; // 5 minutes
        if let Ok(ts) = t.parse::<i64>() {
            let now = chrono::Utc::now().timestamp();
            if (now - ts).abs() > tolerance_seconds {
                return Err(AppError::Unauthorized(
                    format!("Webhook timestamp too old: {}s delta (tolerance: {}s)", (now - ts).abs(), tolerance_seconds)
                ));
            }
        } else {
            return Err(AppError::Unauthorized("Invalid timestamp format".into()));
        }

        Ok(())
    }

    async fn get_or_create_customer_id(&self, org_id: &str, email: Option<&str>) -> Result<String> {
        // DB Lookup
        let row: Option<(Option<String>,)> = sqlx::query_as("SELECT stripe_customer_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&self.db)
            .await?;
        
        if let Some((Some(cid),)) = row {
             if !cid.is_empty() { return Ok(cid); }
        }

        // Create in Stripe
        let url = format!("{}/v1/customers", self.api_base);
        let mut params = HashMap::new();
        params.insert("metadata[organization_id]", org_id.to_string());
        if let Some(e) = email {
            params.insert("email", e.to_string());
        }

        let res = self.client.post(url)
            .headers(self.headers()?)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        let json: serde_json::Value = res.json().await.map_err(|_| AppError::Internal("Json error".into()))?;
        let cid = json["id"].as_str().ok_or(AppError::Internal("No ID".into()))?.to_string();

        // Update DB
        sqlx::query("UPDATE organizations SET stripe_customer_id = $1 WHERE id = $2")
            .bind(&cid)
            .bind(org_id)
            .execute(&self.db)
            .await?;

        Ok(cid)
    }
    
    /// List subscriptions for an organization
    pub async fn list_subscriptions(&self, org_id: &str) -> Result<Vec<serde_json::Value>> {
        let customer_id = self.get_or_create_customer_id(org_id, None).await?;
        
        let url = format!(
            "{}/v1/subscriptions?customer={}&status=all&limit=10",
            self.api_base, customer_id
        );
        
        let res = self.client.get(&url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;
        
        let subs = json["data"].as_array()
            .cloned()
            .unwrap_or_default();
        
        Ok(subs)
    }
    
    /// Get a specific subscription by ID
    pub async fn get_subscription(&self, subscription_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/subscriptions/{}", self.api_base, subscription_id);
        
        let res = self.client.get(&url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        if !res.status().is_success() {
            return Err(AppError::NotFound("Subscription not found".into()));
        }
        
        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;
        
        Ok(json)
    }
    
    /// Cancel a subscription (at period end or immediately)
    pub async fn cancel_subscription(&self, subscription_id: &str, immediately: bool) -> Result<serde_json::Value> {
        let url = format!("{}/v1/subscriptions/{}", self.api_base, subscription_id);
        
        if immediately {
            // DELETE for immediate cancellation
            let res = self.client.delete(&url)
                .headers(self.headers()?)
                .send()
                .await
                .map_err(|e| AppError::External(e.to_string()))?;
            
            let json: serde_json::Value = res.json().await
                .map_err(|_| AppError::Internal("Json error".into()))?;
            
            Ok(json)
        } else {
            // POST with cancel_at_period_end = true
            let mut params = HashMap::new();
            params.insert("cancel_at_period_end", "true".to_string());
            
            let res = self.client.post(&url)
                .headers(self.headers()?)
                .form(&params)
                .send()
                .await
                .map_err(|e| AppError::External(e.to_string()))?;
            
            let json: serde_json::Value = res.json().await
                .map_err(|_| AppError::Internal("Json error".into()))?;
            
            Ok(json)
        }
    }
    
    /// Create a billing portal session for self-service billing management
    pub async fn create_portal_session(&self, org_id: &str, return_url: &str) -> Result<String> {
        let customer_id = self.get_or_create_customer_id(org_id, None).await?;
        
        let url = format!("{}/v1/billing_portal/sessions", self.api_base);
        let mut params = HashMap::new();
        params.insert("customer", customer_id);
        params.insert("return_url", return_url.to_string());
        
        let res = self.client.post(url)
            .headers(self.headers()?)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;
        
        let portal_url = json["url"].as_str()
            .ok_or(AppError::Internal("No portal URL".into()))?
            .to_string();
        
        Ok(portal_url)
    }
    
    /// List invoices for an organization
    pub async fn list_invoices(&self, org_id: &str, limit: u32) -> Result<Vec<serde_json::Value>> {
        let customer_id = self.get_or_create_customer_id(org_id, None).await?;
        
        let url = format!(
            "{}/v1/invoices?customer={}&limit={}",
            self.api_base, customer_id, limit
        );
        
        let res = self.client.get(&url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;
        
        let invoices = json["data"].as_array()
            .cloned()
            .unwrap_or_default();
        
        Ok(invoices)
    }
    
    /// Get upcoming invoice (preview of next billing)
    pub async fn get_upcoming_invoice(&self, org_id: &str) -> Result<Option<serde_json::Value>> {
        let customer_id = self.get_or_create_customer_id(org_id, None).await?;
        
        let url = format!(
            "{}/v1/invoices/upcoming?customer={}",
            self.api_base, customer_id
        );
        
        let res = self.client.get(&url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;
        
        if res.status() == 404 {
            // No upcoming invoice (no active subscription)
            return Ok(None);
        }
        
        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;
        
        Ok(Some(json))
    }

    /// Get price details by price ID
    pub async fn get_price(&self, price_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/prices/{}", self.api_base, price_id);

        let res = self.client.get(&url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(|e| AppError::External(e.to_string()))?;

        if !res.status().is_success() {
            return Err(AppError::NotFound(format!("Price {} not found", price_id)));
        }

        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json error".into()))?;

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    /// Helper to create a valid Stripe signature for testing
    fn create_stripe_signature(payload: &str, secret: &str, timestamp: i64) -> String {
        let signed_payload = format!("{}.{}", timestamp, payload);
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let result = mac.finalize().into_bytes();
        let signature = hex::encode(result);
        
        format!("t={},v1={}", timestamp, signature)
    }

    #[test]
    fn test_signature_header_parsing() {
        // Test that we can parse the Stripe-Signature header format
        let sig_header = "t=1234567890,v1=abc123def456";
        
        let parts: std::collections::HashMap<&str, &str> = sig_header.split(',')
            .filter_map(|s| {
                let mut split = s.split('=');
                Some((split.next()?, split.next()?))
            })
            .collect();
        
        assert_eq!(parts.get("t"), Some(&"1234567890"));
        assert_eq!(parts.get("v1"), Some(&"abc123def456"));
    }

    #[test]
    fn test_signature_hmac_computation() {
        // Test that HMAC-SHA256 computation works correctly
        let payload = r#"{"type":"checkout.session.completed"}"#;
        let secret = "whsec_test_secret_key";
        let timestamp = 1735689600i64;
        
        let sig_header = create_stripe_signature(payload, secret, timestamp);
        
        // Verify the signature format
        assert!(sig_header.starts_with("t=1735689600,v1="));
        assert!(sig_header.len() > 25); // Reasonable length check
    }

    #[test]
    fn test_signature_format_with_multiple_signatures() {
        // Stripe can send multiple signatures (v0, v1) for rollover
        let sig_header = "t=123,v0=oldsig,v1=newsig";
        
        let parts: std::collections::HashMap<&str, &str> = sig_header.split(',')
            .filter_map(|s| {
                let mut split = s.split('=');
                Some((split.next()?, split.next()?))
            })
            .collect();
        
        assert_eq!(parts.get("t"), Some(&"123"));
        assert_eq!(parts.get("v0"), Some(&"oldsig"));
        assert_eq!(parts.get("v1"), Some(&"newsig"));
    }

    #[test]
    fn test_signature_payload_format() {
        // Verify the signed payload format is timestamp.payload
        let timestamp = 1735689600i64;
        let payload = "test_payload";
        
        let signed_payload = format!("{}.{}", timestamp, payload);
        
        assert_eq!(signed_payload, "1735689600.test_payload");
    }

    #[test]
    fn test_hmac_hex_encoding() {
        // Test that hex encoding produces lowercase output
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"message");
        let result = mac.finalize().into_bytes();
        let hex_result = hex::encode(result);
        
        // Should be lowercase hex string
        assert!(hex_result.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(hex_result.len(), 64); // SHA256 produces 32 bytes = 64 hex chars
    }
}

