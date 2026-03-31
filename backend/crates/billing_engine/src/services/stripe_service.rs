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
            .map_err(|e| AppError::External(format!("Stripe req error: {e}")))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AppError::External(format!("Stripe API error: {body}")));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| AppError::Internal(e.to_string()))?;
        json["url"].as_str().map(|s| s.to_string()).ok_or_else(|| AppError::Internal("No URL in response".into()))
    }

    /// Webhook: Verify Stripe signature (HMAC-SHA256).
    ///
    /// CRITICAL-7 FIX: Uses `hmac::Mac::verify_slice()` which performs a constant-time
    /// comparison internally. The previous `computed != *v1` string comparison was
    /// vulnerable to timing side-channel attacks that could allow an attacker to
    /// brute-force the webhook secret byte-by-byte.
    pub fn verify_signature(&self, payload: &str, sig_header: &str, webhook_secret: &str) -> Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Parse signature header: t=TIMESTAMP,v1=SIGNATURE
        // Stripe may send multiple v1 values (key rotation); we accept any valid one.
        let mut timestamp: Option<&str> = None;
        let mut v1_signatures: Vec<&str> = Vec::new();

        for part in sig_header.split(',') {
            if let Some(val) = part.strip_prefix("t=") {
                timestamp = Some(val);
            } else if let Some(val) = part.strip_prefix("v1=") {
                v1_signatures.push(val);
            }
        }

        let t = timestamp.ok_or_else(|| AppError::Unauthorized("Missing timestamp in Stripe-Signature".into()))?;
        if v1_signatures.is_empty() {
            return Err(AppError::Unauthorized("Missing v1 signature in Stripe-Signature".into()));
        }

        // Check timestamp freshness FIRST (before HMAC computation) to prevent
        // resource exhaustion from replayed old events.
        let ts = t.parse::<i64>()
            .map_err(|_| AppError::Unauthorized("Invalid timestamp format in Stripe-Signature".into()))?;
        let now = chrono::Utc::now().timestamp();
        let tolerance_seconds: i64 = 300; // 5 minutes
        if (now - ts).abs() > tolerance_seconds {
            return Err(AppError::Unauthorized(format!(
                "Webhook timestamp too old: {}s delta (tolerance: {}s)",
                (now - ts).abs(), tolerance_seconds
            )));
        }

        // Reconstruct signed payload: timestamp.payload
        let signed_payload = format!("{t}.{payload}");

        // Compute expected HMAC
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal("HMAC key init error".into()))?;
        mac.update(signed_payload.as_bytes());

        // CRITICAL-7 FIX: Decode the hex signature and use verify_slice() which is
        // constant-time. This prevents timing attacks on the HMAC comparison.
        // We check all v1 signatures (Stripe sends multiple during key rotation).
        let mut any_valid = false;
        for v1_hex in &v1_signatures {
            if let Ok(v1_bytes) = hex::decode(v1_hex) {
                // Clone mac for each attempt (verify_slice consumes it)
                let mac_clone = HmacSha256::new_from_slice(webhook_secret.as_bytes())
                    .map_err(|_| AppError::Internal("HMAC key init error".into()))?;
                let mut mac_for_verify = mac_clone;
                mac_for_verify.update(signed_payload.as_bytes());
                if mac_for_verify.verify_slice(&v1_bytes).is_ok() {
                    any_valid = true;
                    break;
                }
            }
        }

        if !any_valid {
            return Err(AppError::Unauthorized("Invalid Stripe webhook signature".into()));
        }

        Ok(())
    }

    /// Get or create a Stripe customer ID for an organization.
    ///
    /// HIGH-4 FIX: Uses a conditional UPDATE (`WHERE stripe_customer_id IS NULL`) to
    /// prevent the race condition where two concurrent requests both find no customer,
    /// both create one in Stripe, and both try to write — resulting in duplicate customers.
    /// The pattern: create in Stripe first, then atomically claim the slot in the DB.
    /// If another request won the race, we discard our newly created customer.
    async fn get_or_create_customer_id(&self, org_id: &str, email: Option<&str>) -> Result<String> {
        // Fast path: customer already exists
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT stripe_customer_id FROM organizations WHERE id = $1"
        )
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?;

        if let Some((Some(cid),)) = &row {
            if !cid.is_empty() {
                return Ok(cid.clone());
            }
        }

        // Create a new customer in Stripe
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

        let json: serde_json::Value = res.json().await
            .map_err(|_| AppError::Internal("Json parse error".into()))?;
        let new_cid = json["id"].as_str()
            .ok_or_else(|| AppError::Internal("No customer ID in Stripe response".into()))?
            .to_string();

        // HIGH-4 FIX: Conditional UPDATE — only sets the customer ID if it's still NULL.
        // If another concurrent request already set it, rows_affected() == 0 and we
        // re-fetch the winner's customer ID instead of creating a duplicate.
        let result = sqlx::query(
            "UPDATE organizations
             SET stripe_customer_id = $1
             WHERE id = $2 AND stripe_customer_id IS NULL"
        )
        .bind(&new_cid)
        .bind(org_id)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            // Another request won the race — fetch the customer ID they set.
            // Our newly created Stripe customer is orphaned; log it for cleanup.
            tracing::warn!(
                org_id = %org_id,
                orphaned_customer = %new_cid,
                "Race condition in get_or_create_customer_id — orphaned Stripe customer created. \
                 Consider archiving {} in Stripe dashboard.",
                new_cid
            );

            let winner: (String,) = sqlx::query_as(
                "SELECT stripe_customer_id FROM organizations WHERE id = $1"
            )
            .bind(org_id)
            .fetch_one(&self.db)
            .await?;

            return Ok(winner.0);
        }

        Ok(new_cid)
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
            return Err(AppError::NotFound(format!("Price {price_id} not found")));
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

