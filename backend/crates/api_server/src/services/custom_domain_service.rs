//! Custom Domain Service
//!
//! Manages custom domains for organizations:
//! - Domain registration and verification (DNS TXT)
//! - SSL certificate provisioning
//! - Domain routing configuration

use crate::middleware::tenant_conn::TenantConn;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use sqlx::PgPool;

// Domain verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
}

// SSL status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SslStatus {
    Pending,
    Provisioning,
    Active,
    Failed,
}

/// Custom domain record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDomain {
    pub id: String,
    pub organization_id: String,
    pub domain: String,
    pub verification_status: String,
    pub verification_token: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub ssl_status: String,
    pub is_primary: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Domain verification instructions
#[derive(Debug, Clone, Serialize)]
pub struct VerificationInstructions {
    pub method: String,
    pub record_type: String,
    pub record_name: String,
    pub record_value: String,
}

/// Custom domain service
#[derive(Clone)]
pub struct CustomDomainService {
    db: PgPool,
}

impl CustomDomainService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate a random verification token
    fn generate_verification_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(bytes)
    }

    /// Add a custom domain for an organization
    pub async fn add_domain(&self, org_id: &str, domain: &str) -> Result<CustomDomain> {
        // Validate domain format
        if !Self::is_valid_domain(domain) {
            return Err(AppError::Validation("Invalid domain format".into()));
        }

        // Check if domain already exists
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM custom_domains WHERE domain = $1")
                .bind(domain)
                .fetch_optional(&self.db)
                .await?;

        if existing.is_some() {
            return Err(AppError::Conflict("Domain already registered".into()));
        }

        let id = shared_types::id_generator::generate_id("domain");
        let verification_token = Self::generate_verification_token();

        sqlx::query(
            r#"
            INSERT INTO custom_domains (
                id, organization_id, domain, verification_token
            ) VALUES ($1, $2, $3, $4)
        "#,
        )
        .bind(&id)
        .bind(org_id)
        .bind(domain)
        .bind(&verification_token)
        .execute(&self.db)
        .await?;

        self.get_domain(&id).await
    }

    /// Get domain by ID
    pub async fn get_domain(&self, id: &str) -> Result<CustomDomain> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                Option<DateTime<Utc>>,
                String,
                bool,
                bool,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT id, organization_id, domain, verification_status, verification_token,
                   verified_at, ssl_status, is_primary, is_active, created_at
            FROM custom_domains WHERE id = $1
        "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::NotFound("Domain not found".into()))?;

        Ok(CustomDomain {
            id: row.0,
            organization_id: row.1,
            domain: row.2,
            verification_status: row.3,
            verification_token: row.4,
            verified_at: row.5,
            ssl_status: row.6,
            is_primary: row.7,
            is_active: row.8,
            created_at: row.9,
        })
    }

    /// List domains for an organization
    pub async fn list_domains(&self, org_id: &str) -> Result<Vec<CustomDomain>> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                Option<DateTime<Utc>>,
                String,
                bool,
                bool,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT id, organization_id, domain, verification_status, verification_token,
                   verified_at, ssl_status, is_primary, is_active, created_at
            FROM custom_domains WHERE organization_id = $1
            ORDER BY created_at DESC
        "#,
        )
        .bind(org_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| CustomDomain {
                id: row.0,
                organization_id: row.1,
                domain: row.2,
                verification_status: row.3,
                verification_token: row.4,
                verified_at: row.5,
                ssl_status: row.6,
                is_primary: row.7,
                is_active: row.8,
                created_at: row.9,
            })
            .collect())
    }

    /// Get verification instructions for a domain
    pub fn get_verification_instructions(&self, domain: &CustomDomain) -> VerificationInstructions {
        VerificationInstructions {
            method: "dns_txt".to_string(),
            record_type: "TXT".to_string(),
            record_name: format!("_idaas-verification.{}", domain.domain),
            record_value: format!("idaas-verification={}", domain.verification_token),
        }
    }

    /// Verify a domain (check DNS TXT record)
    pub async fn verify_domain(&self, id: &str) -> Result<bool> {
        let domain = self.get_domain(id).await?;

        // Update last verification attempt
        sqlx::query("UPDATE custom_domains SET last_verification_attempt = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;

        // Perform real DNS lookup for TXT record
        let expected_value = format!("idaas-verification={}", domain.verification_token);

        let verified = match Self::check_dns_txt_record(&domain.domain, &expected_value).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DNS check error for {}: {}", domain.domain, e);
                false
            }
        };

        // Log the verification attempt
        let log_id = shared_types::id_generator::generate_id("vlog");
        sqlx::query(
            r#"
            INSERT INTO domain_verification_logs (id, domain_id, success, error_message)
            VALUES ($1, $2, $3, $4)
        "#,
        )
        .bind(&log_id)
        .bind(id)
        .bind(verified)
        .bind(if verified {
            None
        } else {
            Some("DNS record not found")
        })
        .execute(&self.db)
        .await?;

        if verified {
            sqlx::query(
                r#"
                UPDATE custom_domains 
                SET verification_status = 'verified', verified_at = NOW(), updated_at = NOW()
                WHERE id = $1
            "#,
            )
            .bind(id)
            .execute(&self.db)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE custom_domains 
                SET verification_error = 'DNS record not found', updated_at = NOW()
                WHERE id = $1
            "#,
            )
            .bind(id)
            .execute(&self.db)
            .await?;
        }

        Ok(verified)
    }

    /// Check if a DNS TXT record exists with the expected verification token
    pub async fn check_dns_txt_record(
        domain: &str,
        expected_token: &str,
    ) -> std::result::Result<bool, String> {
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
        use trust_dns_resolver::TokioAsyncResolver;

        let verification_domain = format!("_idaas-verification.{domain}");

        // trust-dns-resolver 0.23: TokioAsyncResolver::tokio() returns the resolver
        // directly (not a Result). The glob import of config::* caused a type-alias
        // ambiguity with 2 generic args; use explicit imports instead.
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        match resolver.txt_lookup(&verification_domain).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let txt_data = record.to_string();
                    if txt_data.contains(expected_token) {
                        tracing::info!("DNS verification successful for {}", domain);
                        return Ok(true);
                    }
                }
                tracing::debug!(
                    "DNS TXT record found for {} but no matching token (expected: {})",
                    verification_domain,
                    expected_token
                );
                Ok(false)
            }
            Err(e) => {
                tracing::debug!("DNS TXT lookup failed for {}: {}", verification_domain, e);
                Ok(false) // No record found is not an error, just unverified
            }
        }
    }

    /// Delete a domain
    pub async fn delete_domain(&self, id: &str, org_id: &str) -> Result<()> {
        // RLS defense-in-depth: TenantConn sets app.current_org_id on the connection
        let mut conn = TenantConn::acquire(&self.db, org_id).await?;
        let result =
            sqlx::query("DELETE FROM custom_domains WHERE id = $1 AND organization_id = $2")
                .bind(id)
                .bind(org_id)
                .execute(&mut **conn)
                .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Domain not found".into()));
        }

        Ok(())
    }

    /// Set a domain as primary
    pub async fn set_primary(&self, id: &str, org_id: &str) -> Result<()> {
        // RLS defense-in-depth: TenantConn sets app.current_org_id on the connection
        let mut conn = TenantConn::acquire(&self.db, org_id).await?;

        // Unset current primary
        sqlx::query("UPDATE custom_domains SET is_primary = false WHERE organization_id = $1")
            .bind(org_id)
            .execute(&mut **conn)
            .await?;

        // Set new primary
        sqlx::query("UPDATE custom_domains SET is_primary = true, updated_at = NOW() WHERE id = $1 AND organization_id = $2")
            .bind(id)
            .bind(org_id)
            .execute(&mut **conn)
            .await?;

        Ok(())
    }

    /// Validate domain format
    fn is_valid_domain(domain: &str) -> bool {
        // Basic validation
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        // Must have at least one dot
        if !domain.contains('.') {
            return false;
        }

        // No leading/trailing dots
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }

        // Check each label
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            // Must start and end with alphanumeric
            if !label
                .chars()
                .next()
                .map(|c| c.is_alphanumeric())
                .unwrap_or(false)
            {
                return false;
            }
            if !label
                .chars()
                .last()
                .map(|c| c.is_alphanumeric())
                .unwrap_or(false)
            {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation() {
        assert!(CustomDomainService::is_valid_domain("example.com"));
        assert!(CustomDomainService::is_valid_domain("auth.example.com"));
        assert!(CustomDomainService::is_valid_domain(
            "my-auth.example.co.uk"
        ));

        assert!(!CustomDomainService::is_valid_domain("")); // Empty
        assert!(!CustomDomainService::is_valid_domain("example")); // No dot
        assert!(!CustomDomainService::is_valid_domain(".example.com")); // Leading dot
        assert!(!CustomDomainService::is_valid_domain("example.com.")); // Trailing dot
    }
}
