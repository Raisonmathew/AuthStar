use std::sync::Arc;
use sqlx::{PgPool, Postgres, Transaction};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use anyhow::{Result, anyhow};
use tracing::{info, error, instrument};
use rand::RngCore;
use crate::services::factor_encryption::FactorEncryption;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserFactor {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub factor_type: String, // "totp", "passkey", etc.
    pub factor_data: Option<serde_json::Value>,
    pub status: String,      // "pending", "active", "disabled"
    pub created_at: DateTime<Utc>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct UserFactorService {
    pool: PgPool,
    encryption: FactorEncryption,
}

impl UserFactorService {
    pub fn new(pool: PgPool) -> Self {
        Self::with_encryption(pool, FactorEncryption::new(None))
    }

    pub fn with_encryption(pool: PgPool, encryption: FactorEncryption) -> Self {
        Self { pool, encryption }
    }

    /// Start enrollment for a new factor (e.g., generate TOTP secret)
    #[instrument(skip(self))]
    pub async fn initiate_enrollment(&self, user_id: &str, tenant_id: &str, factor_type: &str) -> Result<(String, String)> {
        // Generate factor ID
        let factor_id = format!("uf_{}", Uuid::new_v4().to_string().replace("-", ""));

        // Generate secret/data based on type
        let (factor_data, secret_to_return) = match factor_type {
            "totp" => {
                let uuid1 = Uuid::new_v4();
                let uuid2 = Uuid::new_v4();
                let mut key = [0u8; 20]; // 160 bits for SHA1
                key[..16].copy_from_slice(uuid1.as_bytes());
                key[16..].copy_from_slice(&uuid2.as_bytes()[..4]);
                
                let secret_str = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &key);
                
                // Encrypt the TOTP secret before storing
                let encrypted_secret = self.encryption.encrypt(&secret_str);
                let data = serde_json::json!({
                    "secret": encrypted_secret
                });
                
                (data, secret_str)
            },
            "passkey" => {
                // Passkey enrollment is handled via the dedicated WebAuthn endpoints.
                return Err(anyhow!("Passkey enrollment must use /api/passkeys/register"));
            },
            _ => return Err(anyhow!("Unsupported factor type")),
        };

        // Store pending factor
        sqlx::query(
            r#"
            INSERT INTO user_factors 
            (id, user_id, tenant_id, factor_type, factor_data, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, 'pending', NOW(), NOW())
            "#
        )
        .bind(&factor_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(factor_type)
        .bind(factor_data)
        .execute(&self.pool)
        .await?;

        Ok((factor_id, secret_to_return))
    }

    /// Verify enrollment and activate the factor
    #[instrument(skip(self))]
    pub async fn verify_enrollment(&self, user_id: &str, tenant_id: &str, factor_id: &str, code: &str) -> Result<bool> {
        let factor = self.get_factor(user_id, tenant_id, factor_id).await?;
        
        if factor.status != "pending" {
            return Err(anyhow!("Factor is not pending enrollment"));
        }

        let valid = self.verify_code_internal(&factor, code)?;

        if valid {
            // Activate factor
            sqlx::query(
                r#"
                UPDATE user_factors
                SET status = 'active', enrolled_at = NOW(), updated_at = NOW()
                WHERE id = $1
                "#
            )
            .bind(factor_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(valid)
    }

    /// Verify a factor for step-up authentication and update session
    #[instrument(skip(self))]
    pub async fn verify_factor_for_session(&self, user_id: &str, tenant_id: &str, session_id: &str, factor_id: &str, code: &str) -> Result<bool> {
        let factor = self.get_factor(user_id, tenant_id, factor_id).await?;

        if factor.status != "active" {
            return Err(anyhow!("Factor is not active"));
        }

        let valid = self.verify_code_internal(&factor, code)?;

        if valid {
            // Update session: promote assurance level and clear provisional flag
            // We append the factor type to verified_capabilities. 
            // Note: Postgres JSONB concatenation `||` or `jsonb_insert` could be used, but let's be safe with strict logic.
            // Simplified approach: atomic update assuming we are adding a capability.
            
            // Logic:
            // 1. Fetch current capabilities (handled in query roughly or we fetch-modify-save).
            // 2. Add new capability.
            // 3. Upgrade AAL if applicable.
            
            let capability = match factor.factor_type.as_str() {
                "totp" | "passkey" => factor.factor_type.clone(),
                _ => "unknown".to_string(),
            };

            // Upgrade to AAL2 if we have a strong factor
            let new_aal = "aal2"; 

            sqlx::query(
                r#"
                UPDATE sessions
                SET 
                    is_provisional = false,
                    assurance_level = $1,
                    verified_capabilities = CASE 
                        WHEN verified_capabilities @> to_jsonb($2::text) THEN verified_capabilities
                        ELSE verified_capabilities || to_jsonb($2::text)
                    END,
                    updated_at = NOW()
                WHERE id = $3 AND user_id = $4 AND tenant_id = $5
                "#
            )
            .bind(new_aal)
            .bind(capability)
            .bind(session_id)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(valid)
    }

    // Helper to fetch factor
    async fn get_factor(&self, user_id: &str, tenant_id: &str, factor_id: &str) -> Result<UserFactor> {
        sqlx::query_as::<_, UserFactor>(
            r#"
            SELECT id, user_id, tenant_id, factor_type, factor_data, status, 
                   created_at, enrolled_at, last_used_at
            FROM user_factors
            WHERE id = $1 AND user_id = $2 AND tenant_id = $3
            "#
        )
        .bind(factor_id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("Factor not found"))
    }

    // Helper to verify code (CPU bound, no async)
    fn verify_code_internal(&self, factor: &UserFactor, code: &str) -> Result<bool> {
        match factor.factor_type.as_str() {
            "totp" => {
                let data = factor.factor_data.as_ref().ok_or_else(|| anyhow!("Missing factor data"))?;
                let stored_secret = data["secret"].as_str().ok_or_else(|| anyhow!("Invalid factor data schema"))?;
                
                // Decrypt the secret (handles both encrypted and legacy plaintext)
                let secret_str = self.encryption.decrypt(stored_secret)
                    .map_err(|e| anyhow!("Secret decryption failed: {}", e))?;
                
                let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret_str)
                    .ok_or_else(|| anyhow!("Invalid base32 secret"))?;

                let totp = TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    secret_bytes,
                    None,
                    "IDaaS".to_string(),
                ).map_err(|e| anyhow!("TOTP error: {:?}", e))?;

                totp.check_current(code).map_err(|e| anyhow!("Verification error: {:?}", e))
            },
            "passkey" => {
                // Passkey verification requires the WebAuthn challenge/response flow
                // via PasskeyService, not a simple code string. If we reach here,
                // the caller is using the wrong verification path.
                Err(anyhow!("Passkey verification must use /api/passkeys/authenticate"))
            },
            _ => Ok(false),
        }
    }

    /// Delete a factor
    #[instrument(skip(self))]
    pub async fn delete_factor(&self, user_id: &str, tenant_id: &str, factor_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM user_factors
            WHERE id = $1 AND user_id = $2 AND tenant_id = $3
            "#
        )
        .bind(factor_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List enrolled factors
    #[instrument(skip(self))]
    pub async fn list_factors(&self, user_id: &str, tenant_id: &str) -> Result<Vec<UserFactor>> {
        let factors = sqlx::query_as::<_, UserFactor>(
            r#"
            SELECT 
                id, user_id, tenant_id, factor_type, factor_data, status, 
                created_at, enrolled_at, last_used_at
            FROM user_factors
            WHERE user_id = $1 AND tenant_id = $2 AND status = 'active'
            ORDER BY created_at DESC
            "#
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(factors)
    }
}
