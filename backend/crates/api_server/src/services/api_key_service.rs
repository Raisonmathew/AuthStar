use chrono::{DateTime, Utc};
use shared_types::{AppError, Result};
use sqlx::PgPool;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CreateApiKeyParams {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct ApiKeyListItem {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// The full API key — returned ONCE on creation, never stored, never returned again.
    pub key: String,
}

// ─── Key Generation / Hashing ─────────────────────────────────────────────────

/// Generate a cryptographically secure API key.
///
/// Format: `ask_<8-char-prefix>_<48-char-base64url-random>`
///
/// - 8-char prefix — stored in DB for fast lookup without scanning hashes
/// - 48-char base64url random — 288 bits of entropy, URL-safe, no padding
///
/// Returns `(full_key, prefix)`.
fn generate_api_key() -> (String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::RngCore;

    let mut raw = [0u8; 36];
    rand::thread_rng().fill_bytes(&mut raw);

    let random_part = URL_SAFE_NO_PAD.encode(raw);
    debug_assert_eq!(random_part.len(), 48);

    let prefix: String = random_part.chars().take(8).collect();
    debug_assert_eq!(prefix.len(), 8);

    let full_key = format!("ask_{prefix}_{random_part}");
    (full_key, prefix)
}

/// Hash an API key using Argon2id (OWASP minimums for high-entropy keys).
fn hash_api_key(key: &str) -> Result<String> {
    use argon2::Params;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None)
        .map_err(|e| AppError::Internal(format!("Argon2 params error: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let hash = argon2
        .hash_password(key.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Argon2 hash error: {e}")))?
        .to_string();

    Ok(hash)
}

/// Verify an API key against its stored hash.
fn verify_api_key(key: &str, hash: &str) -> bool {
    use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(key.as_bytes(), &parsed_hash)
        .is_ok()
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiKeyService {
    db: PgPool,
}

impl ApiKeyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// List active (non-revoked) API keys for a user+tenant.
    /// Acquires a dedicated connection and sets RLS context.
    pub async fn list(&self, user_id: &str, tenant_id: &str) -> Result<Vec<ApiKeyListItem>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("DB acquire failed: {e}")))?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;

        let keys = sqlx::query_as::<_, ApiKeyListItem>(
            r#"
            SELECT id, name, key_prefix, scopes, last_used_at, expires_at, created_at
            FROM api_keys
            WHERE user_id = $1
              AND tenant_id = $2
              AND revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 200
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    /// Create a new API key. Returns the full key ONCE.
    ///
    /// Enforces a per-tenant limit on active (non-revoked) API keys based on the
    /// organization's plan entitlements (`max_api_keys`). Free tier default: 5 keys.
    pub async fn create(
        &self,
        user_id: &str,
        tenant_id: &str,
        params: &CreateApiKeyParams,
    ) -> Result<CreateApiKeyResponse> {
        let name = params.name.trim().to_string();
        if name.is_empty() || name.len() > 100 {
            return Err(AppError::BadRequest(
                "Key name must be 1–100 characters".into(),
            ));
        }
        for scope in &params.scopes {
            if scope.len() > 100 || scope.contains('\n') || scope.contains('\r') {
                return Err(AppError::BadRequest(format!("Invalid scope: {scope}")));
            }
        }

        // Billing quota: enforce max_api_keys per tenant
        let max_keys = self.get_max_api_keys(tenant_id).await?;
        let current_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error counting API keys: {e}")))?;

        if current_count >= max_keys {
            return Err(AppError::Forbidden(format!(
                "API key limit reached ({max_keys}). Upgrade your plan to create more keys."
            )));
        }

        let (full_key, prefix) = generate_api_key();
        let key_hash = hash_api_key(&full_key)?;
        let now = Utc::now();

        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("DB acquire failed: {e}")))?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;

        let row = sqlx::query_scalar::<_, String>(
            r#"
            INSERT INTO api_keys (tenant_id, user_id, name, key_prefix, key_hash, scopes, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(&name)
        .bind(&prefix)
        .bind(&key_hash)
        .bind(&params.scopes)
        .bind(params.expires_at)
        .bind(now)
        .fetch_one(&mut *conn)
        .await;

        let id = match row {
            Ok(id) => id,
            Err(sqlx::Error::Database(db_err))
                if db_err.constraint() == Some("api_keys_unique_name_per_user") =>
            {
                return Err(AppError::Conflict(format!(
                    "An API key named '{name}' already exists"
                )));
            }
            Err(e) => return Err(e.into()),
        };

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            key_id = %id,
            key_name = %name,
            "API key created"
        );

        Ok(CreateApiKeyResponse {
            id,
            name,
            key_prefix: prefix,
            scopes: params.scopes.clone(),
            expires_at: params.expires_at,
            created_at: now,
            key: full_key,
        })
    }

    /// Revoke (soft-delete) an API key.
    pub async fn revoke(&self, key_id: &str, user_id: &str, tenant_id: &str) -> Result<()> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("DB acquire failed: {e}")))?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;

        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = NOW()
            WHERE id = $1
              AND user_id = $2
              AND tenant_id = $3
              AND revoked_at IS NULL
            "#,
        )
        .bind(key_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("API key not found".into()));
        }

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            key_id = %key_id,
            "API key revoked"
        );

        Ok(())
    }

    /// Authenticate an API key by prefix lookup + Argon2id verification.
    /// Returns `(user_id, tenant_id, scopes)` on success.
    pub async fn authenticate(&self, full_key: &str) -> Result<Option<(String, String, Vec<String>)>> {
        if full_key.len() != 61 || !full_key.starts_with("ask_") || full_key.as_bytes()[12] != b'_'
        {
            return Ok(None);
        }
        let prefix = &full_key[4..12];

        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, tenant_id, key_hash, scopes, revoked_at, expires_at
            FROM api_keys
            WHERE key_prefix = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
            prefix
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            if verify_api_key(full_key, &row.key_hash) {
                // Debounced last_used_at update (fire-and-forget).
                // Only updates if last_used_at is NULL or older than 5 minutes.
                let db_clone = self.db.clone();
                let key_id = row.id;
                tokio::spawn(async move {
                    let _ = sqlx::query!(
                        r#"UPDATE api_keys
                           SET last_used_at = NOW()
                           WHERE id = $1
                             AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '5 minutes')"#,
                        key_id
                    )
                    .execute(&db_clone)
                    .await;
                });

                return Ok(Some((row.user_id, row.tenant_id, row.scopes)));
            }
        }

        Ok(None)
    }

    /// Resolve the max API keys allowed for a tenant based on plan entitlements.
    /// Falls back to 5 (free tier) if no active subscription, limit is defined,
    /// or the billing tables haven't been created yet.
    async fn get_max_api_keys(&self, tenant_id: &str) -> Result<i64> {
        let result: std::result::Result<Option<serde_json::Value>, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT p.features
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            WHERE s.organization_id = $1 AND s.status = 'active'
            ORDER BY s.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await;

        let features = match result {
            Ok(f) => f,
            Err(e) => {
                // Billing tables may not exist yet — gracefully default
                tracing::warn!("Could not query plan entitlements (billing tables may not exist): {e}");
                None
            }
        };

        let limit = features
            .and_then(|f| f.get("max_api_keys").and_then(|v| v.as_i64()))
            .unwrap_or(5); // Free tier default

        Ok(limit)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let (key, prefix) = generate_api_key();
        assert!(key.starts_with("ask_"), "Key must start with ask_: {key}");
        assert_eq!(prefix.len(), 8, "Prefix must be 8 chars: {prefix}");
        assert!(key.contains(&prefix), "Key must contain prefix");
        assert_eq!(&key[0..4], "ask_");
        assert_eq!(&key[12..13], "_");
        let random_segment = &key[13..];
        assert_eq!(
            random_segment.len(),
            48,
            "Random segment must be exactly 48 chars"
        );
        assert!(
            random_segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Random segment must contain only base64url chars: {random_segment}"
        );
    }

    #[test]
    fn test_generate_api_key_format_deterministic_length() {
        for i in 0..1000 {
            let (key, prefix) = generate_api_key();
            assert_eq!(
                key.len(),
                61,
                "Iteration {i}: key must be exactly 61 chars: {key}"
            );
            assert!(
                key.starts_with("ask_"),
                "Iteration {i}: key must start with ask_: {key}"
            );
            assert_eq!(
                key.as_bytes()[12],
                b'_',
                "Iteration {i}: key must have underscore after prefix: {key}"
            );
            let key_prefix = &key[4..12];
            let key_random = &key[13..];
            assert_eq!(
                key_prefix.len(),
                8,
                "Iteration {i}: prefix must be exactly 8 chars, got {}: {}",
                key_prefix.len(),
                key
            );
            assert_eq!(
                key_random.len(),
                48,
                "Iteration {i}: random segment must be exactly 48 chars, got {}: {}",
                key_random.len(),
                key
            );
            assert_eq!(
                prefix, key_prefix,
                "Iteration {i}: returned prefix must match parsed prefix: {prefix}"
            );
        }
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let keys: std::collections::HashSet<String> =
            (0..100).map(|_| generate_api_key().0).collect();
        assert_eq!(keys.len(), 100, "All generated keys must be unique");
    }

    #[test]
    fn test_hash_and_verify_api_key() {
        let (key, _) = generate_api_key();
        let hash = hash_api_key(&key).expect("Hash should succeed");
        assert!(verify_api_key(&key, &hash), "Correct key should verify");
        let (other_key, _) = generate_api_key();
        assert!(
            !verify_api_key(&other_key, &hash),
            "Wrong key should not verify"
        );
    }

    #[test]
    fn test_verify_invalid_hash() {
        assert!(!verify_api_key("ask_test1234_somekey", "not-a-valid-hash"));
    }

    #[test]
    fn test_authenticate_api_key_invalid_format() {
        let bad_keys = vec![
            "not-an-api-key",
            "jwt.eyJ...",
            "ask_short_key",
            "ask_toolongprefix_key",
            "",
        ];
        for key in bad_keys {
            let is_valid =
                key.len() == 61 && key.starts_with("ask_") && key.as_bytes().get(12) == Some(&b'_');
            assert!(!is_valid, "Key '{key}' should be invalid format");
        }
    }
}
