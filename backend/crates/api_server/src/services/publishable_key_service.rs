use chrono::{DateTime, Utc};
use shared_types::{AppError, Result};
use sqlx::PgPool;

#[derive(serde::Deserialize)]
pub struct CreatePublishableKeyParams {
    pub environment: String,
    #[serde(default = "default_key_name")]
    pub name: String,
}

fn default_key_name() -> String {
    "Default".to_string()
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct PublishableKeyItem {
    pub id: String,
    pub key: String,
    pub environment: String,
    pub name: String,
    pub is_active: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Serialize)]
pub struct PublishableKeyResponse {
    pub id: String,
    pub key: String,
    pub environment: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Resolved publishable key information returned by `validate()`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedPublishableKey {
    pub tenant_id: String,
    pub environment: String,
}

#[derive(Clone)]
pub struct PublishableKeyService {
    db: PgPool,
}

impl PublishableKeyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// List active publishable keys for a tenant.
    pub async fn list(&self, tenant_id: &str) -> Result<Vec<PublishableKeyItem>> {
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

        let keys = sqlx::query_as::<_, PublishableKeyItem>(
            r#"
            SELECT id, key, environment, name, is_active, last_used_at, created_at
            FROM publishable_keys
            WHERE tenant_id = $1
              AND revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 50
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    /// Create a publishable key for a tenant.
    /// Key format: pk_{environment}_{org_slug}
    pub async fn create(
        &self,
        tenant_id: &str,
        params: &CreatePublishableKeyParams,
    ) -> Result<PublishableKeyResponse> {
        let env = params.environment.trim().to_lowercase();
        if env != "test" && env != "live" {
            return Err(AppError::BadRequest(
                "environment must be 'test' or 'live'".into(),
            ));
        }

        let name = params.name.trim().to_string();
        if name.is_empty() || name.len() > 100 {
            return Err(AppError::BadRequest(
                "Key name must be 1–100 characters".into(),
            ));
        }

        // Look up the org slug to build the key
        let slug: String = sqlx::query_scalar(
            "SELECT slug FROM organizations WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

        let key = format!("pk_{env}_{slug}");
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

        let id = sqlx::query_scalar::<_, String>(
            r#"
            INSERT INTO publishable_keys (tenant_id, key, environment, name, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&key)
        .bind(&env)
        .bind(&name)
        .bind(now)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err)
                if db_err
                    .constraint()
                    .is_some_and(|c| c.contains("publishable_keys_unique")) =>
            {
                AppError::Conflict(format!(
                    "A publishable key for environment '{env}' already exists for this organization"
                ))
            }
            e => e.into(),
        })?;

        tracing::info!(
            tenant_id = %tenant_id,
            key_id = %id,
            environment = %env,
            key = %key,
            "Publishable key created"
        );

        Ok(PublishableKeyResponse {
            id,
            key,
            environment: env,
            name,
            created_at: now,
        })
    }

    /// Revoke a publishable key.
    pub async fn revoke(&self, key_id: &str, tenant_id: &str) -> Result<()> {
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
            UPDATE publishable_keys
            SET revoked_at = NOW(), is_active = FALSE
            WHERE id = $1
              AND tenant_id = $2
              AND revoked_at IS NULL
            "#,
        )
        .bind(key_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Publishable key not found".into()));
        }

        Ok(())
    }

    /// Validate a publishable key and return the resolved tenant info.
    /// Used by the manifest endpoint and SDK middleware.
    /// This does a cross-tenant lookup (no RLS context needed).
    pub async fn validate(&self, key: &str) -> Result<Option<ResolvedPublishableKey>> {
        if !key.starts_with("pk_") {
            return Ok(None);
        }

        let row: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT tenant_id, environment
            FROM publishable_keys
            WHERE key = $1
              AND is_active = TRUE
              AND revoked_at IS NULL
            "#,
        )
        .bind(key)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error validating publishable key: {e}")))?;

        if let Some((tenant_id, environment)) = &row {
            // Fire-and-forget last_used_at update (debounced)
            let db_clone = self.db.clone();
            let key_owned = key.to_owned();
            tokio::spawn(async move {
                let _ = sqlx::query(
                    r#"UPDATE publishable_keys
                       SET last_used_at = NOW()
                       WHERE key = $1
                         AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '5 minutes')"#,
                )
                .bind(&key_owned)
                .execute(&db_clone)
                .await;
            });

            return Ok(Some(ResolvedPublishableKey {
                tenant_id: tenant_id.clone(),
                environment: environment.clone(),
            }));
        }

        Ok(None)
    }
}
