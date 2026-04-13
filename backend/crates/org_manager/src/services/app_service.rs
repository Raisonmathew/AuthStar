use crate::models::{Application, CreateAppRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};
use shared_types::{AppError, Result};
use sqlx::PgPool;
use url::Url;

#[derive(Clone)]
pub struct AppService {
    db: PgPool,
}

impl AppService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    fn generate_secret() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn hash_secret(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn validate_urls(urls: &[String], field_name: &str) -> Result<()> {
        for value in urls {
            let parsed = Url::parse(value)
                .map_err(|e| AppError::BadRequest(format!("Invalid {field_name} '{value}': {e}")))?;
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(AppError::BadRequest(format!(
                    "Invalid {field_name} '{value}': only http/https schemes are allowed"
                )));
            }
        }
        Ok(())
    }

    fn validate_allowed_flows(allowed_flows: &[String]) -> Result<()> {
        let allowed = ["authorization_code", "refresh_token", "client_credentials"];
        for flow in allowed_flows {
            if !allowed.contains(&flow.as_str()) {
                return Err(AppError::BadRequest(format!(
                    "Invalid allowed flow '{flow}'. Supported flows: authorization_code, refresh_token, client_credentials"
                )));
            }
        }
        Ok(())
    }

    fn validate_allowed_scopes(allowed_scopes: &[String]) -> Result<()> {
        use crate::models::KNOWN_SCOPES;
        for scope in allowed_scopes {
            if !KNOWN_SCOPES.contains(&scope.as_str()) {
                return Err(AppError::BadRequest(format!(
                    "Invalid scope '{scope}'. Supported scopes: {}",
                    KNOWN_SCOPES.join(", ")
                )));
            }
        }
        Ok(())
    }

    pub async fn create_app(
        &self,
        tenant_id: &str,
        req: CreateAppRequest,
    ) -> Result<(Application, String)> {
        Self::validate_urls(&req.redirect_uris, "redirect URI")?;
        if let Some(public_config) = &req.public_config {
            if let Some(origins) = &public_config.allowed_origins {
                Self::validate_urls(origins, "allowed origin")?;
            }
        }

        let client_id = format!("client_{}", nanoid::nanoid!(20));
        let client_secret = Self::generate_secret();
        let secret_hash = Self::hash_secret(&client_secret);

        let redirect_uris = serde_json::to_value(&req.redirect_uris)
            .map_err(|e| AppError::BadRequest(format!("Invalid redirect_uris: {e}")))?;

        let allowed_flows_vec = req
            .allowed_flows
            .unwrap_or_else(|| vec!["authorization_code".to_string(), "refresh_token".to_string()]);
        Self::validate_allowed_flows(&allowed_flows_vec)?;
        let allowed_flows = serde_json::to_value(allowed_flows_vec)
            .map_err(|e| AppError::BadRequest(format!("Invalid allowed_flows: {e}")))?;

        let allowed_scopes_vec = req.allowed_scopes.unwrap_or_else(|| {
            crate::models::DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
        });
        Self::validate_allowed_scopes(&allowed_scopes_vec)?;
        let allowed_scopes = serde_json::to_value(allowed_scopes_vec)
            .map_err(|e| AppError::BadRequest(format!("Invalid allowed_scopes: {e}")))?;

        let public_config = serde_json::to_value(req.public_config.unwrap_or_default())
            .map_err(|e| AppError::BadRequest(format!("Invalid public_config: {e}")))?;

        let app = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (tenant_id, name, type, client_id, client_secret_hash, redirect_uris, allowed_flows, public_config, allowed_scopes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#)
            .bind(tenant_id)
            .bind(req.name)
            .bind(req.r#type)
            .bind(client_id)
            .bind(secret_hash)
            .bind(redirect_uris)
            .bind(allowed_flows)
            .bind(public_config)
            .bind(allowed_scopes)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create app: {e}")))?;

        Ok((app, client_secret))
    }

    pub async fn list_apps(&self, tenant_id: &str) -> Result<Vec<Application>> {
        let apps = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list apps: {e}")))?;

        Ok(apps)
    }

    pub async fn get_app(&self, tenant_id: &str, app_id: &str) -> Result<Application> {
        let app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE id = $1 AND tenant_id = $2",
        )
        .bind(app_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
        .ok_or(AppError::NotFound("Application not found".into()))?;

        Ok(app)
    }
    pub async fn update_app(
        &self,
        tenant_id: &str,
        app_id: &str,
        req: crate::models::UpdateAppRequest,
    ) -> Result<Application> {
        // Construct dynamic query or just update fields if present
        // For simplicity using COALESCE or just checking

        // Handling redirect_uris JSONB update is tricky in pure SQL without building query dynamically if it's optional
        // But let's fetch first to verify ownership then update.

        let _current = self.get_app(tenant_id, app_id).await?;

        // Prepare optional updates
        let name = req.name.as_deref();
        let uris = req.redirect_uris;
        let allowed_flows = req.allowed_flows;
        let allowed_scopes = req.allowed_scopes;
        let public_config = req.public_config;

        let uris_json = match uris {
            Some(u) => {
                Self::validate_urls(&u, "redirect URI")?;
                Some(
                    serde_json::to_value(u)
                    .map_err(|e| AppError::BadRequest(format!("Invalid redirect_uris: {e}")))?,
                )
            }
            None => None,
        };

        let allowed_flows_json = match allowed_flows {
            Some(flows) => {
                Self::validate_allowed_flows(&flows)?;
                Some(
                    serde_json::to_value(flows)
                        .map_err(|e| AppError::BadRequest(format!("Invalid allowed_flows: {e}")))?,
                )
            }
            None => None,
        };

        let allowed_scopes_json = match allowed_scopes {
            Some(scopes) => {
                Self::validate_allowed_scopes(&scopes)?;
                Some(
                    serde_json::to_value(scopes)
                        .map_err(|e| AppError::BadRequest(format!("Invalid allowed_scopes: {e}")))?,
                )
            }
            None => None,
        };

        let public_config_json = match public_config {
            Some(config) => {
                if let Some(origins) = &config.allowed_origins {
                    Self::validate_urls(origins, "allowed origin")?;
                }
                Some(
                    serde_json::to_value(config)
                        .map_err(|e| AppError::BadRequest(format!("Invalid public_config: {e}")))?,
                )
            }
            None => None,
        };

        let app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications
            SET 
                name = COALESCE($3, name),
                redirect_uris = COALESCE($4, redirect_uris),
                allowed_flows = COALESCE($5, allowed_flows),
                public_config = COALESCE($6, public_config),
                allowed_scopes = COALESCE($7, allowed_scopes),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(app_id)
        .bind(tenant_id)
        .bind(name)
        .bind(uris_json)
        .bind(allowed_flows_json)
        .bind(public_config_json)
        .bind(allowed_scopes_json)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update app: {e}")))?;

        Ok(app)
    }

    /// Delete an application by ID. Tenant-scoped to prevent cross-tenant deletion.
    pub async fn delete_app(&self, tenant_id: &str, app_id: &str) -> Result<()> {
        let rows_affected =
            sqlx::query("DELETE FROM applications WHERE id = $1 AND tenant_id = $2")
                .bind(app_id)
                .bind(tenant_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to delete app: {e}")))?
                .rows_affected();

        if rows_affected == 0 {
            return Err(AppError::NotFound("Application not found".into()));
        }

        Ok(())
    }

    /// Rotate a confidential client secret and return the updated app and plain secret.
    pub async fn rotate_secret(&self, tenant_id: &str, app_id: &str) -> Result<(Application, String)> {
        let client_secret = Self::generate_secret();
        let secret_hash = Self::hash_secret(&client_secret);

        let app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications
            SET
                client_secret_hash = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(app_id)
        .bind(tenant_id)
        .bind(secret_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to rotate app secret: {e}")))?
        .ok_or(AppError::NotFound("Application not found".into()))?;

        Ok((app, client_secret))
    }
}
