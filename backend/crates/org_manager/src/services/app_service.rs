use shared_types::{AppError, Result};
use sqlx::PgPool;
use crate::models::{Application, CreateAppRequest};
use rand::Rng;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

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

    pub async fn create_app(&self, tenant_id: &str, req: CreateAppRequest) -> Result<(Application, String)> {
        let client_id = format!("client_{}", nanoid::nanoid!(20));
        let client_secret = Self::generate_secret();
        let secret_hash = Self::hash_secret(&client_secret);

        let redirect_uris = serde_json::to_value(&req.redirect_uris)
            .map_err(|e| AppError::BadRequest(format!("Invalid redirect_uris: {e}")))?;
        
        // Default flows for now
        let allowed_flows = serde_json::json!(["authorization_code", "refresh_token"]);

        let app = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (tenant_id, name, type, client_id, client_secret_hash, redirect_uris, allowed_flows)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#)
            .bind(tenant_id)
            .bind(req.name)
            .bind(req.r#type)
            .bind(client_id)
            .bind(secret_hash)
            .bind(redirect_uris)
            .bind(allowed_flows)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create app: {e}")))?;

        Ok((app, client_secret))
    }

    pub async fn list_apps(&self, tenant_id: &str) -> Result<Vec<Application>> {
        let apps = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE tenant_id = $1 ORDER BY created_at DESC"
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list apps: {e}")))?;

        Ok(apps)
    }

    pub async fn get_app(&self, tenant_id: &str, app_id: &str) -> Result<Application> {
        let app = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE id = $1 AND tenant_id = $2"
        )
        .bind(app_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
        .ok_or(AppError::NotFound("Application not found".into()))?;

        Ok(app)
    }
    pub async fn update_app(&self, tenant_id: &str, app_id: &str, req: crate::models::UpdateAppRequest) -> Result<Application> {
        // Construct dynamic query or just update fields if present
        // For simplicity using COALESCE or just checking
        
        // Handling redirect_uris JSONB update is tricky in pure SQL without building query dynamically if it's optional
        // But let's fetch first to verify ownership then update.
        
        let _current = self.get_app(tenant_id, app_id).await?;

        // Prepare optional updates
        let name = req.name.as_deref();
        let uris = req.redirect_uris;

        let uris_json = match uris {
            Some(u) => Some(serde_json::to_value(u)
                .map_err(|e| AppError::BadRequest(format!("Invalid redirect_uris: {e}")))?),
            None => None,
        };

        let app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications
            SET 
                name = COALESCE($3, name),
                redirect_uris = COALESCE($4, redirect_uris),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#)
            .bind(app_id)
            .bind(tenant_id)
            .bind(name)
            .bind(uris_json) // Simple serialization
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update app: {e}")))?;

        Ok(app)
    }

    /// Delete an application by ID. Tenant-scoped to prevent cross-tenant deletion.
    pub async fn delete_app(&self, tenant_id: &str, app_id: &str) -> Result<()> {
        let rows_affected = sqlx::query(
            "DELETE FROM applications WHERE id = $1 AND tenant_id = $2"
        )
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
}
