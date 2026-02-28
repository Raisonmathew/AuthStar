use axum::{
    extract::{Path, State, Extension},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use crate::state::AppState;
use crate::services::sso_encryption::SsoEncryption;
use shared_types::AppError;
use auth_core::jwt::Claims;

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoConnection {
    pub id: String,
    pub tenant_id: String,
    pub r#type: String, // 'oauth', 'oidc', 'saml'
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub enabled: bool,
    pub config: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSsoConnectionRequest {
    // tenant_id is sourced from Claims, NOT from body
    pub r#type: String,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSsoConnectionRequest {
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connections))
        .route("/", post(create_connection))
        .route("/:id", get(get_connection))
        .route("/:id", put(update_connection))
        .route("/:id", delete(delete_connection))
}

/// List SSO connections — scoped to authenticated tenant.
///
/// MEDIUM-6: `client_secret` is REDACTED in list responses.
/// Admins can see that a secret is configured but cannot retrieve it.
/// Use the dedicated GET /:id endpoint to verify a connection works.
async fn list_connections(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<SsoConnection>>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, type, provider, name, client_id, client_secret,
               redirect_uri, discovery_url, authorization_url, token_url, userinfo_url,
               scope, enabled, config, created_at
        FROM sso_connections
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(&claims.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let connections = rows.into_iter().map(|row| {
        let stored_secret: String = row.get("client_secret");
        // MEDIUM-6: Redact client_secret in list — show presence indicator only
        let secret_display = if stored_secret.is_empty() {
            String::new()
        } else {
            "***configured***".to_string()
        };

        SsoConnection {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            r#type: row.get("type"),
            provider: row.get("provider"),
            name: row.get("name"),
            client_id: row.get("client_id"),
            client_secret: secret_display,
            redirect_uri: row.get("redirect_uri"),
            discovery_url: row.get("discovery_url"),
            authorization_url: row.get("authorization_url"),
            token_url: row.get("token_url"),
            userinfo_url: row.get("userinfo_url"),
            scope: row.get("scope"),
            enabled: row.get("enabled"),
            config: row.get("config"),
            created_at: row.get("created_at"),
        }
    }).collect();

    Ok(Json(connections))
}

/// Create SSO connection — tenant_id from Claims (not request body).
///
/// MEDIUM-6: `client_secret` is encrypted with AES-256-GCM before storage.
async fn create_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateSsoConnectionRequest>,
) -> Result<Json<SsoConnection>, AppError> {
    let id = shared_types::id_generator::generate_id("sso");
    let tenant_id = &claims.tenant_id;

    // Validate type
    if !["oauth", "oidc", "saml"].contains(&payload.r#type.as_str()) {
        return Err(AppError::Validation("Invalid type. Must be oauth, oidc, or saml".into()));
    }

    let config_json = payload.config.clone().unwrap_or(serde_json::json!({}));

    // MEDIUM-6: Encrypt client_secret before storage
    let enc = SsoEncryption::from_env();
    let encrypted_secret = enc.encrypt(&payload.client_secret)
        .map_err(|e| AppError::Internal(format!("Failed to encrypt SSO secret: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO sso_connections (
            id, tenant_id, type, provider, name, client_id, client_secret,
            redirect_uri, discovery_url, authorization_url, token_url, userinfo_url,
            scope, config
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#
    )
    .bind(&id)
    .bind(tenant_id) // From Claims, not request body
    .bind(&payload.r#type)
    .bind(&payload.provider)
    .bind(&payload.name)
    .bind(&payload.client_id)
    .bind(&encrypted_secret)  // Store encrypted
    .bind(&payload.redirect_uri)
    .bind(&payload.discovery_url)
    .bind(&payload.authorization_url)
    .bind(&payload.token_url)
    .bind(&payload.userinfo_url)
    .bind(&payload.scope)
    .bind(&config_json)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Return redacted secret in response — caller already knows what they submitted
    Ok(Json(SsoConnection {
        id,
        tenant_id: tenant_id.clone(),
        r#type: payload.r#type,
        provider: payload.provider,
        name: payload.name,
        client_id: payload.client_id,
        client_secret: "***configured***".to_string(),
        redirect_uri: payload.redirect_uri,
        discovery_url: payload.discovery_url,
        authorization_url: payload.authorization_url,
        token_url: payload.token_url,
        userinfo_url: payload.userinfo_url,
        scope: payload.scope,
        enabled: true,
        config: Some(config_json),
        created_at: chrono::Utc::now(),
    }))
}

/// Get SSO connection — scoped to tenant.
///
/// MEDIUM-6: `client_secret` is redacted in the response.
/// The secret is only decrypted internally when used for OAuth token exchange.
async fn get_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<SsoConnection>, AppError> {
    let row = sqlx::query(
        "SELECT * FROM sso_connections WHERE id = $1 AND tenant_id = $2"
    )
    .bind(id)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or(AppError::NotFound("Connection not found".into()))?;

    let stored_secret: String = row.get("client_secret");
    let secret_display = if stored_secret.is_empty() {
        String::new()
    } else {
        "***configured***".to_string()
    };

    Ok(Json(SsoConnection {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        r#type: row.get("type"),
        provider: row.get("provider"),
        name: row.get("name"),
        client_id: row.get("client_id"),
        client_secret: secret_display,  // MEDIUM-6: Redacted
        redirect_uri: row.get("redirect_uri"),
        discovery_url: row.get("discovery_url"),
        authorization_url: row.get("authorization_url"),
        token_url: row.get("token_url"),
        userinfo_url: row.get("userinfo_url"),
        scope: row.get("scope"),
        enabled: row.get("enabled"),
        config: row.get("config"),
        created_at: row.get("created_at"),
    }))
}

/// Update SSO connection — ALL updates scoped to tenant
async fn update_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSsoConnectionRequest>,
) -> Result<StatusCode, AppError> {
    // Verify connection belongs to tenant before any updates
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM sso_connections WHERE id = $1 AND tenant_id = $2"
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if exists.is_none() {
        return Err(AppError::NotFound("Connection not found".into()));
    }

    // Build dynamic UPDATE — every field change is tenant-scoped
    let mut tx = state.db.begin().await.map_err(|e| AppError::Internal(e.to_string()))?;

    if let Some(name) = payload.name {
        sqlx::query("UPDATE sso_connections SET name = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(name).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(client_id) = payload.client_id {
        sqlx::query("UPDATE sso_connections SET client_id = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(client_id).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(client_secret) = payload.client_secret {
        // MEDIUM-6: Encrypt new secret before storing
        let enc = SsoEncryption::from_env();
        let encrypted_secret = enc.encrypt(&client_secret)
            .map_err(|e| AppError::Internal(format!("Failed to encrypt SSO secret: {}", e)))?;
        sqlx::query("UPDATE sso_connections SET client_secret = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(encrypted_secret).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(redirect_uri) = payload.redirect_uri {
        sqlx::query("UPDATE sso_connections SET redirect_uri = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(redirect_uri).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(discovery_url) = payload.discovery_url {
        sqlx::query("UPDATE sso_connections SET discovery_url = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(discovery_url).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(authorization_url) = payload.authorization_url {
        sqlx::query("UPDATE sso_connections SET authorization_url = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(authorization_url).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(token_url) = payload.token_url {
        sqlx::query("UPDATE sso_connections SET token_url = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(token_url).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(userinfo_url) = payload.userinfo_url {
        sqlx::query("UPDATE sso_connections SET userinfo_url = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(userinfo_url).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(scope) = payload.scope {
        sqlx::query("UPDATE sso_connections SET scope = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(scope).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(enabled) = payload.enabled {
        sqlx::query("UPDATE sso_connections SET enabled = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(enabled).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(config) = payload.config {
        sqlx::query("UPDATE sso_connections SET config = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(config).bind(&id).bind(&claims.tenant_id).execute(&mut *tx).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    
    tx.commit().await.map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

/// Delete SSO connection — scoped to tenant
async fn delete_connection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM sso_connections WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&claims.tenant_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Connection not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}
