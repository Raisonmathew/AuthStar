#![allow(dead_code)]
use axum::{
    extract::{Path, State, Extension},
    routing::{get, patch},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use shared_types::AppError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct BrandingConfig {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub background_color: String,
    pub text_color: String,
    pub font_family: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub fields: FieldsConfig,
    pub oauth: OAuthConfig,
    pub custom_css: String,
    pub redirect_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FieldsConfig {
    pub email: bool,
    pub password: bool,
    pub phone: bool,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub google: OAuthProvider,
    pub github: OAuthProvider,
    pub microsoft: OAuthProvider,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub enabled: bool,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub branding: BrandingConfig,
    pub auth_config: AuthConfig,
    pub custom_domain: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        // Public read routes (no auth needed - org config for hosted pages)
        .route("/api/organizations/:id", get(get_organization))
        // Protected write routes need auth + EIAA in router.rs
        .route("/api/organizations/:id/branding", patch(update_branding))
        .route("/api/organizations/:id/auth-config", patch(update_auth_config))
        // EIAA Login Methods - triggers policy compilation
        .route("/api/org-config/login-methods", get(get_login_methods))
        .route("/api/org-config/login-methods", patch(update_login_methods))
}

/// Public read routes (for hosted pages, no auth needed)
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/:id", get(get_organization))
}

/// Protected write routes (requires auth + EIAA)
pub fn write_routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/:id/branding", patch(update_branding))
        .route("/api/organizations/:id/auth-config", patch(update_auth_config))
        .route("/api/org-config/login-methods", get(get_login_methods))
        .route("/api/org-config/login-methods", patch(update_login_methods))
}

/// Get organization configuration
async fn get_organization(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<OrganizationResponse>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, name, slug, branding, auth_config, custom_domain
        FROM organizations
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| AppError::NotFound("Organization not found".into()))?;

    let id: String = row.try_get("id").unwrap_or_default();
    let name: String = row.try_get("name").unwrap_or_default();
    let slug: String = row.try_get("slug").unwrap_or_default();
    let branding_val: Option<serde_json::Value> = row.try_get("branding").ok();
    let auth_config_val: Option<serde_json::Value> = row.try_get("auth_config").ok();
    let custom_domain: Option<String> = row.try_get("custom_domain").ok();

    let branding: BrandingConfig = branding_val.and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or(BrandingConfig {
            logo_url: None,
            primary_color: "#3B82F6".to_string(),
            background_color: "#FFFFFF".to_string(),
            text_color: "#1F2937".to_string(),
            font_family: "Inter".to_string(),
        });

    let auth_config: AuthConfig = auth_config_val.and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_else(|| AuthConfig {
            fields: FieldsConfig {
                email: true,
                password: true,
                phone: false,
                custom_fields: vec![],
            },
            oauth: OAuthConfig {
                google: OAuthProvider { enabled: false, client_id: None, client_secret: None },
                github: OAuthProvider { enabled: false, client_id: None, client_secret: None },
                microsoft: OAuthProvider { enabled: false, client_id: None, client_secret: None },
            },
            custom_css: String::new(),
            redirect_urls: vec![format!("{}/callback", state.config.frontend_url)],
        });

    Ok(Json(OrganizationResponse {
        id,
        name,
        slug,
        branding,
        auth_config,
        custom_domain,
    }))
}

/// Update organization branding
async fn update_branding(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
    Json(branding): Json<BrandingConfig>,
) -> Result<Json<BrandingConfig>, AppError> {
    if org_id != claims.tenant_id {
        return Err(AppError::Forbidden("Cannot modify another organization's branding".into()));
    }
    let branding_json = serde_json::to_value(&branding)
        .map_err(|e| AppError::Internal(format!("JSON serialization failed: {e}")))?;

    sqlx::query(
        r#"
        UPDATE organizations
        SET branding = $1, updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(branding_json)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?;

    Ok(Json(branding))
}

/// Update organization auth configuration
async fn update_auth_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
    Json(config): Json<AuthConfig>,
) -> Result<Json<AuthConfig>, AppError> {
    if org_id != claims.tenant_id {
        return Err(AppError::Forbidden("Cannot modify another organization's auth config".into()));
    }
    let config_json = serde_json::to_value(&config)
        .map_err(|e| AppError::Internal(format!("JSON serialization failed: {e}")))?;

    sqlx::query(
        r#"
        UPDATE organizations
        SET auth_config = $1, updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(config_json)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?;

    Ok(Json(config))
}

// ===============================================
// EIAA Login Methods Configuration
// ===============================================

use crate::services::policy_compiler::LoginMethodsConfig;
use auth_core::jwt::Claims;

/// Get current login methods configuration
async fn get_login_methods(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<LoginMethodsConfig>, AppError> {
    let tenant_id = &claims.tenant_id;
    
    let row = sqlx::query(
        "SELECT login_methods FROM organizations WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?;
    
    match row {
        Some(row) => {
            let config: Option<serde_json::Value> = row.try_get("login_methods").ok();
            let parsed = config
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            Ok(Json(parsed))
        }
        None => Ok(Json(LoginMethodsConfig::default())),
    }
}

/// Update login methods and recompile policies
async fn update_login_methods(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(config): Json<LoginMethodsConfig>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = &claims.tenant_id;
    let config_json = serde_json::to_value(&config)
        .map_err(|e| AppError::Internal(format!("JSON serialization failed: {e}")))?;
    
    // Store login methods config
    sqlx::query(
        r#"
        UPDATE organizations
        SET login_methods = $1, updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(&config_json)
    .bind(tenant_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?;
    
    // EIAA: Compile and store policies (single authority)
    let require_email_verification = state.config.require_email_verification;
    
    crate::services::policy_compiler::PolicyStorage::compile_and_store_all(
        &state.db,
        tenant_id,
        &config,
        require_email_verification,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Policy compilation failed: {e}")))?;
    
    tracing::info!(tenant_id = %tenant_id, "Login methods updated and policies recompiled");
    
    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "Login methods saved and policies recompiled"
    })))
}
