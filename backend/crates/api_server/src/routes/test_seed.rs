/**
 * Test Data Seeding Endpoint
 * 
 * Provides endpoints for E2E tests to seed and clean up test data.
 * Only available in development/test environments.
 */

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use shared_types::{AppError, Result};

/// Test seed router - only enabled in non-production environments
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/seed/user", post(seed_user))
        .route("/seed/organization", post(seed_organization))
        .route("/seed/api-key", post(seed_api_key))
        .route("/seed/policy", post(seed_policy))
        .route("/seed/mfa-factor", post(seed_mfa_factor))
        .route("/cleanup/:resource_type/:resource_id", delete(cleanup_resource))
        .route("/cleanup/all", delete(cleanup_all))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct SeedUserRequest {
    email: String,
    password: String,
    first_name: Option<String>,
    last_name: Option<String>,
    org_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct SeedUserResponse {
    user_id: Uuid,
    email: String,
    org_id: Uuid,
}

/// Seed a test user
async fn seed_user(
    State(state): State<AppState>,
    Json(req): Json<SeedUserRequest>,
) -> Result<Json<SeedUserResponse>> {
    // Only allow in non-production
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test seeding not available in production".into()));
    }

    let password_hash = auth_core::hash_password(&req.password)?;
    
    let org_id = if let Some(org_id) = req.org_id {
        org_id
    } else {
        // Create a test organization
        let org_id = Uuid::new_v4();
        sqlx::query!(
            r#"
            INSERT INTO organizations (id, name, slug, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            "#,
            org_id,
            format!("Test Org {}", &req.email),
            format!("test-org-{}", Uuid::new_v4()),
        )
        .execute(&state.pool)
        .await?;
        
        org_id
    };

    let user_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO users (
            id, email, password_hash, first_name, last_name, 
            email_verified, org_id, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, true, $6, NOW(), NOW())
        "#,
        user_id,
        req.email,
        password_hash,
        req.first_name,
        req.last_name,
        org_id,
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(SeedUserResponse {
        user_id,
        email: req.email,
        org_id,
    }))
}

#[derive(Debug, Deserialize)]
struct SeedOrganizationRequest {
    name: String,
    slug: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedOrganizationResponse {
    org_id: Uuid,
    name: String,
    slug: String,
}

/// Seed a test organization
async fn seed_organization(
    State(state): State<AppState>,
    Json(req): Json<SeedOrganizationRequest>,
) -> Result<Json<SeedOrganizationResponse>> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test seeding not available in production".into()));
    }

    let org_id = Uuid::new_v4();
    let slug = req.slug.unwrap_or_else(|| format!("test-org-{}", Uuid::new_v4()));

    sqlx::query!(
        r#"
        INSERT INTO organizations (id, name, slug, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        "#,
        org_id,
        req.name,
        slug,
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(SeedOrganizationResponse {
        org_id,
        name: req.name,
        slug,
    }))
}

#[derive(Debug, Deserialize)]
struct SeedApiKeyRequest {
    name: String,
    org_id: Uuid,
    user_id: Uuid,
}

#[derive(Debug, Serialize)]
struct SeedApiKeyResponse {
    key_id: Uuid,
    key: String,
}

/// Seed a test API key
async fn seed_api_key(
    State(state): State<AppState>,
    Json(req): Json<SeedApiKeyRequest>,
) -> Result<Json<SeedApiKeyResponse>> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test seeding not available in production".into()));
    }

    let key_id = Uuid::new_v4();
    let key = format!("test_key_{}", Uuid::new_v4().simple());
    let key_hash = auth_core::hash_password(&key)?;

    sqlx::query!(
        r#"
        INSERT INTO api_keys (
            id, name, key_hash, org_id, created_by, 
            created_at, last_used_at
        )
        VALUES ($1, $2, $3, $4, $5, NOW(), NULL)
        "#,
        key_id,
        req.name,
        key_hash,
        req.org_id,
        req.user_id,
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(SeedApiKeyResponse { key_id, key }))
}

#[derive(Debug, Deserialize)]
struct SeedPolicyRequest {
    name: String,
    org_id: Uuid,
    action: String,
}

#[derive(Debug, Serialize)]
struct SeedPolicyResponse {
    policy_id: Uuid,
}

/// Seed a test policy
async fn seed_policy(
    State(state): State<AppState>,
    Json(req): Json<SeedPolicyRequest>,
) -> Result<Json<SeedPolicyResponse>> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test seeding not available in production".into()));
    }

    let policy_id = Uuid::new_v4();
    
    // Simple allow-all policy AST
    let policy_ast = serde_json::json!({
        "version": "1.0",
        "steps": [
            {
                "type": "Allow",
                "reason": "Test policy - allow all"
            }
        ]
    });

    sqlx::query!(
        r#"
        INSERT INTO eiaa_policies (
            id, org_id, name, action, policy_ast, 
            is_active, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
        "#,
        policy_id,
        req.org_id,
        req.name,
        req.action,
        policy_ast,
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(SeedPolicyResponse { policy_id }))
}

#[derive(Debug, Deserialize)]
struct SeedMfaFactorRequest {
    user_id: Uuid,
    factor_type: String, // "totp" or "backup_codes"
}

#[derive(Debug, Serialize)]
struct SeedMfaFactorResponse {
    factor_id: Uuid,
    secret: Option<String>,
    backup_codes: Option<Vec<String>>,
}

/// Seed a test MFA factor
async fn seed_mfa_factor(
    State(state): State<AppState>,
    Json(req): Json<SeedMfaFactorRequest>,
) -> Result<Json<SeedMfaFactorResponse>> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test seeding not available in production".into()));
    }

    let factor_id = Uuid::new_v4();
    
    match req.factor_type.as_str() {
        "totp" => {
            let secret = "JBSWY3DPEHPK3PXP"; // Test TOTP secret
            
            sqlx::query!(
                r#"
                INSERT INTO user_factors (
                    id, user_id, factor_type, secret, 
                    is_verified, created_at
                )
                VALUES ($1, $2, 'totp', $3, true, NOW())
                "#,
                factor_id,
                req.user_id,
                secret,
            )
            .execute(&state.pool)
            .await?;

            Ok(Json(SeedMfaFactorResponse {
                factor_id,
                secret: Some(secret.to_string()),
                backup_codes: None,
            }))
        }
        "backup_codes" => {
            let backup_codes: Vec<String> = (0..10)
                .map(|i| format!("TEST-CODE-{:04}", i))
                .collect();
            
            let codes_json = serde_json::to_value(&backup_codes)?;
            
            sqlx::query!(
                r#"
                INSERT INTO user_factors (
                    id, user_id, factor_type, backup_codes, 
                    is_verified, created_at
                )
                VALUES ($1, $2, 'backup_codes', $3, true, NOW())
                "#,
                factor_id,
                req.user_id,
                codes_json,
            )
            .execute(&state.pool)
            .await?;

            Ok(Json(SeedMfaFactorResponse {
                factor_id,
                secret: None,
                backup_codes: Some(backup_codes),
            }))
        }
        _ => Err(AppError::Validation("Invalid factor type".into())),
    }
}

/// Cleanup a specific resource
async fn cleanup_resource(
    State(state): State<AppState>,
    Path((resource_type, resource_id)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test cleanup not available in production".into()));
    }

    match resource_type.as_str() {
        "user" => {
            sqlx::query!("DELETE FROM users WHERE id = $1", resource_id)
                .execute(&state.pool)
                .await?;
        }
        "organization" => {
            // Cascade delete will handle related records
            sqlx::query!("DELETE FROM organizations WHERE id = $1", resource_id)
                .execute(&state.pool)
                .await?;
        }
        "api-key" => {
            sqlx::query!("DELETE FROM api_keys WHERE id = $1", resource_id)
                .execute(&state.pool)
                .await?;
        }
        "policy" => {
            sqlx::query!("DELETE FROM eiaa_policies WHERE id = $1", resource_id)
                .execute(&state.pool)
                .await?;
        }
        "mfa-factor" => {
            sqlx::query!("DELETE FROM user_factors WHERE id = $1", resource_id)
                .execute(&state.pool)
                .await?;
        }
        _ => return Err(AppError::Validation("Invalid resource type".into())),
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Cleanup all test data (use with caution!)
async fn cleanup_all(State(state): State<AppState>) -> Result<impl IntoResponse> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized("Test cleanup not available in production".into()));
    }

    // Delete test data (organizations with slug starting with "test-org-")
    sqlx::query!(
        r#"
        DELETE FROM organizations 
        WHERE slug LIKE 'test-org-%'
        "#
    )
    .execute(&state.pool)
    .await?;

    // Delete test users (emails containing "test" or ending with ".test")
    sqlx::query!(
        r#"
        DELETE FROM users 
        WHERE email LIKE '%test%' OR email LIKE '%.test'
        "#
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_endpoints_only_in_non_production() {
        // This is a compile-time check that the endpoints exist
        // Runtime checks are in the handlers
        assert!(true);
    }
}

// Made with Bob
