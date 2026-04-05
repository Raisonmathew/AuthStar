//! Test Data Seeding Endpoint
//!
//! Provides endpoints for E2E tests to seed and clean up test data.
//! Only available in development/test environments.
//!
//! All queries use `sqlx::query` (no compile-time macro) to avoid requiring
//! an offline cache or live DB during `cargo check`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, AppError, Result};

use crate::state::AppState;

/// Test seed router - only enabled in non-production environments
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/seed/user", post(seed_user))
        .route("/seed/organization", post(seed_organization))
        .route("/seed/api-key", post(seed_api_key))
        .route("/seed/policy", post(seed_policy))
        .route("/seed/mfa-factor", post(seed_mfa_factor))
        .route(
            "/cleanup/:resource_type/:resource_id",
            delete(cleanup_resource),
        )
        .route("/cleanup/all", delete(cleanup_all))
        .with_state(state)
}

// -- Request / Response structs -----------------------------------------------

#[derive(Debug, Deserialize)]
struct SeedUserRequest {
    email: String,
    password: String,
    first_name: Option<String>,
    last_name: Option<String>,
    /// If provided the user will be added as a 'member' of this organisation.
    org_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedUserResponse {
    user_id: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct SeedOrganizationRequest {
    name: String,
    slug: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedOrganizationResponse {
    org_id: String,
    name: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct SeedApiKeyRequest {
    name: String,
    org_id: String,
    user_id: String,
}

#[derive(Debug, Serialize)]
struct SeedApiKeyResponse {
    key_id: String,
    /// Full plaintext key - returned once, never stored.
    key: String,
}

#[derive(Debug, Deserialize)]
struct SeedPolicyRequest {
    name: String,
    org_id: String,
    action: String,
}

#[derive(Debug, Serialize)]
struct SeedPolicyResponse {
    policy_id: String,
}

#[derive(Debug, Deserialize)]
struct SeedMfaFactorRequest {
    user_id: String,
    tenant_id: String,
    factor_type: String, // "totp" | "backup_codes"
}

#[derive(Debug, Serialize)]
struct SeedMfaFactorResponse {
    factor_id: String,
    secret: Option<String>,
    backup_codes: Option<Vec<String>>,
}

// -- Handlers -----------------------------------------------------------------

/// Seed a test user.
///
/// Creates rows in `users`, `identities` (type=email, verified=true),
/// and `passwords`.  Optionally creates a `memberships` row if `org_id` is given.
async fn seed_user(
    State(state): State<AppState>,
    Json(req): Json<SeedUserRequest>,
) -> Result<Json<SeedUserResponse>> {
    guard_non_production()?;

    let password_hash = auth_core::hash_password(&req.password)?;
    let user_id = generate_id("user");

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO users (id, first_name, last_name, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_id)
    .bind(&req.first_name)
    .bind(&req.last_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO identities (id, user_id, type, identifier, verified, created_at, updated_at)
         VALUES ($1, $2, 'email', $3, true, NOW(), NOW())",
    )
    .bind(generate_id("ident"))
    .bind(&user_id)
    .bind(&req.email)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO passwords (id, user_id, password_hash, created_at)
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(generate_id("pass"))
    .bind(&user_id)
    .bind(&password_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(ref org_id) = req.org_id {
        sqlx::query(
            "INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
             VALUES ($1, $2, $3, 'member', NOW(), NOW())",
        )
        .bind(generate_id("memb"))
        .bind(org_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(SeedUserResponse {
        user_id,
        email: req.email,
    }))
}

/// Seed a test organisation.
async fn seed_organization(
    State(state): State<AppState>,
    Json(req): Json<SeedOrganizationRequest>,
) -> Result<Json<SeedOrganizationResponse>> {
    guard_non_production()?;

    let org_id = generate_id("org");
    let slug = req
        .slug
        .unwrap_or_else(|| format!("test-org-{}", &org_id[4..]));

    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&org_id)
    .bind(&req.name)
    .bind(&slug)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(SeedOrganizationResponse {
        org_id,
        name: req.name,
        slug,
    }))
}

/// Seed a test API key.
///
/// Key format: `ask_<8-char-prefix>_<32-char-random>`.
/// Full plaintext key is returned once and not stored.
async fn seed_api_key(
    State(state): State<AppState>,
    Json(req): Json<SeedApiKeyRequest>,
) -> Result<Json<SeedApiKeyResponse>> {
    guard_non_production()?;

    let key_id = generate_id("akey");
    let random = uuid::Uuid::new_v4().simple().to_string(); // 32 hex chars
    let key_prefix = random[..8].to_string();
    let key = format!("ask_{}_{}", key_prefix, uuid::Uuid::new_v4().simple());
    let key_hash = auth_core::hash_password(&key)?;

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, key_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, '{}', NOW())",
    )
    .bind(&key_id)
    .bind(&req.org_id)
    .bind(&req.user_id)
    .bind(&req.name)
    .bind(&key_prefix)
    .bind(&key_hash)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(SeedApiKeyResponse { key_id, key }))
}

/// Seed a test EIAA policy (minimal allow-all spec).
async fn seed_policy(
    State(state): State<AppState>,
    Json(req): Json<SeedPolicyRequest>,
) -> Result<Json<SeedPolicyResponse>> {
    guard_non_production()?;

    let policy_id = generate_id("eipol");
    let spec = serde_json::json!({
        "version": "1.0",
        "name": req.name,
        "steps": [{ "type": "Allow", "reason": "Test policy - allow all" }]
    });

    sqlx::query(
        "INSERT INTO eiaa_policies (id, tenant_id, action, version, spec, created_at)
         VALUES ($1, $2, $3, 1, $4, NOW())",
    )
    .bind(&policy_id)
    .bind(&req.org_id)
    .bind(&req.action)
    .bind(&spec)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(SeedPolicyResponse { policy_id }))
}

/// Seed a test MFA factor.
///
/// Factor-specific data is stored in the `factor_data` JSONB column.
/// Inserted with `status = 'active'` so it is immediately usable in tests.
async fn seed_mfa_factor(
    State(state): State<AppState>,
    Json(req): Json<SeedMfaFactorRequest>,
) -> Result<Json<SeedMfaFactorResponse>> {
    guard_non_production()?;

    let factor_id = generate_id("ufact");

    let (factor_data, response) = match req.factor_type.as_str() {
        "totp" => {
            let secret = "JBSWY3DPEHPK3PXP".to_string();
            let data = serde_json::json!({ "secret": secret });
            let resp = SeedMfaFactorResponse {
                factor_id: factor_id.clone(),
                secret: Some(secret),
                backup_codes: None,
            };
            (data, resp)
        }
        "backup_codes" => {
            let codes: Vec<String> = (0..10).map(|i| format!("TEST-CODE-{i:04}")).collect();
            let data = serde_json::json!({ "codes": codes });
            let resp = SeedMfaFactorResponse {
                factor_id: factor_id.clone(),
                secret: None,
                backup_codes: Some(codes),
            };
            (data, resp)
        }
        _ => {
            return Err(AppError::Validation(
                "Invalid factor type. Use 'totp' or 'backup_codes'".into(),
            ))
        }
    };

    sqlx::query(
        "INSERT INTO user_factors (id, user_id, tenant_id, factor_type, factor_data, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'active', NOW(), NOW())",
    )
    .bind(&factor_id)
    .bind(&req.user_id)
    .bind(&req.tenant_id)
    .bind(&req.factor_type)
    .bind(&factor_data)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(response))
}

/// Delete a specific test resource by ID.
async fn cleanup_resource(
    State(state): State<AppState>,
    Path((resource_type, resource_id)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    guard_non_production()?;

    let sql = match resource_type.as_str() {
        "user" => "DELETE FROM users         WHERE id = $1",
        "organization" => "DELETE FROM organizations WHERE id = $1",
        "api-key" => "DELETE FROM api_keys      WHERE id = $1",
        "policy" => "DELETE FROM eiaa_policies WHERE id = $1",
        "mfa-factor" => "DELETE FROM user_factors  WHERE id = $1",
        _ => return Err(AppError::Validation("Invalid resource type".into())),
    };

    sqlx::query(sql)
        .bind(&resource_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete all test data.
///
/// Removes organisations whose slug starts with `test-org-` (cascade handles
/// memberships / api_keys) and users who have a test email identity.
async fn cleanup_all(State(state): State<AppState>) -> Result<impl IntoResponse> {
    guard_non_production()?;

    sqlx::query("DELETE FROM organizations WHERE slug LIKE 'test-org-%'")
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "DELETE FROM users WHERE id IN (
             SELECT user_id FROM identities
             WHERE  type = 'email'
               AND  (identifier LIKE '%test%' OR identifier LIKE '%.test')
         )",
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// -- Helpers ------------------------------------------------------------------

fn guard_non_production() -> Result<()> {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
        return Err(AppError::Unauthorized(
            "Test seeding not available in production".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn guard_allows_non_production() {
        std::env::remove_var("ENVIRONMENT");
        assert!(super::guard_non_production().is_ok());
    }
}

// Made with Bob
