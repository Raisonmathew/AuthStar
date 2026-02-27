//! Tenant Policy Management API
//!
//! REST endpoints for tenants to manage their EIAA policies.
//! Policies define authorization rules compiled to WASM capsules.
//!
//! ## Endpoints
//! - GET  /api/v1/policies           - List policies for current tenant
//! - POST /api/v1/policies           - Create new policy version
//! - GET  /api/v1/policies/:action   - Get specific policy
//! - POST /api/v1/policies/:action/activate - Activate a version

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};
use auth_core::Claims;
use shared_types::AppError;
use crate::state::AppState;
use crate::services::CapsuleCacheService;

/// List policies query params
#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Create policy request
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    /// Action this policy applies to (e.g., "login", "billing:read")
    pub action: String,
    /// Policy specification (AST)
    pub spec: serde_json::Value,
    /// Optional description
    pub description: Option<String>,
}

/// Activate policy request
#[derive(Debug, Deserialize)]
pub struct ActivatePolicyRequest {
    /// Version to activate
    pub version: i32,
}

/// Policy summary (for list endpoint)
#[derive(Debug, Serialize, FromRow)]
pub struct PolicySummary {
    pub id: String,
    pub action: String,
    pub version: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Full policy details
#[derive(Debug, Serialize, FromRow)]
pub struct PolicyDetails {
    pub id: String,
    pub tenant_id: String,
    pub action: String,
    pub version: i32,
    pub spec: serde_json::Value,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Policy version entry
#[derive(Debug, Serialize)]
pub struct PolicyVersion {
    pub id: String,
    pub version: i32,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

/// Create the policies router
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/:action", get(get_policy))
        .route("/:action/activate", post(activate_policy))
        .route("/:action/versions", get(list_versions))
}

/// List all policies for the current tenant
///
/// GET /api/v1/policies
async fn list_policies(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<PolicySummary>>, AppError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let policies = sqlx::query_as::<_, PolicySummary>(
        r#"
        SELECT 
            p.id,
            p.action,
            p.version,
            COALESCE(a.is_active, false) as is_active,
            p.created_at
        FROM eiaa_policies p
        LEFT JOIN eiaa_policy_activations a ON p.id = a.policy_id AND a.is_active = true
        WHERE p.tenant_id = $1
        ORDER BY p.action, p.version DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch policies: {}", e)))?;

    Ok(Json(policies))
}

/// Create a new policy version
///
/// POST /api/v1/policies
async fn create_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyVersion>), AppError> {
    // Validate action format
    if req.action.is_empty() || req.action.len() > 100 {
        return Err(AppError::BadRequest("Invalid action name".to_string()));
    }

    // Validate AST structure (basic check)
    if !req.spec.is_object() {
        return Err(AppError::BadRequest("Policy spec must be a JSON object".to_string()));
    }

    // Get next version number
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM eiaa_policies WHERE tenant_id = $1 AND action = $2",
    )
    .bind(&claims.tenant_id)
    .bind(&req.action)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to get next version: {}", e)))?;

    // Insert new policy version
    let id = format!("pol_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    
    sqlx::query(
        r#"
        INSERT INTO eiaa_policies (id, tenant_id, action, version, spec)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&id)
    .bind(&claims.tenant_id)
    .bind(&req.action)
    .bind(next_version)
    .bind(&req.spec)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create policy: {}", e)))?;

    tracing::info!(
        "Created policy version {} for action={} tenant={}",
        next_version, req.action, claims.tenant_id
    );

    Ok((StatusCode::CREATED, Json(PolicyVersion {
        id,
        version: next_version,
        action: req.action,
        created_at: Utc::now(),
    })))
}

/// Get a specific policy by action
///
/// GET /api/v1/policies/:action
async fn get_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(action): Path<String>,
) -> Result<Json<PolicyDetails>, AppError> {
    // Get the active version, or latest if none active
    let policy = sqlx::query_as::<_, PolicyDetails>(
        r#"
        SELECT 
            p.id,
            p.tenant_id,
            p.action,
            p.version,
            p.spec,
            p.created_at,
            p.created_at as updated_at,
            COALESCE(a.is_active, false) as is_active,
            NULL as description
        FROM eiaa_policies p
        LEFT JOIN eiaa_policy_activations a ON p.id = a.policy_id AND a.is_active = true
        WHERE p.tenant_id = $1 AND p.action = $2
        ORDER BY COALESCE(a.is_active, false) DESC, p.version DESC
        LIMIT 1
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&action)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch policy: {}", e)))?;

    match policy {
        Some(p) => Ok(Json(p)),
        None => Err(AppError::NotFound(format!("Policy not found: {}", action))),
    }
}

/// Activate a specific policy version
///
/// POST /api/v1/policies/:action/activate
async fn activate_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(action): Path<String>,
    Json(req): Json<ActivatePolicyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Verify policy exists
    let policy_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM eiaa_policies WHERE tenant_id = $1 AND action = $2 AND version = $3",
    )
    .bind(&claims.tenant_id)
    .bind(&action)
    .bind(req.version)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to verify policy: {}", e)))?;

    let policy_id = match policy_id {
        Some(id) => id,
        None => return Err(AppError::NotFound(format!(
            "Policy not found: {} version {}", action, req.version
        ))),
    };

    // Transaction: deactivate current, activate new
    let mut tx = state.db.begin().await
        .map_err(|e| AppError::Internal(format!("Failed to start transaction: {}", e)))?;

    // Deactivate all versions for this action
    sqlx::query(
        r#"
        UPDATE eiaa_policy_activations
        SET is_active = false, updated_at = NOW()
        WHERE policy_id IN (
            SELECT id FROM eiaa_policies WHERE tenant_id = $1 AND action = $2
        )
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&action)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to deactivate policies: {}", e)))?;

    // Activate the specified version
    sqlx::query(
        r#"
        INSERT INTO eiaa_policy_activations (policy_id, is_active, updated_at)
        VALUES ($1, true, NOW())
        ON CONFLICT (policy_id) DO UPDATE SET is_active = true, updated_at = NOW()
        "#,
    )
    .bind(&policy_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to activate policy: {}", e)))?;

    tx.commit().await
        .map_err(|e| AppError::Internal(format!("Failed to commit transaction: {}", e)))?;

    // Invalidate capsule cache
    // Note: CapsuleCacheService would need to be added to state
    // For now, log the invalidation need
    tracing::info!(
        "Activated policy {} version {} for tenant={} - cache invalidation needed",
        action, req.version, claims.tenant_id
    );

    Ok(Json(serde_json::json!({
        "status": "activated",
        "action": action,
        "version": req.version,
    })))
}

/// List all versions of a policy
///
/// GET /api/v1/policies/:action/versions
async fn list_versions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(action): Path<String>,
) -> Result<Json<Vec<PolicySummary>>, AppError> {
    let versions = sqlx::query_as::<_, PolicySummary>(
        r#"
        SELECT 
            p.id,
            p.action,
            p.version,
            COALESCE(a.is_active, false) as is_active,
            p.created_at
        FROM eiaa_policies p
        LEFT JOIN eiaa_policy_activations a ON p.id = a.policy_id AND a.is_active = true
        WHERE p.tenant_id = $1 AND p.action = $2
        ORDER BY p.version DESC
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&action)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch versions: {}", e)))?;

    Ok(Json(versions))
}
