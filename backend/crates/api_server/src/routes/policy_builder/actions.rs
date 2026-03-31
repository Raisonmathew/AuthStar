//! Action registry handlers.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use auth_core::Claims;
use shared_types::AppError;
use crate::state::AppState;
use super::types::*;
use super::permissions::{Tier, write_audit};

/// GET /policy-builder/actions
pub async fn list_actions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<ActionItem>>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, action_key, display_name, description, category, is_platform, tenant_id, created_at
        FROM policy_actions
        WHERE tenant_id IS NULL OR tenant_id = $1
        ORDER BY category, display_name
        "#,
        claims.tenant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch actions: {e}")))?;

    Ok(Json(rows.into_iter().map(|r| ActionItem {
        id:           r.id,
        action_key:   r.action_key,
        display_name: r.display_name,
        description:  r.description,
        category:     r.category,
        is_platform:  r.is_platform,
        tenant_id:    r.tenant_id,
        created_at:   r.created_at,
    }).collect()))
}

/// POST /policy-builder/actions
pub async fn create_action(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateActionRequest>,
) -> Result<(StatusCode, Json<ActionItem>), AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    if req.action_key.is_empty() || req.action_key.len() > 100 {
        return Err(AppError::BadRequest("action_key must be 1-100 characters".into()));
    }
    if !req.action_key.chars().all(|c| c.is_alphanumeric() || c == ':' || c == '_' || c == '-') {
        return Err(AppError::BadRequest(
            "action_key may only contain alphanumeric characters, colons, underscores, and hyphens".into()
        ));
    }

    let id = format!("act_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let category = req.category.unwrap_or_else(|| "custom".to_string());
    let now = chrono::Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO policy_actions (id, tenant_id, action_key, display_name, description, category, is_platform)
        VALUES ($1, $2, $3, $4, $5, $6, false)
        "#,
        id, claims.tenant_id, req.action_key, req.display_name, req.description, category
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
            AppError::BadRequest(format!("Action '{}' already exists for this tenant", req.action_key))
        } else {
            AppError::Internal(format!("Failed to create action: {e}"))
        }
    })?;

    Ok((StatusCode::CREATED, Json(ActionItem {
        id,
        action_key:   req.action_key,
        display_name: req.display_name,
        description:  req.description,
        category,
        is_platform:  false,
        tenant_id:    Some(claims.tenant_id),
        created_at:   now,
    })))
}

/// PUT /policy-builder/actions/:id
pub async fn update_action(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(action_id): Path<String>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<Json<ActionItem>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    let rows = sqlx::query!(
        r#"
        UPDATE policy_actions
        SET display_name = COALESCE($1, display_name),
            description  = COALESCE($2, description),
            category     = COALESCE($3, category)
        WHERE id = $4 AND tenant_id = $5 AND is_platform = false
        RETURNING id, action_key, display_name, description, category, is_platform, tenant_id, created_at
        "#,
        req.display_name, req.description, req.category,
        action_id, claims.tenant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update action: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Custom action not found: {action_id}")))?;

    Ok(Json(ActionItem {
        id:           rows.id,
        action_key:   rows.action_key,
        display_name: rows.display_name,
        description:  rows.description,
        category:     rows.category,
        is_platform:  rows.is_platform,
        tenant_id:    rows.tenant_id,
        created_at:   rows.created_at,
    }))
}

/// DELETE /policy-builder/actions/:id
pub async fn delete_action(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(action_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    // Check no active config uses this action
    let in_use: bool = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM policy_builder_configs
            WHERE tenant_id = $1
              AND action_key = (SELECT action_key FROM policy_actions WHERE id = $2)
              AND state != 'archived'
        )
        "#,
        claims.tenant_id, action_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check action usage: {e}")))?
    .unwrap_or(false);

    if in_use {
        return Err(AppError::BadRequest(
            "Cannot delete an action that has active policy configs. Archive the configs first.".into()
        ));
    }

    let rows = sqlx::query!(
        "DELETE FROM policy_actions WHERE id = $1 AND tenant_id = $2 AND is_platform = false",
        action_id, claims.tenant_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete action: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Custom action not found: {action_id}")));
    }

    write_audit(
        &state.db, &claims.tenant_id, None, None,
        "action_deleted", &claims.sub, None,
        Some(format!("Deleted custom action {action_id}")),
        None,
    ).await;

    Ok(Json(serde_json::json!({ "status": "deleted", "id": action_id })))
}
