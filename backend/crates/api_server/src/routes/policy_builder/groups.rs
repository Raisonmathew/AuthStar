//! Rule group CRUD handlers.
//!
//! Groups are the top-level logical containers within a policy config.
//! Each group has a `match_mode` (all/any) and `on_match`/`on_no_match` actions.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use auth_core::Claims;
use shared_types::AppError;
use crate::state::AppState;
use super::types::*;
use super::permissions::{Tier, verify_config_ownership, mark_config_dirty, write_audit};

/// POST /policy-builder/configs/:id/groups
pub async fn add_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
    Json(req): Json<AddGroupRequest>,
) -> Result<(StatusCode, Json<GroupDetail>), AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // Validate match_mode
    if !["all", "any"].contains(&req.match_mode.as_str()) {
        return Err(AppError::BadRequest(
            "match_mode must be 'all' or 'any'".into(),
        ));
    }

    // Validate on_match / on_no_match
    let valid_actions = ["continue", "deny", "stepup", "allow"];
    if !valid_actions.contains(&req.on_match.as_str()) {
        return Err(AppError::BadRequest(
            "on_match must be one of: continue, deny, stepup, allow".into(),
        ));
    }
    if !valid_actions.contains(&req.on_no_match.as_str()) {
        return Err(AppError::BadRequest(
            "on_no_match must be one of: continue, deny, stepup, allow".into(),
        ));
    }

    // stepup_methods required when on_match or on_no_match is 'stepup'
    if (req.on_match == "stepup" || req.on_no_match == "stepup")
        && req.stepup_methods.is_empty()
    {
        return Err(AppError::BadRequest(
            "stepup_methods must be non-empty when on_match or on_no_match is 'stepup'".into(),
        ));
    }

    // Determine sort_order: max + 1
    let max_order: i32 = sqlx::query_scalar!(
        "SELECT COALESCE(MAX(sort_order), 0) FROM policy_builder_rule_groups WHERE config_id = $1",
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to get max sort_order: {e}")))?
    .unwrap_or(0);

    let sort_order = max_order + 1;
    let id = format!("pbg_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let now = chrono::Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO policy_builder_rule_groups
            (id, config_id, sort_order, display_name, description,
             match_mode, on_match, on_no_match, stepup_methods, is_enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
        "#,
        id,
        config_id,
        sort_order,
        req.display_name,
        req.description,
        req.match_mode,
        req.on_match,
        req.on_no_match,
        &req.stepup_methods,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to insert group: {e}")))?;

    mark_config_dirty(&state.db, &config_id).await;

    write_audit(
        &state.db, &claims.tenant_id, Some(&config_id), Some(&config.action_key),
        "group_added", &claims.sub, None,
        Some(format!("Rule group '{}' added", req.display_name)),
        Some(serde_json::json!({ "group_id": id, "match_mode": req.match_mode })),
    ).await;

    Ok((StatusCode::CREATED, Json(GroupDetail {
        id,
        config_id,
        sort_order,
        display_name:   req.display_name,
        description:    req.description,
        match_mode:     req.match_mode,
        on_match:       req.on_match,
        on_no_match:    req.on_no_match,
        stepup_methods: req.stepup_methods,
        is_enabled:     true,
        rules:          vec![],
        created_at:     now,
        updated_at:     now,
    })))
}

/// PUT /policy-builder/configs/:id/groups/:gid
pub async fn update_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id)): Path<(String, String)>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // Validate enums if provided
    if let Some(ref mm) = req.match_mode {
        if !["all", "any"].contains(&mm.as_str()) {
            return Err(AppError::BadRequest("match_mode must be 'all' or 'any'".into()));
        }
    }
    let valid_actions = ["continue", "deny", "stepup", "allow"];
    if let Some(ref om) = req.on_match {
        if !valid_actions.contains(&om.as_str()) {
            return Err(AppError::BadRequest(
                "on_match must be one of: continue, deny, stepup, allow".into(),
            ));
        }
    }
    if let Some(ref onm) = req.on_no_match {
        if !valid_actions.contains(&onm.as_str()) {
            return Err(AppError::BadRequest(
                "on_no_match must be one of: continue, deny, stepup, allow".into(),
            ));
        }
    }

    let rows = sqlx::query!(
        r#"
        UPDATE policy_builder_rule_groups
        SET display_name   = COALESCE($1, display_name),
            description    = COALESCE($2, description),
            match_mode     = COALESCE($3, match_mode),
            on_match       = COALESCE($4, on_match),
            on_no_match    = COALESCE($5, on_no_match),
            stepup_methods = COALESCE($6, stepup_methods),
            is_enabled     = COALESCE($7, is_enabled),
            updated_at     = NOW()
        WHERE id = $8 AND config_id = $9
        "#,
        req.display_name,
        req.description,
        req.match_mode,
        req.on_match,
        req.on_no_match,
        req.stepup_methods.as_deref(),
        req.is_enabled,
        group_id,
        config_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update group: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Group not found: {group_id}")));
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({ "status": "updated", "id": group_id })))
}

/// DELETE /policy-builder/configs/:id/groups/:gid
pub async fn remove_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // Cascade: delete conditions → rules → group
    sqlx::query!(
        r#"
        DELETE FROM policy_builder_conditions
        WHERE rule_id IN (
            SELECT id FROM policy_builder_rules WHERE group_id = $1 AND config_id = $2
        )
        "#,
        group_id, config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete conditions: {e}")))?;

    sqlx::query!(
        "DELETE FROM policy_builder_rules WHERE group_id = $1 AND config_id = $2",
        group_id, config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete rules: {e}")))?;

    let rows = sqlx::query!(
        "DELETE FROM policy_builder_rule_groups WHERE id = $1 AND config_id = $2",
        group_id, config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete group: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Group not found: {group_id}")));
    }

    mark_config_dirty(&state.db, &config_id).await;

    write_audit(
        &state.db, &claims.tenant_id, Some(&config_id), Some(&config.action_key),
        "group_removed", &claims.sub, None,
        Some(format!("Rule group {group_id} removed")),
        Some(serde_json::json!({ "group_id": group_id })),
    ).await;

    Ok(Json(serde_json::json!({ "status": "removed", "id": group_id })))
}

/// POST /policy-builder/configs/:id/groups/reorder
///
/// Body: `{ "order": ["pbg_aaa", "pbg_bbb", "pbg_ccc"] }`
/// Sets sort_order = index+1 for each group id in the list.
pub async fn reorder_groups(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // Verify all ids belong to this config
    let existing_ids: Vec<String> = sqlx::query_scalar!(
        "SELECT id FROM policy_builder_rule_groups WHERE config_id = $1",
        config_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch group ids: {e}")))?;

    for id in &req.order {
        if !existing_ids.contains(id) {
            return Err(AppError::BadRequest(format!(
                "Group id '{id}' does not belong to config '{config_id}'"
            )));
        }
    }

    if req.order.len() != existing_ids.len() {
        return Err(AppError::BadRequest(format!(
            "Reorder list has {} items but config has {} groups. All groups must be included.",
            req.order.len(),
            existing_ids.len()
        )));
    }

    // Apply new sort_order values
    for (idx, group_id) in req.order.iter().enumerate() {
        sqlx::query!(
            "UPDATE policy_builder_rule_groups SET sort_order = $1, updated_at = NOW() WHERE id = $2",
            (idx + 1) as i32,
            group_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to reorder group: {e}")))?;
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({
        "status": "reordered",
        "config_id": config_id,
        "new_order": req.order
    })))
}
