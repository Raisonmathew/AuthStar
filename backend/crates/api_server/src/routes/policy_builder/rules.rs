//! Rule CRUD handlers.
//!
//! Rules live inside a rule group and reference a policy template.
//! Each rule has `param_values` (JSONB) that override the template's defaults.

use super::permissions::{
    mark_config_dirty, verify_config_ownership, write_audit, PolicyAuditEvent, Tier,
};
use super::types::*;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use shared_types::AppError;

/// POST /policy-builder/configs/:id/groups/:gid/rules
pub async fn add_rule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id)): Path<(String, String)>,
    Json(req): Json<AddRuleRequest>,
) -> Result<(StatusCode, Json<RuleDetail>), AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest(
            "Cannot modify an archived config".into(),
        ));
    }

    // Verify group belongs to this config
    let group_exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM policy_builder_rule_groups WHERE id = $1 AND config_id = $2)",
        group_id,
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check group: {e}")))?
    .unwrap_or(false);

    if !group_exists {
        return Err(AppError::NotFound(format!(
            "Group '{group_id}' not found in config '{config_id}'"
        )));
    }

    // Verify template exists and is applicable to this action
    let template = sqlx::query!(
        r#"
        SELECT slug, display_name, description, category, applicable_actions,
               icon, param_schema, param_defaults, supported_conditions,
               owner_tenant_id, is_deprecated, deprecated_reason, migration_guide,
               sort_order, created_at, updated_at
        FROM policy_templates
        WHERE slug = $1
          AND (owner_tenant_id IS NULL OR owner_tenant_id = $2)
          AND is_deprecated = false
        "#,
        req.template_slug, claims.tenant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch template: {e}")))?
    .ok_or_else(|| AppError::BadRequest(format!(
        "Template '{}' not found or is deprecated. Use GET /policy-builder/templates to see available templates.",
        req.template_slug
    )))?;

    // Check template is applicable to this action (if applicable_actions is non-empty)
    let applicable: Vec<String> = template.applicable_actions.clone().unwrap_or_default();
    if !applicable.is_empty() && !applicable.contains(&config.action_key) {
        return Err(AppError::BadRequest(format!(
            "Template '{}' is not applicable to action '{}'. Applicable actions: {:?}",
            req.template_slug, config.action_key, applicable
        )));
    }

    // Validate param_values against param_schema (basic: check required fields)
    // param_schema is NOT NULL in DB but sqlx returns Option<Value> for JSONB columns.
    // unwrap_or_else provides an empty schema (no required fields) as a safe fallback.
    let param_schema = template.param_schema;
    validate_params_against_schema(&req.param_values, &param_schema)?;

    // Determine sort_order
    let max_order: i32 = sqlx::query_scalar!(
        "SELECT COALESCE(MAX(sort_order), 0) FROM policy_builder_rules WHERE group_id = $1 AND config_id = $2",
        group_id, config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to get max sort_order: {e}")))?
    .unwrap_or(0);

    let sort_order = max_order + 1;
    let id = format!("pbr_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let now = chrono::Utc::now();

    // Merge param_defaults with provided param_values.
    // param_defaults is NOT NULL in DB but sqlx returns Option<Value> for JSONB columns.
    let defaults = template.param_defaults;
    let merged_params = merge_params(Some(&defaults), &req.param_values);

    sqlx::query!(
        r#"
        INSERT INTO policy_builder_rules
            (id, config_id, group_id, template_slug, display_name, param_values, is_enabled, sort_order)
        VALUES ($1, $2, $3, $4, $5, $6, true, $7)
        "#,
        id,
        config_id,
        group_id,
        req.template_slug,
        req.display_name,
        merged_params,
        sort_order,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to insert rule: {e}")))?;

    mark_config_dirty(&state.db, &config_id).await;

    write_audit(
        &state.db, PolicyAuditEvent {
            tenant_id: &claims.tenant_id, config_id: Some(&config_id), action_key: Some(&config.action_key),
            event_type: "rule_added", actor_id: &claims.sub, actor_ip: None,
            description: Some(format!("Rule '{}' added using template '{}'", req.display_name, req.template_slug)),
            metadata: Some(serde_json::json!({ "rule_id": id, "group_id": group_id, "template": req.template_slug })),
        },
    ).await;

    Ok((
        StatusCode::CREATED,
        Json(RuleDetail {
            id,
            group_id,
            template_slug: req.template_slug.clone(),
            display_name: req.display_name,
            param_values: Some(merged_params),
            is_enabled: true,
            sort_order,
            conditions: vec![],
            template: TemplateItem {
                slug: template.slug,
                display_name: template.display_name,
                description: template.description,
                category: template.category,
                applicable_actions: template.applicable_actions.unwrap_or_default(),
                icon: template.icon,
                // param_schema / param_defaults are NOT NULL in DB but sqlx returns Option<Value>
                param_schema,
                param_defaults: defaults,
                supported_conditions: template.supported_conditions,
                owner_tenant_id: template.owner_tenant_id,
                is_deprecated: template.is_deprecated,
                deprecated_reason: template.deprecated_reason,
                migration_guide: template.migration_guide,
                sort_order: template.sort_order,
                created_at: template.created_at,
                updated_at: template.updated_at,
            },
            created_at: now,
            updated_at: now,
        }),
    ))
}

/// PUT /policy-builder/configs/:id/groups/:gid/rules/:rid
pub async fn update_rule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id, rule_id)): Path<(String, String, String)>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest(
            "Cannot modify an archived config".into(),
        ));
    }

    // If param_values provided, validate against template schema
    if let Some(ref _params) = req.param_values {
        let schema: Option<serde_json::Value> = sqlx::query_scalar!(
            r#"
            SELECT t.param_schema
            FROM policy_builder_rules r
            JOIN policy_templates t ON t.slug = r.template_slug
            WHERE r.id = $1 AND r.group_id = $2 AND r.config_id = $3
            "#,
            rule_id,
            group_id,
            config_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch rule schema: {e}")))?;

        if let Some(s) = schema {
            validate_params_against_schema(&req.param_values, &s)?;
        }
    }

    let rows = sqlx::query!(
        r#"
        UPDATE policy_builder_rules
        SET display_name  = COALESCE($1, display_name),
            param_values  = COALESCE($2, param_values),
            is_enabled    = COALESCE($3, is_enabled),
            updated_at    = NOW()
        WHERE id = $4 AND group_id = $5 AND config_id = $6
        "#,
        req.display_name,
        req.param_values,
        req.is_enabled,
        rule_id,
        group_id,
        config_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update rule: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Rule not found: {rule_id}")));
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(
        serde_json::json!({ "status": "updated", "id": rule_id }),
    ))
}

/// DELETE /policy-builder/configs/:id/groups/:gid/rules/:rid
pub async fn remove_rule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id, rule_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest(
            "Cannot modify an archived config".into(),
        ));
    }

    // Delete conditions first (FK constraint)
    sqlx::query!(
        "DELETE FROM policy_builder_conditions WHERE rule_id = $1",
        rule_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete conditions: {e}")))?;

    let rows = sqlx::query!(
        "DELETE FROM policy_builder_rules WHERE id = $1 AND group_id = $2 AND config_id = $3",
        rule_id,
        group_id,
        config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete rule: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Rule not found: {rule_id}")));
    }

    mark_config_dirty(&state.db, &config_id).await;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: Some(&config_id),
            action_key: Some(&config.action_key),
            event_type: "rule_removed",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!("Rule {rule_id} removed from group {group_id}")),
            metadata: Some(serde_json::json!({ "rule_id": rule_id, "group_id": group_id })),
        },
    )
    .await;

    Ok(Json(
        serde_json::json!({ "status": "removed", "id": rule_id }),
    ))
}

/// POST /policy-builder/configs/:id/groups/:gid/rules/reorder
pub async fn reorder_rules(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id)): Path<(String, String)>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest(
            "Cannot modify an archived config".into(),
        ));
    }

    let existing_ids: Vec<String> = sqlx::query_scalar!(
        "SELECT id FROM policy_builder_rules WHERE group_id = $1 AND config_id = $2",
        group_id,
        config_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch rule ids: {e}")))?;

    for id in &req.order {
        if !existing_ids.contains(id) {
            return Err(AppError::BadRequest(format!(
                "Rule id '{id}' does not belong to group '{group_id}'"
            )));
        }
    }

    if req.order.len() != existing_ids.len() {
        return Err(AppError::BadRequest(format!(
            "Reorder list has {} items but group has {} rules. All rules must be included.",
            req.order.len(),
            existing_ids.len()
        )));
    }

    for (idx, rule_id) in req.order.iter().enumerate() {
        sqlx::query!(
            "UPDATE policy_builder_rules SET sort_order = $1, updated_at = NOW() WHERE id = $2",
            (idx + 1) as i32,
            rule_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to reorder rule: {e}")))?;
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({
        "status": "reordered",
        "group_id": group_id,
        "new_order": req.order
    })))
}

// ============================================================================
// Helpers
// ============================================================================

/// Merge template param_defaults with user-provided param_values.
/// User values take precedence; defaults fill in missing keys.
/// `defaults` is always `Some` since param_defaults is NOT NULL in DB,
/// but we keep the Option signature for flexibility.
fn merge_params(
    defaults: Option<&serde_json::Value>,
    provided: &Option<serde_json::Value>,
) -> serde_json::Value {
    let mut merged = match defaults {
        Some(serde_json::Value::Object(m)) => m.clone(),
        _ => serde_json::Map::new(),
    };

    if let Some(serde_json::Value::Object(user)) = provided {
        for (k, v) in user {
            merged.insert(k.clone(), v.clone());
        }
    }

    serde_json::Value::Object(merged)
}

/// Basic JSON Schema validation: check that all `required` fields are present
/// in the provided params. Full JSON Schema validation would use a library;
/// this is a lightweight guard sufficient for the builder.
fn validate_params_against_schema(
    params: &Option<serde_json::Value>,
    schema: &serde_json::Value,
) -> Result<(), AppError> {
    let required = match schema.get("required") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        _ => return Ok(()), // no required fields
    };

    if required.is_empty() {
        return Ok(());
    }

    let provided_keys: Vec<String> = match params {
        Some(serde_json::Value::Object(m)) => m.keys().cloned().collect(),
        _ => vec![],
    };

    let missing: Vec<&str> = required
        .iter()
        .filter(|r| !provided_keys.contains(r))
        .map(|s| s.as_str())
        .collect();

    if !missing.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Missing required param(s): {}",
            missing.join(", ")
        )));
    }

    Ok(())
}
