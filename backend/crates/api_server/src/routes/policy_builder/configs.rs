//! Policy config CRUD handlers.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use auth_core::Claims;
use shared_types::AppError;
use crate::state::AppState;
use super::types::*;
use super::permissions::{Tier, verify_config_ownership, write_audit};

/// GET /policy-builder/configs
pub async fn list_configs(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<ConfigSummary>>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            c.id, c.tenant_id, c.action_key, c.display_name, c.state,
            c.draft_version, c.active_version, c.activated_at,
            c.created_at, c.updated_at,
            COUNT(DISTINCT g.id) AS group_count,
            COUNT(DISTINCT r.id) AS rule_count
        FROM policy_builder_configs c
        LEFT JOIN policy_builder_rule_groups g ON g.config_id = c.id AND g.is_enabled = true
        LEFT JOIN policy_builder_rules r ON r.config_id = c.id AND r.is_enabled = true
        WHERE c.tenant_id = $1 AND c.state != 'archived'
        GROUP BY c.id
        ORDER BY c.updated_at DESC
        "#,
        claims.tenant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch configs: {e}")))?;

    Ok(Json(rows.into_iter().map(|r| ConfigSummary {
        id:             r.id,
        tenant_id:      r.tenant_id,
        action_key:     r.action_key,
        display_name:   r.display_name,
        state:          r.state,
        draft_version:  r.draft_version,
        active_version: r.active_version,
        group_count:    r.group_count.unwrap_or(0),
        rule_count:     r.rule_count.unwrap_or(0),
        activated_at:   r.activated_at,
        created_at:     r.created_at,
        updated_at:     r.updated_at,
    }).collect()))
}

/// POST /policy-builder/configs
pub async fn create_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateConfigRequest>,
) -> Result<(StatusCode, Json<ConfigDetail>), AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    // Validate action_key exists (platform or tenant-owned)
    let action_exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM policy_actions WHERE action_key = $1 AND (tenant_id IS NULL OR tenant_id = $2))",
        req.action_key, claims.tenant_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check action: {e}")))?
    .unwrap_or(false);

    if !action_exists {
        return Err(AppError::BadRequest(format!(
            "Unknown action '{}'. Use GET /policy-builder/actions to see available actions.",
            req.action_key
        )));
    }

    // One config per (tenant, action) — check for existing
    let existing: Option<String> = sqlx::query_scalar!(
        "SELECT id FROM policy_builder_configs WHERE tenant_id = $1 AND action_key = $2",
        claims.tenant_id, req.action_key
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check existing config: {e}")))?;

    if let Some(existing_id) = existing {
        return Err(AppError::BadRequest(format!(
            "A policy config already exists for action '{}' (id: {}). \
             Edit the existing config or archive it first.",
            req.action_key, existing_id
        )));
    }

    let id = format!("pbc_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let now = chrono::Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO policy_builder_configs
            (id, tenant_id, action_key, display_name, description, state, draft_version, created_by)
        VALUES ($1, $2, $3, $4, $5, 'draft', 1, $6)
        "#,
        id, claims.tenant_id, req.action_key, req.display_name, req.description, claims.sub
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create config: {e}")))?;

    write_audit(
        &state.db, &claims.tenant_id, Some(&id), Some(&req.action_key),
        "config_created", &claims.sub, None,
        Some(format!("Policy config created for action '{}'", req.action_key)),
        None,
    ).await;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        config_id = %id,
        action = %req.action_key,
        "Policy builder config created"
    );

    Ok((StatusCode::CREATED, Json(ConfigDetail {
        id,
        tenant_id:               claims.tenant_id,
        action_key:              req.action_key,
        display_name:            req.display_name,
        description:             req.description,
        state:                   "draft".to_string(),
        draft_version:           1,
        active_version:          None,
        active_capsule_hash_b64: None,
        groups:                  vec![],
        activated_at:            None,
        activated_by:            None,
        created_by:              claims.sub,
        created_at:              now,
        updated_at:              now,
    })))
}

/// GET /policy-builder/configs/:id
pub async fn get_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
) -> Result<Json<ConfigDetail>, AppError> {
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    let row = sqlx::query!(
        r#"
        SELECT display_name, description, draft_version, activated_at, activated_by, created_by, created_at, updated_at
        FROM policy_builder_configs
        WHERE id = $1
        "#,
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch config detail: {e}")))?;

    let groups = load_groups_with_rules(&state, &config_id).await?;

    Ok(Json(ConfigDetail {
        id:                      config.id,
        tenant_id:               config.tenant_id,
        action_key:              config.action_key,
        display_name:            row.display_name,
        description:             row.description,
        state:                   config.state,
        draft_version:           row.draft_version,
        active_version:          config.active_version,
        active_capsule_hash_b64: config.active_capsule_hash_b64,
        groups,
        activated_at:            row.activated_at,
        activated_by:            row.activated_by,
        created_by:              row.created_by,
        created_at:              row.created_at,
        updated_at:              row.updated_at,
    }))
}

/// PUT /policy-builder/configs/:id
pub async fn update_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    sqlx::query!(
        r#"
        UPDATE policy_builder_configs
        SET display_name = COALESCE($1, display_name),
            description  = COALESCE($2, description),
            updated_at   = NOW()
        WHERE id = $3
        "#,
        req.display_name, req.description, config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update config: {e}")))?;

    Ok(Json(serde_json::json!({ "status": "updated", "id": config_id })))
}

/// DELETE /policy-builder/configs/:id  (archives, does not hard-delete)
pub async fn archive_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    let rows = sqlx::query!(
        "UPDATE policy_builder_configs SET state = 'archived', updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
        config_id, claims.tenant_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to archive config: {e}")))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!("Config not found: {config_id}")));
    }

    write_audit(
        &state.db, &claims.tenant_id, Some(&config_id), None,
        "config_archived", &claims.sub, None,
        Some("Policy config archived".to_string()),
        None,
    ).await;

    Ok(Json(serde_json::json!({ "status": "archived", "id": config_id })))
}

// ============================================================================
// Shared loader: load all groups with their rules and conditions
// ============================================================================

/// Load all rule groups for a config, with nested rules and conditions.
/// Used by get_config and the compiler.
pub async fn load_groups_with_rules(
    state: &AppState,
    config_id: &str,
) -> Result<Vec<GroupDetail>, AppError> {
    // Load groups
    let groups = sqlx::query!(
        r#"
        SELECT id, config_id, sort_order, display_name, description,
               match_mode, on_match, on_no_match, stepup_methods, is_enabled,
               created_at, updated_at
        FROM policy_builder_rule_groups
        WHERE config_id = $1
        ORDER BY sort_order ASC
        "#,
        config_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to load groups: {e}")))?;

    let mut result = Vec::with_capacity(groups.len());

    for g in groups {
        let rules = load_rules_for_group(state, &g.id, config_id).await?;
        result.push(GroupDetail {
            id:             g.id,
            config_id:      g.config_id,
            sort_order:     g.sort_order,
            display_name:   g.display_name.unwrap_or_default(),
            description:    g.description,
            match_mode:     g.match_mode,
            on_match:       g.on_match,
            on_no_match:    g.on_no_match,
            stepup_methods: g.stepup_methods.unwrap_or_default(),
            is_enabled:     g.is_enabled,
            rules,
            created_at:     g.created_at,
            updated_at:     g.updated_at,
        });
    }

    Ok(result)
}

/// Load all rules for a group, with nested conditions and template info.
pub async fn load_rules_for_group(
    state: &AppState,
    group_id: &str,
    config_id: &str,
) -> Result<Vec<RuleDetail>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            r.id            AS rule_id,
            r.group_id,
            r.template_slug,
            r.display_name  AS rule_display_name,
            r.param_values,
            r.is_enabled,
            r.sort_order,
            r.created_at    AS rule_created_at,
            r.updated_at    AS rule_updated_at,
            t.slug          AS t_slug,
            t.display_name  AS t_display_name,
            t.description   AS t_description,
            t.category      AS t_category,
            t.applicable_actions AS t_applicable_actions,
            t.icon          AS t_icon,
            t.param_schema  AS t_param_schema,
            t.param_defaults AS t_param_defaults,
            t.supported_conditions AS t_supported_conditions,
            t.owner_tenant_id AS t_owner_tenant_id,
            t.is_deprecated AS t_is_deprecated,
            t.deprecated_reason AS t_deprecated_reason,
            t.migration_guide AS t_migration_guide,
            t.sort_order    AS t_sort_order,
            t.created_at    AS t_created_at,
            t.updated_at    AS t_updated_at
        FROM policy_builder_rules r
        JOIN policy_templates t ON t.slug = r.template_slug
        WHERE r.group_id = $1 AND r.config_id = $2
        ORDER BY r.sort_order ASC
        "#,
        group_id,
        config_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to load rules: {e}")))?;

    let mut rules = Vec::with_capacity(rows.len());

    for r in rows {
        let conditions = load_conditions_for_rule(state, &r.rule_id).await?;
        rules.push(RuleDetail {
            id:            r.rule_id,
            group_id:      r.group_id,
            template_slug: r.template_slug,
            display_name:  r.rule_display_name.unwrap_or_default(),
            param_values:  Some(r.param_values),
            is_enabled:    r.is_enabled,
            sort_order:    r.sort_order,
            conditions,
            template: TemplateItem {
                slug:                 r.t_slug,
                display_name:         r.t_display_name,
                description:          r.t_description,
                category:             r.t_category,
                applicable_actions:   r.t_applicable_actions.unwrap_or_default(),
                icon:                 r.t_icon,
                // param_schema / param_defaults are NOT NULL in DB
            param_schema:         r.t_param_schema,
            param_defaults:       r.t_param_defaults,
            supported_conditions: r.t_supported_conditions,
            owner_tenant_id:      r.t_owner_tenant_id,
                is_deprecated:        r.t_is_deprecated,
                deprecated_reason:    r.t_deprecated_reason,
                migration_guide:      r.t_migration_guide,
                sort_order:           r.t_sort_order,
                created_at:           r.t_created_at,
                updated_at:           r.t_updated_at,
            },
            created_at: r.rule_created_at,
            updated_at: r.rule_updated_at,
        });
    }

    Ok(rules)
}

/// Load all conditions for a rule, ordered by sort_order.
pub async fn load_conditions_for_rule(
    state: &AppState,
    rule_id: &str,
) -> Result<Vec<ConditionDetail>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, rule_id, condition_type, condition_params, next_operator, sort_order, created_at
        FROM policy_builder_conditions
        WHERE rule_id = $1
        ORDER BY sort_order ASC
        "#,
        rule_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to load conditions: {e}")))?;

    Ok(rows.into_iter().map(|r| ConditionDetail {
        id:               r.id,
        rule_id:          r.rule_id,
        condition_type:   r.condition_type,
        condition_params: Some(r.condition_params),
        next_operator:    r.next_operator,
        sort_order:       r.sort_order,
        created_at:       r.created_at,
    }).collect())
}
