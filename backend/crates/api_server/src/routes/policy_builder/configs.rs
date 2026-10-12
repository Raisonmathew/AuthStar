//! Policy config CRUD handlers.

use super::permissions::{verify_config_ownership, write_audit, PolicyAuditEvent, Tier};
use super::types::*;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use shared_types::AppError;

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
        LIMIT 200
        "#,
        claims.tenant_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch configs: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ConfigSummary {
                id: r.id,
                tenant_id: r.tenant_id,
                action_key: r.action_key,
                display_name: r.display_name,
                state: r.state,
                draft_version: r.draft_version,
                active_version: r.active_version,
                group_count: r.group_count.unwrap_or(0),
                rule_count: r.rule_count.unwrap_or(0),
                activated_at: r.activated_at,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect(),
    ))
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
        claims.tenant_id,
        req.action_key
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
        id,
        claims.tenant_id,
        req.action_key,
        req.display_name,
        req.description,
        claims.sub
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create config: {e}")))?;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: Some(&id),
            action_key: Some(&req.action_key),
            event_type: "config_created",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!(
                "Policy config created for action '{}'",
                req.action_key
            )),
            metadata: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        config_id = %id,
        action = %req.action_key,
        "Policy builder config created"
    );

    Ok((
        StatusCode::CREATED,
        Json(ConfigDetail {
            id,
            tenant_id: claims.tenant_id,
            action_key: req.action_key,
            display_name: req.display_name,
            description: req.description,
            state: "draft".to_string(),
            draft_version: 1,
            active_version: None,
            active_capsule_hash_b64: None,
            groups: vec![],
            activated_at: None,
            activated_by: None,
            created_by: claims.sub,
            created_at: now,
            updated_at: now,
        }),
    ))
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
        id: config.id,
        tenant_id: config.tenant_id,
        action_key: config.action_key,
        display_name: row.display_name,
        description: row.description,
        state: config.state,
        draft_version: row.draft_version,
        active_version: config.active_version,
        active_capsule_hash_b64: config.active_capsule_hash_b64,
        groups,
        activated_at: row.activated_at,
        activated_by: row.activated_by,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
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
        return Err(AppError::BadRequest(
            "Cannot modify an archived config".into(),
        ));
    }

    sqlx::query!(
        r#"
        UPDATE policy_builder_configs
        SET display_name = COALESCE($1, display_name),
            description  = COALESCE($2, description),
            updated_at   = NOW()
        WHERE id = $3
        "#,
        req.display_name,
        req.description,
        config_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update config: {e}")))?;

    Ok(Json(
        serde_json::json!({ "status": "updated", "id": config_id }),
    ))
}

/// DELETE /policy-builder/configs/:id  (archives, does not hard-delete)
pub async fn archive_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    // Fetch the config first so we can use its action_key for capsule invalidation.
    let config = sqlx::query_as::<_, (String, String)>(
        "SELECT action_key, state FROM policy_builder_configs WHERE id = $1 AND tenant_id = $2"
    )
    .bind(&config_id)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch config: {e}")))?
    .map(|(action_key, state)| (action_key, state))
    .ok_or_else(|| AppError::NotFound(format!("Config not found: {config_id}")))?;
    let (config_action_key, config_state) = config;

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

    // If the config was active, remove its capsule from eiaa_capsules and
    // invalidate the Redis capsule cache so EiaaAuthzLayer stops serving it.
    if config_state == "active" {
        let _ = sqlx::query(
            "DELETE FROM eiaa_capsules WHERE tenant_id = $1 AND action = $2"
        )
        .bind(&claims.tenant_id)
        .bind(&config_action_key)
        .execute(&state.db)
        .await;

        let _ = state.capsule_cache.invalidate(&claims.tenant_id, &config_action_key).await;

        tracing::info!(
            tenant_id  = %claims.tenant_id,
            config_id  = %config_id,
            action_key = %config_action_key,
            "Archived active config — capsule removed from eiaa_capsules and cache invalidated"
        );
    }

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: Some(&config_id),
            action_key: None,
            event_type: "config_archived",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some("Policy config archived".to_string()),
            metadata: None,
        },
    )
    .await;

    Ok(Json(
        serde_json::json!({ "status": "archived", "id": config_id }),
    ))
}

// ============================================================================
// Shared loader: load all groups with their rules and conditions
// ============================================================================

/// Load all rule groups for a config, with nested rules and conditions.
/// Used by get_config and the compiler.
///
/// # Performance
/// Single flat JOIN over groups → rules → templates → conditions, ordered
/// (group.sort_order, rule.sort_order, condition.sort_order).  This replaces
/// the previous O(groups × rules) sequential round-trips with a single query.
/// The result rows are assembled in-memory into the nested structure.
pub async fn load_groups_with_rules(
    state: &AppState,
    config_id: &str,
) -> Result<Vec<GroupDetail>, AppError> {
    // One query: groups LEFT JOIN rules LEFT JOIN templates LEFT JOIN conditions.
    // Uses sqlx::query (non-macro) so it doesn't require an entry in the offline
    // query cache — this is a new complex query added post-initial-prepare.
    use sqlx::Row as _;

    let rows = sqlx::query(
        r#"
        SELECT
            g.id            AS g_id,
            g.config_id     AS g_config_id,
            g.sort_order    AS g_sort_order,
            g.display_name  AS g_display_name,
            g.description   AS g_description,
            g.match_mode    AS g_match_mode,
            g.on_match      AS g_on_match,
            g.on_no_match   AS g_on_no_match,
            g.stepup_methods AS g_stepup_methods,
            g.is_enabled    AS g_is_enabled,
            g.created_at    AS g_created_at,
            g.updated_at    AS g_updated_at,
            r.id            AS r_id,
            r.group_id      AS r_group_id,
            r.template_slug AS r_template_slug,
            r.display_name  AS r_display_name,
            r.param_values  AS r_param_values,
            r.is_enabled    AS r_is_enabled,
            r.sort_order    AS r_sort_order,
            r.created_at    AS r_created_at,
            r.updated_at    AS r_updated_at,
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
            t.updated_at    AS t_updated_at,
            c.id            AS c_id,
            c.rule_id       AS c_rule_id,
            c.condition_type AS c_condition_type,
            c.condition_params AS c_condition_params,
            c.next_operator AS c_next_operator,
            c.sort_order    AS c_sort_order,
            c.created_at    AS c_created_at
        FROM policy_builder_rule_groups g
        LEFT JOIN policy_builder_rules r
            ON r.group_id = g.id AND r.config_id = g.config_id
        LEFT JOIN policy_templates t
            ON t.slug = r.template_slug
        LEFT JOIN policy_builder_conditions c
            ON c.rule_id = r.id
        WHERE g.config_id = $1
        ORDER BY g.sort_order ASC, r.sort_order ASC NULLS LAST, c.sort_order ASC NULLS LAST
        "#,
    )
    .bind(config_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to load groups: {e}")))?;

    // Assemble the nested structure from flat rows using .get() on sqlx::PgRow.
    // Rows are already sorted by (g.sort_order, r.sort_order, c.sort_order).

    let mut group_idx: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut groups: Vec<GroupDetail> = Vec::new();
    let mut rule_idx: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();

    for row in rows {
        let gid: String = row.get("g_id");

        // Ensure the group exists
        if !group_idx.contains_key(&gid) {
            let idx = groups.len();
            groups.push(GroupDetail {
                id: gid.clone(),
                config_id: row.get("g_config_id"),
                sort_order: row.get("g_sort_order"),
                display_name: row.get::<Option<String>, _>("g_display_name").unwrap_or_default(),
                description: row.get("g_description"),
                match_mode: row.get("g_match_mode"),
                on_match: row.get("g_on_match"),
                on_no_match: row.get("g_on_no_match"),
                stepup_methods: row.get::<Option<Vec<String>>, _>("g_stepup_methods").unwrap_or_default(),
                is_enabled: row.get("g_is_enabled"),
                rules: vec![],
                created_at: row.get("g_created_at"),
                updated_at: row.get("g_updated_at"),
            });
            group_idx.insert(gid.clone(), idx);
        }

        // No rule on this row (group with no rules)
        let rid: Option<String> = row.get("r_id");
        let rid = match rid {
            Some(id) => id,
            None => continue,
        };

        // Ensure the rule exists within its group
        let rule_key = (gid.clone(), rid.clone());
        if !rule_idx.contains_key(&rule_key) {
            let gidx = *group_idx.get(&gid).unwrap();
            let group = &mut groups[gidx];
            let idx = group.rules.len();
            group.rules.push(RuleDetail {
                id: rid.clone(),
                group_id: row.get::<Option<String>, _>("r_group_id").unwrap_or_default(),
                template_slug: row.get::<Option<String>, _>("r_template_slug").unwrap_or_default(),
                display_name: row.get::<Option<String>, _>("r_display_name").unwrap_or_default(),
                param_values: row.get("r_param_values"),
                is_enabled: row.get::<Option<bool>, _>("r_is_enabled").unwrap_or(true),
                sort_order: row.get::<Option<i32>, _>("r_sort_order").unwrap_or(0),
                conditions: vec![],
                template: TemplateItem {
                    slug: row.get::<Option<String>, _>("t_slug").unwrap_or_default(),
                    display_name: row.get::<Option<String>, _>("t_display_name").unwrap_or_default(),
                    description: row.get::<Option<String>, _>("t_description").unwrap_or_default(),
                    category: row.get::<Option<String>, _>("t_category").unwrap_or_default(),
                    applicable_actions: row.get::<Option<Vec<String>>, _>("t_applicable_actions").unwrap_or_default(),
                    icon: row.get("t_icon"),
                    param_schema: row.get::<Option<serde_json::Value>, _>("t_param_schema").unwrap_or(serde_json::json!({})),
                    param_defaults: row.get::<Option<serde_json::Value>, _>("t_param_defaults").unwrap_or(serde_json::json!({})),
                    supported_conditions: row.get::<Option<Vec<String>>, _>("t_supported_conditions").unwrap_or_default(),
                    owner_tenant_id: row.get("t_owner_tenant_id"),
                    is_deprecated: row.get::<Option<bool>, _>("t_is_deprecated").unwrap_or(false),
                    deprecated_reason: row.get("t_deprecated_reason"),
                    migration_guide: row.get("t_migration_guide"),
                    sort_order: row.get::<Option<i32>, _>("t_sort_order").unwrap_or(100),
                    created_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("t_created_at").unwrap_or_else(chrono::Utc::now),
                    updated_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("t_updated_at").unwrap_or_else(chrono::Utc::now),
                },
                created_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("r_created_at").unwrap_or_else(chrono::Utc::now),
                updated_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("r_updated_at").unwrap_or_else(chrono::Utc::now),
            });
            rule_idx.insert(rule_key.clone(), idx);
        }

        // No condition on this row (rule with no conditions)
        let cid: Option<String> = row.get("c_id");
        let cid = match cid {
            Some(id) => id,
            None => continue,
        };

        // Append condition to the rule
        let ridx = *rule_idx.get(&rule_key).unwrap();
        let gidx = *group_idx.get(&gid).unwrap();
        groups[gidx].rules[ridx].conditions.push(ConditionDetail {
            id: cid,
            rule_id: row.get::<Option<String>, _>("c_rule_id").unwrap_or_default(),
            condition_type: row.get::<Option<String>, _>("c_condition_type").unwrap_or_default(),
            condition_params: row.get("c_condition_params"),
            next_operator: row.get("c_next_operator"),
            sort_order: row.get::<Option<i32>, _>("c_sort_order").unwrap_or(0),
            created_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("c_created_at").unwrap_or_else(chrono::Utc::now),
        });
    }

    Ok(groups)
}

