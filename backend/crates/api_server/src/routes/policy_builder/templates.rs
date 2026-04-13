//! Template management handlers.
//!
//! Permission rules:
//!   GET  /templates, /templates/:slug, /templates/:slug/conditions → all tiers
//!   POST /templates                → PlatformAdmin (platform template) OR TenantAdmin (custom)
//!   PUT  /templates/:slug          → PlatformAdmin for platform; TenantAdmin for own custom
//!   DELETE /templates/:slug        → same as PUT (soft-deprecate only)

use super::permissions::{write_audit, PolicyAuditEvent, Tier};
use super::types::*;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use shared_types::AppError;

/// GET /policy-builder/templates
/// List all active templates visible to this caller.
/// Platform admins see all; tenants see platform templates + their own custom ones.
pub async fn list_templates(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<TemplateItem>>, AppError> {
    let tier = Tier::from_user(&state.db, &claims).await?;

    let templates: Vec<TemplateItem> = if tier >= Tier::PlatformAdmin {
        // Platform admins see everything including deprecated
        sqlx::query!(
            r#"
            SELECT slug, display_name, description, category,
                   applicable_actions, icon, param_schema, param_defaults,
                   supported_conditions, owner_tenant_id,
                   is_deprecated, deprecated_reason, migration_guide,
                   sort_order, created_at, updated_at
            FROM policy_templates
            WHERE is_active = true
            ORDER BY sort_order, display_name
            LIMIT 500
            "#
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch templates: {e}")))?
        .into_iter()
        .map(|r| TemplateItem {
            slug: r.slug,
            display_name: r.display_name,
            description: r.description,
            category: r.category,
            applicable_actions: r.applicable_actions.unwrap_or_default(),
            icon: r.icon,
            param_schema: r.param_schema,
            param_defaults: r.param_defaults,
            supported_conditions: r.supported_conditions,
            owner_tenant_id: r.owner_tenant_id,
            is_deprecated: r.is_deprecated,
            deprecated_reason: r.deprecated_reason,
            migration_guide: r.migration_guide,
            sort_order: r.sort_order,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect()
    } else {
        // Tenants see platform templates + their own custom ones (non-deprecated)
        sqlx::query!(
            r#"
            SELECT slug, display_name, description, category,
                   applicable_actions, icon, param_schema, param_defaults,
                   supported_conditions, owner_tenant_id,
                   is_deprecated, deprecated_reason, migration_guide,
                   sort_order, created_at, updated_at
            FROM policy_templates
            WHERE is_active = true
              AND is_deprecated = false
              AND (owner_tenant_id IS NULL OR owner_tenant_id = $1)
            ORDER BY sort_order, display_name
            LIMIT 500
            "#,
            claims.tenant_id
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch templates: {e}")))?
        .into_iter()
        .map(|r| TemplateItem {
            slug: r.slug,
            display_name: r.display_name,
            description: r.description,
            category: r.category,
            applicable_actions: r.applicable_actions.unwrap_or_default(),
            icon: r.icon,
            param_schema: r.param_schema,
            param_defaults: r.param_defaults,
            supported_conditions: r.supported_conditions,
            owner_tenant_id: r.owner_tenant_id,
            is_deprecated: r.is_deprecated,
            deprecated_reason: r.deprecated_reason,
            migration_guide: r.migration_guide,
            sort_order: r.sort_order,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect()
    };

    Ok(Json(templates))
}

/// GET /policy-builder/templates/:slug
pub async fn get_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(slug): Path<String>,
) -> Result<Json<TemplateItem>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT slug, display_name, description, category,
               applicable_actions, icon, param_schema, param_defaults,
               supported_conditions, owner_tenant_id,
               is_deprecated, deprecated_reason, migration_guide,
               sort_order, created_at, updated_at
        FROM policy_templates
        WHERE slug = $1
          AND is_active = true
          AND (owner_tenant_id IS NULL OR owner_tenant_id = $2)
        "#,
        slug,
        claims.tenant_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch template: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Template not found: {slug}")))?;

    Ok(Json(TemplateItem {
        slug: row.slug,
        display_name: row.display_name,
        description: row.description,
        category: row.category,
        applicable_actions: row.applicable_actions.unwrap_or_default(),
        icon: row.icon,
        param_schema: row.param_schema,
        param_defaults: row.param_defaults,
        supported_conditions: row.supported_conditions,
        owner_tenant_id: row.owner_tenant_id,
        is_deprecated: row.is_deprecated,
        deprecated_reason: row.deprecated_reason,
        migration_guide: row.migration_guide,
        sort_order: row.sort_order,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }))
}

/// GET /policy-builder/templates/:slug/conditions
/// Returns the list of condition types that make semantic sense for this template.
pub async fn list_supported_conditions(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<ConditionTypeItem>>, AppError> {
    let row = sqlx::query!(
        "SELECT supported_conditions FROM policy_templates WHERE slug = $1 AND is_active = true",
        slug
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch template: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Template not found: {slug}")))?;

    let supported = row.supported_conditions;
    let items = supported
        .into_iter()
        .filter_map(|ct| condition_type_metadata(&ct))
        .collect();

    Ok(Json(items))
}

/// POST /policy-builder/templates
/// Create a new template.
/// - PlatformAdmin: creates a platform template (owner_tenant_id = NULL)
/// - TenantAdmin: creates a tenant-custom template (owner_tenant_id = caller's tenant)
pub async fn create_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateTemplateRequest>,
) -> Result<(StatusCode, Json<TemplateItem>), AppError> {
    let tier = Tier::from_user(&state.db, &claims).await?;
    tier.require_admin()?;

    // Validate slug format
    if req.slug.is_empty() || req.slug.len() > 100 {
        return Err(AppError::BadRequest("slug must be 1-100 characters".into()));
    }
    if !req.slug.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError::BadRequest(
            "slug may only contain alphanumeric characters and underscores".into(),
        ));
    }

    // Platform admins create platform templates; others create tenant-custom
    let owner_tenant_id: Option<String> = if tier >= Tier::PlatformAdmin {
        None // Platform template
    } else {
        Some(claims.tenant_id.clone()) // Tenant-custom template
    };

    let applicable_actions = req.applicable_actions.unwrap_or_default();
    let supported_conditions = req.supported_conditions.unwrap_or_default();
    let sort_order = req.sort_order.unwrap_or(100);

    sqlx::query!(
        r#"
        INSERT INTO policy_templates
            (slug, display_name, description, category, applicable_actions, icon,
             param_schema, param_defaults, supported_conditions, owner_tenant_id,
             sort_order, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
        req.slug,
        req.display_name,
        req.description,
        req.category,
        &applicable_actions,
        req.icon,
        req.param_schema,
        req.param_defaults,
        &supported_conditions,
        owner_tenant_id,
        sort_order,
        claims.sub
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
            AppError::BadRequest(format!("Template with slug '{}' already exists", req.slug))
        } else {
            AppError::Internal(format!("Failed to create template: {e}"))
        }
    })?;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: None,
            action_key: None,
            event_type: "template_created",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!("Created template '{}'", req.slug)),
            metadata: Some(serde_json::json!({ "slug": req.slug, "category": req.category })),
        },
    )
    .await;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        slug = %req.slug,
        tier = ?tier,
        "Policy template created"
    );

    let now = chrono::Utc::now();
    Ok((
        StatusCode::CREATED,
        Json(TemplateItem {
            slug: req.slug,
            display_name: req.display_name,
            description: req.description,
            category: req.category,
            applicable_actions,
            icon: req.icon,
            param_schema: req.param_schema.unwrap_or_else(|| serde_json::json!({})),
            param_defaults: req.param_defaults.unwrap_or_else(|| serde_json::json!({})),
            supported_conditions,
            owner_tenant_id,
            is_deprecated: false,
            deprecated_reason: None,
            migration_guide: None,
            sort_order,
            created_at: now,
            updated_at: now,
        }),
    ))
}

/// PUT /policy-builder/templates/:slug
/// Update a template. Permission: PlatformAdmin for platform templates; TenantAdmin for own custom.
pub async fn update_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(slug): Path<String>,
    Json(req): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateItem>, AppError> {
    let tier = Tier::from_user(&state.db, &claims).await?;

    // Fetch current template to check ownership
    let current = sqlx::query!(
        "SELECT owner_tenant_id FROM policy_templates WHERE slug = $1 AND is_active = true",
        slug
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch template: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Template not found: {slug}")))?;

    tier.can_manage_template(current.owner_tenant_id.as_deref())?;

    // Build update query dynamically
    sqlx::query!(
        r#"
        UPDATE policy_templates SET
            display_name         = COALESCE($1, display_name),
            description          = COALESCE($2, description),
            category             = COALESCE($3, category),
            applicable_actions   = COALESCE($4, applicable_actions),
            icon                 = COALESCE($5, icon),
            param_schema         = COALESCE($6, param_schema),
            param_defaults       = COALESCE($7, param_defaults),
            supported_conditions = COALESCE($8, supported_conditions),
            sort_order           = COALESCE($9, sort_order),
            updated_at           = NOW()
        WHERE slug = $10
        "#,
        req.display_name,
        req.description,
        req.category,
        req.applicable_actions.as_deref(),
        req.icon,
        req.param_schema,
        req.param_defaults,
        req.supported_conditions.as_deref(),
        req.sort_order,
        slug
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update template: {e}")))?;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: None,
            action_key: None,
            event_type: "template_updated",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!("Updated template '{slug}'")),
            metadata: None,
        },
    )
    .await;

    // Return updated template
    get_template(State(state), Extension(claims), Path(slug)).await
}

/// DELETE /policy-builder/templates/:slug
/// Soft-deprecate a template. Existing configs using it continue to work.
/// New rules cannot use deprecated templates.
pub async fn deprecate_template(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(slug): Path<String>,
    Json(req): Json<DeprecateTemplateRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tier = Tier::from_user(&state.db, &claims).await?;

    let current = sqlx::query!(
        "SELECT owner_tenant_id FROM policy_templates WHERE slug = $1 AND is_active = true",
        slug
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch template: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Template not found: {slug}")))?;

    tier.can_manage_template(current.owner_tenant_id.as_deref())?;

    sqlx::query!(
        r#"
        UPDATE policy_templates
        SET is_deprecated = true, deprecated_at = NOW(),
            deprecated_reason = $1, migration_guide = $2, updated_at = NOW()
        WHERE slug = $3
        "#,
        req.reason,
        req.migration_guide,
        slug
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to deprecate template: {e}")))?;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: None,
            action_key: None,
            event_type: "template_deprecated",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!("Deprecated template '{}': {}", slug, req.reason)),
            metadata: Some(serde_json::json!({ "slug": slug, "reason": req.reason })),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "status": "deprecated",
        "slug": slug,
        "reason": req.reason,
        "note": "Existing configs using this template continue to work. New rules cannot use deprecated templates."
    })))
}

// ============================================================================
// Condition type metadata catalog
// ============================================================================

/// Returns human-readable metadata for a condition type.
/// This is the source of truth for the UI condition picker.
fn condition_type_metadata(condition_type: &str) -> Option<ConditionTypeItem> {
    let (display_name, description, params_schema) = match condition_type {
        "risk_above" => (
            "Risk Score Above",
            "Matches when the computed risk score exceeds the threshold",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "threshold": { "type": "number", "minimum": 0, "maximum": 100, "description": "Risk score threshold (0-100)" }
                },
                "required": ["threshold"]
            }),
        ),
        "risk_below" => (
            "Risk Score Below",
            "Matches when the computed risk score is below the threshold",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "threshold": { "type": "number", "minimum": 0, "maximum": 100 }
                },
                "required": ["threshold"]
            }),
        ),
        "country_in" => (
            "Country Is",
            "Matches when the request originates from one of the specified countries",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "countries": { "type": "array", "items": { "type": "string", "minLength": 2, "maxLength": 2 }, "minItems": 1, "description": "ISO 3166-1 alpha-2 country codes" }
                },
                "required": ["countries"]
            }),
        ),
        "country_not_in" => (
            "Country Is Not",
            "Matches when the request does NOT originate from any of the specified countries",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "countries": { "type": "array", "items": { "type": "string", "minLength": 2, "maxLength": 2 }, "minItems": 1 }
                },
                "required": ["countries"]
            }),
        ),
        "new_device" => (
            "New Device",
            "Matches when the user is logging in from a device not previously seen",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
        "aal_below" => (
            "Assurance Level Below",
            "Matches when the current session's AAL is below the minimum required",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "level": { "type": "integer", "minimum": 1, "maximum": 3, "description": "Minimum required AAL (1, 2, or 3)" }
                },
                "required": ["level"]
            }),
        ),
        "outside_time_window" => (
            "Outside Time Window",
            "Matches when the request is made outside the allowed days/hours",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "allowed_days": { "type": "array", "items": { "type": "string", "enum": ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"] } },
                    "start_hour": { "type": "integer", "minimum": 0, "maximum": 23 },
                    "end_hour": { "type": "integer", "minimum": 1, "maximum": 24 },
                    "timezone": { "type": "string", "description": "IANA timezone" }
                },
                "required": ["allowed_days", "start_hour", "end_hour", "timezone"]
            }),
        ),
        "impossible_travel" => (
            "Impossible Travel",
            "Matches when the user appears to have traveled an impossible distance between logins",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "max_speed_kmh": { "type": "number", "minimum": 1, "description": "Maximum plausible travel speed in km/h (default: 900 = commercial flight)" }
                },
                "required": ["max_speed_kmh"]
            }),
        ),
        "email_not_verified" => (
            "Email Not Verified",
            "Matches when the user's email address has not been verified",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
        "role_in" => (
            "Role Is",
            "Matches when the user's organization role is one of the specified roles",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "roles": { "type": "array", "items": { "type": "string", "enum": ["owner","admin","developer","member","viewer"] }, "minItems": 1 }
                },
                "required": ["roles"]
            }),
        ),
        "role_not_in" => (
            "Role Is Not",
            "Matches when the user's organization role is NOT one of the specified roles",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "roles": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
                },
                "required": ["roles"]
            }),
        ),
        "vpn_detected" => (
            "VPN Detected",
            "Matches when the request appears to originate from a VPN or proxy",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
        "tor_detected" => (
            "Tor Exit Node Detected",
            "Matches when the request originates from a known Tor exit node",
            serde_json::json!({ "type": "object", "properties": {} }),
        ),
        "ip_in_range" => (
            "IP In Range",
            "Matches when the request IP is within the specified CIDR range",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cidr": { "type": "string", "description": "CIDR range (e.g. 10.0.0.0/8 or 192.168.1.0/24)" }
                },
                "required": ["cidr"]
            }),
        ),
        "ip_not_in_range" => (
            "IP Not In Range",
            "Matches when the request IP is NOT within the specified CIDR range",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cidr": { "type": "string", "description": "CIDR range (e.g. 10.0.0.0/8 or 192.168.1.0/24)" }
                },
                "required": ["cidr"]
            }),
        ),
        "custom_claim" => (
            "Custom JWT Claim",
            "Matches when a specific JWT claim key equals the specified value",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "claim_key":   { "type": "string", "description": "JWT claim key to inspect (e.g. app_metadata.tier)" },
                    "claim_value": { "type": "string", "description": "Expected value (string equality)" }
                },
                "required": ["claim_key", "claim_value"]
            }),
        ),
        "password_breached" => (
            "Password Breached",
            "Matches when the user's password has been found in known data breaches (via HaveIBeenPwned k-Anonymity API)",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "min_appearances": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1,
                        "description": "Minimum number of breach appearances to trigger (default: 1)"
                    }
                },
                "required": []
            }),
        ),
        _ => return None,
    };

    Some(ConditionTypeItem {
        condition_type: condition_type.to_string(),
        display_name: display_name.to_string(),
        description: description.to_string(),
        params_schema,
    })
}
