//! Condition CRUD handlers.
//!
//! Conditions are attached to rules and evaluated with AND/OR logic
//! via the `next_operator` field linking adjacent conditions.
//!
//! Supported condition types (15):
//!   risk_above, risk_below, country_in, country_not_in, new_device,
//!   aal_below, outside_time_window, impossible_travel, email_not_verified,
//!   role_in, role_not_in, vpn_detected, tor_detected,
//!   ip_in_range, ip_not_in_range, custom_claim

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use auth_core::Claims;
use shared_types::AppError;
use crate::state::AppState;
use super::types::*;
use super::permissions::{Tier, verify_config_ownership, mark_config_dirty};

/// All valid condition types with their required param keys.
const CONDITION_TYPES: &[(&str, &[&str])] = &[
    ("risk_above",          &["threshold"]),
    ("risk_below",          &["threshold"]),
    ("country_in",          &["countries"]),
    ("country_not_in",      &["countries"]),
    ("new_device",          &[]),
    ("aal_below",           &["level"]),
    ("outside_time_window", &["start_hour", "end_hour", "timezone"]),
    ("impossible_travel",   &["max_speed_kmh"]),
    ("email_not_verified",  &[]),
    ("role_in",             &["roles"]),
    ("role_not_in",         &["roles"]),
    ("vpn_detected",        &[]),
    ("tor_detected",        &[]),
    ("ip_in_range",         &["cidr"]),
    ("ip_not_in_range",     &["cidr"]),
    ("custom_claim",        &["claim_key", "claim_value"]),
];

fn valid_condition_type(ct: &str) -> bool {
    CONDITION_TYPES.iter().any(|(t, _)| *t == ct)
}

fn required_params_for(ct: &str) -> &'static [&'static str] {
    CONDITION_TYPES
        .iter()
        .find(|(t, _)| *t == ct)
        .map(|(_, p)| *p)
        .unwrap_or(&[])
}

/// Validate that all required params for a condition type are present.
fn validate_condition_params(
    condition_type: &str,
    params: &Option<serde_json::Value>,
) -> Result<(), AppError> {
    let required = required_params_for(condition_type);
    if required.is_empty() {
        return Ok(());
    }

    let provided_keys: Vec<String> = match params {
        Some(serde_json::Value::Object(m)) => m.keys().cloned().collect(),
        _ => vec![],
    };

    let missing: Vec<&&str> = required
        .iter()
        .filter(|r| !provided_keys.contains(&r.to_string()))
        .collect();

    if !missing.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Condition type '{}' requires params: {}. Missing: {}",
            condition_type,
            required.join(", "),
            missing.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
        )));
    }

    Ok(())
}

/// GET /policy-builder/condition-types
/// Returns the catalog of all supported condition types with their param schemas.
pub async fn list_condition_types() -> Json<Vec<ConditionTypeItem>> {
    let types = CONDITION_TYPES
        .iter()
        .map(|(ct, _required_params)| ConditionTypeItem {
            condition_type: ct.to_string(),
            display_name:   condition_display_name(ct),
            description:    condition_description(ct),
            params_schema:  condition_param_schema(ct),
        })
        .collect();

    Json(types)
}

/// POST /policy-builder/configs/:id/groups/:gid/rules/:rid/conditions
pub async fn add_condition(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, group_id, rule_id)): Path<(String, String, String)>,
    Json(req): Json<AddConditionRequest>,
) -> Result<(StatusCode, Json<ConditionDetail>), AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // Validate condition_type
    if !valid_condition_type(&req.condition_type) {
        return Err(AppError::BadRequest(format!(
            "Unknown condition type '{}'. Use GET /policy-builder/condition-types to see available types.",
            req.condition_type
        )));
    }

    // Validate required params
    validate_condition_params(&req.condition_type, &req.condition_params)?;

    // Validate next_operator
    if let Some(ref op) = req.next_operator {
        if !["and", "or"].contains(&op.as_str()) {
            return Err(AppError::BadRequest(
                "next_operator must be 'and' or 'or'".into(),
            ));
        }
    }

    // Verify rule belongs to this group and config
    let rule_exists: bool = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM policy_builder_rules WHERE id = $1 AND group_id = $2 AND config_id = $3)",
        rule_id, group_id, config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check rule: {}", e)))?
    .unwrap_or(false);

    if !rule_exists {
        return Err(AppError::NotFound(format!(
            "Rule '{}' not found in group '{}' / config '{}'",
            rule_id, group_id, config_id
        )));
    }

    // Determine sort_order
    let max_order: i32 = sqlx::query_scalar!(
        "SELECT COALESCE(MAX(sort_order), 0) FROM policy_builder_conditions WHERE rule_id = $1",
        rule_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to get max sort_order: {}", e)))?
    .unwrap_or(0);

    let sort_order = max_order + 1;
    let id = format!("pbc_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let now = chrono::Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO policy_builder_conditions
            (id, rule_id, condition_type, condition_params, next_operator, sort_order)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        id,
        rule_id,
        req.condition_type,
        req.condition_params,
        req.next_operator,
        sort_order,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to insert condition: {}", e)))?;

    mark_config_dirty(&state.db, &config_id).await;

    Ok((StatusCode::CREATED, Json(ConditionDetail {
        id,
        rule_id,
        condition_type:   req.condition_type,
        condition_params: req.condition_params,
        next_operator:    req.next_operator,
        sort_order,
        created_at:       now,
    })))
}

/// PUT /policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/:cid
pub async fn update_condition(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, _group_id, rule_id, condition_id)): Path<(String, String, String, String)>,
    Json(req): Json<UpdateConditionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    // If condition_type is being changed, validate it
    if let Some(ref ct) = req.condition_type {
        if !valid_condition_type(ct) {
            return Err(AppError::BadRequest(format!(
                "Unknown condition type '{}'",
                ct
            )));
        }
        // Validate params against new type
        validate_condition_params(ct, &req.condition_params)?;
    }

    if let Some(ref op) = req.next_operator {
        if !["and", "or"].contains(&op.as_str()) {
            return Err(AppError::BadRequest(
                "next_operator must be 'and' or 'or'".into(),
            ));
        }
    }

    let rows = sqlx::query!(
        r#"
        UPDATE policy_builder_conditions
        SET condition_type   = COALESCE($1, condition_type),
            condition_params = COALESCE($2, condition_params),
            next_operator    = COALESCE($3, next_operator),
            sort_order       = COALESCE($4, sort_order)
        WHERE id = $5 AND rule_id = $6
        "#,
        req.condition_type,
        req.condition_params,
        req.next_operator,
        req.sort_order,
        condition_id,
        rule_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to update condition: {}", e)))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "Condition not found: {}",
            condition_id
        )));
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({ "status": "updated", "id": condition_id })))
}

/// DELETE /policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/:cid
pub async fn remove_condition(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, _group_id, rule_id, condition_id)): Path<(String, String, String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    let rows = sqlx::query!(
        "DELETE FROM policy_builder_conditions WHERE id = $1 AND rule_id = $2",
        condition_id, rule_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to delete condition: {}", e)))?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "Condition not found: {}",
            condition_id
        )));
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({ "status": "removed", "id": condition_id })))
}

/// POST /policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/reorder
pub async fn reorder_conditions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, _group_id, rule_id)): Path<(String, String, String)>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest("Cannot modify an archived config".into()));
    }

    let existing_ids: Vec<String> = sqlx::query_scalar!(
        "SELECT id FROM policy_builder_conditions WHERE rule_id = $1",
        rule_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch condition ids: {}", e)))?;

    for id in &req.order {
        if !existing_ids.contains(id) {
            return Err(AppError::BadRequest(format!(
                "Condition id '{}' does not belong to rule '{}'",
                id, rule_id
            )));
        }
    }

    if req.order.len() != existing_ids.len() {
        return Err(AppError::BadRequest(format!(
            "Reorder list has {} items but rule has {} conditions. All conditions must be included.",
            req.order.len(),
            existing_ids.len()
        )));
    }

    for (idx, cond_id) in req.order.iter().enumerate() {
        sqlx::query!(
            "UPDATE policy_builder_conditions SET sort_order = $1 WHERE id = $2",
            (idx + 1) as i32,
            cond_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to reorder condition: {}", e)))?;
    }

    mark_config_dirty(&state.db, &config_id).await;

    Ok(Json(serde_json::json!({
        "status": "reordered",
        "rule_id": rule_id,
        "new_order": req.order
    })))
}

// ============================================================================
// Condition type metadata helpers
// ============================================================================

fn condition_display_name(ct: &str) -> String {
    match ct {
        "risk_above"          => "Risk Score Above Threshold",
        "risk_below"          => "Risk Score Below Threshold",
        "country_in"          => "Country Is In List",
        "country_not_in"      => "Country Is Not In List",
        "new_device"          => "New / Unrecognized Device",
        "aal_below"           => "Authentication Assurance Level Below",
        "outside_time_window" => "Outside Allowed Time Window",
        "impossible_travel"   => "Impossible Travel Detected",
        "email_not_verified"  => "Email Not Verified",
        "role_in"             => "User Role Is In List",
        "role_not_in"         => "User Role Is Not In List",
        "vpn_detected"        => "VPN Detected",
        "tor_detected"        => "Tor Exit Node Detected",
        "ip_in_range"         => "IP Address In CIDR Range",
        "ip_not_in_range"     => "IP Address Not In CIDR Range",
        "custom_claim"        => "Custom JWT Claim Matches",
        _                     => ct,
    }
    .to_string()
}

fn condition_description(ct: &str) -> String {
    match ct {
        "risk_above"          => "Triggers when the computed risk score exceeds the given threshold (0–100).",
        "risk_below"          => "Triggers when the computed risk score is below the given threshold (0–100).",
        "country_in"          => "Triggers when the request originates from one of the listed ISO-3166 country codes.",
        "country_not_in"      => "Triggers when the request does NOT originate from any of the listed country codes.",
        "new_device"          => "Triggers when the device fingerprint has not been seen before for this user.",
        "aal_below"           => "Triggers when the session's Authentication Assurance Level is below the required level (1–3).",
        "outside_time_window" => "Triggers when the current time (in the given timezone) is outside the allowed hour range.",
        "impossible_travel"   => "Triggers when the user's location has changed faster than physically possible.",
        "email_not_verified"  => "Triggers when the user's email address has not been verified.",
        "role_in"             => "Triggers when the user holds one of the specified roles.",
        "role_not_in"         => "Triggers when the user does NOT hold any of the specified roles.",
        "vpn_detected"        => "Triggers when the IP address is identified as a VPN exit node.",
        "tor_detected"        => "Triggers when the IP address is identified as a Tor exit node.",
        "ip_in_range"         => "Triggers when the request IP falls within the specified CIDR range.",
        "ip_not_in_range"     => "Triggers when the request IP does NOT fall within the specified CIDR range.",
        "custom_claim"        => "Triggers when a specific JWT claim key equals the specified value.",
        _                     => "",
    }
    .to_string()
}

fn condition_param_schema(ct: &str) -> serde_json::Value {
    match ct {
        "risk_above" | "risk_below" => serde_json::json!({
            "type": "object",
            "required": ["threshold"],
            "properties": {
                "threshold": { "type": "number", "minimum": 0, "maximum": 100,
                               "description": "Risk score threshold (0–100)" }
            }
        }),
        "country_in" | "country_not_in" => serde_json::json!({
            "type": "object",
            "required": ["countries"],
            "properties": {
                "countries": { "type": "array", "items": { "type": "string", "pattern": "^[A-Z]{2}$" },
                               "description": "ISO-3166 alpha-2 country codes, e.g. [\"US\", \"GB\"]" }
            }
        }),
        "new_device" => serde_json::json!({ "type": "object", "properties": {} }),
        "aal_below" => serde_json::json!({
            "type": "object",
            "required": ["level"],
            "properties": {
                "level": { "type": "integer", "minimum": 1, "maximum": 3,
                           "description": "Minimum required AAL (1, 2, or 3)" }
            }
        }),
        "outside_time_window" => serde_json::json!({
            "type": "object",
            "required": ["start_hour", "end_hour", "timezone"],
            "properties": {
                "start_hour": { "type": "integer", "minimum": 0, "maximum": 23,
                                "description": "Start of allowed window (0–23, inclusive)" },
                "end_hour":   { "type": "integer", "minimum": 0, "maximum": 23,
                                "description": "End of allowed window (0–23, inclusive)" },
                "timezone":   { "type": "string",
                                "description": "IANA timezone, e.g. 'America/New_York'" }
            }
        }),
        "impossible_travel" => serde_json::json!({
            "type": "object",
            "required": ["max_speed_kmh"],
            "properties": {
                "max_speed_kmh": { "type": "number", "minimum": 1,
                                   "description": "Maximum plausible travel speed in km/h (default: 900)" }
            }
        }),
        "email_not_verified" => serde_json::json!({ "type": "object", "properties": {} }),
        "role_in" | "role_not_in" => serde_json::json!({
            "type": "object",
            "required": ["roles"],
            "properties": {
                "roles": { "type": "array", "items": { "type": "string" },
                           "description": "List of role slugs to match against" }
            }
        }),
        "vpn_detected" | "tor_detected" => serde_json::json!({ "type": "object", "properties": {} }),
        "ip_in_range" | "ip_not_in_range" => serde_json::json!({
            "type": "object",
            "required": ["cidr"],
            "properties": {
                "cidr": { "type": "string",
                          "description": "CIDR notation, e.g. '10.0.0.0/8' or '2001:db8::/32'" }
            }
        }),
        "custom_claim" => serde_json::json!({
            "type": "object",
            "required": ["claim_key", "claim_value"],
            "properties": {
                "claim_key":   { "type": "string", "description": "JWT claim key to inspect" },
                "claim_value": { "type": "string", "description": "Expected value (string equality)" }
            }
        }),
        _ => serde_json::json!({}),
    }
}
