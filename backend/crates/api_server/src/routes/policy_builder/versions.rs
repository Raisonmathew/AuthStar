//! Version history, rollback, diff, and per-version export handlers.
//!
//! Every `POST /compile` or `POST /import-ast` creates an immutable
//! `policy_builder_versions` record. This module exposes:
//!
//! - `GET  /configs/:id/versions`          — list all versions
//! - `GET  /configs/:id/versions/:vid`     — get a single version detail
//! - `POST /configs/:id/versions/:vid/rollback` — reactivate a past version
//! - `POST /configs/:id/versions/:vid/diff`     — compare two versions
//! - `GET  /configs/:id/versions/:vid/export-ast` — download a past version's AST

use super::permissions::{verify_config_ownership, write_audit, PolicyAuditEvent, Tier};
use super::types::*;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use shared_types::AppError;

// ============================================================================
// List versions
// ============================================================================

/// GET /policy-builder/configs/:id/versions
pub async fn list_versions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
) -> Result<Json<Vec<VersionSummary>>, AppError> {
    verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    let rows = sqlx::query!(
        r#"
        SELECT id, config_id, version_number, ast_hash_b64, compiled_by, source, compiled_at
        FROM policy_builder_versions
        WHERE config_id = $1
        ORDER BY version_number DESC
        "#,
        config_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch versions: {e}")))?;

    // Get the currently active version number for this config
    let active_version: Option<i32> = sqlx::query_scalar!(
        "SELECT active_version FROM policy_builder_configs WHERE id = $1",
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch active_version: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| VersionSummary {
                id: r.id,
                config_id: r.config_id,
                version_number: r.version_number,
                ast_hash_b64: r.ast_hash_b64,
                compiled_by: r.compiled_by,
                source: r.source,
                is_active: active_version == Some(r.version_number),
                compiled_at: r.compiled_at,
            })
            .collect(),
    ))
}

// ============================================================================
// Get single version
// ============================================================================

/// GET /policy-builder/configs/:id/versions/:vid
pub async fn get_version(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, version_id)): Path<(String, String)>,
) -> Result<Json<VersionDetail>, AppError> {
    verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    let row = sqlx::query!(
        r#"
        SELECT id, config_id, version_number, rule_snapshot, ast_snapshot,
               ast_hash_b64, compiled_by, source, compiled_at
        FROM policy_builder_versions
        WHERE id = $1 AND config_id = $2
        "#,
        version_id,
        config_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch version: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Version not found: {version_id}")))?;

    let active_version: Option<i32> = sqlx::query_scalar!(
        "SELECT active_version FROM policy_builder_configs WHERE id = $1",
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch active_version: {e}")))?;

    Ok(Json(VersionDetail {
        id: row.id,
        config_id: row.config_id,
        version_number: row.version_number,
        rule_snapshot: row.rule_snapshot,
        ast_snapshot: row.ast_snapshot,
        ast_hash_b64: row.ast_hash_b64,
        compiled_by: row.compiled_by,
        source: row.source,
        is_active: active_version == Some(row.version_number),
        compiled_at: row.compiled_at,
    }))
}

// ============================================================================
// Rollback
// ============================================================================

/// POST /policy-builder/configs/:id/versions/:vid/rollback
///
/// Reactivates a previous version. Creates a new version record with
/// `source = 'rollback'` pointing to the rolled-back AST, then activates it.
/// This preserves the full audit trail — rollback is never destructive.
pub async fn rollback_version(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, version_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    if config.state == "archived" {
        return Err(AppError::BadRequest(
            "Cannot rollback an archived config".into(),
        ));
    }

    // Fetch the target version
    let target = sqlx::query!(
        r#"
        SELECT id, version_number, rule_snapshot, ast_snapshot, ast_hash_b64
        FROM policy_builder_versions
        WHERE id = $1 AND config_id = $2
        "#,
        version_id,
        config_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch target version: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Version not found: {version_id}")))?;

    // Get current draft_version to assign the new rollback version number
    let draft_version: i32 = sqlx::query_scalar!(
        "SELECT draft_version FROM policy_builder_configs WHERE id = $1",
        config_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch draft_version: {e}")))?;

    let new_version_id = format!("pbv_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    // Create a new version record with source='rollback'
    sqlx::query!(
        r#"
        INSERT INTO policy_builder_versions
            (id, config_id, version_number, rule_snapshot, ast_snapshot,
             ast_hash_b64, compiled_by, source)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'rollback')
        "#,
        new_version_id,
        config_id,
        draft_version,
        target.rule_snapshot,
        target.ast_snapshot,
        target.ast_hash_b64, // Option<String> — sqlx handles nullable
        claims.sub,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create rollback version: {e}")))?;

    // Activate the rollback version
    sqlx::query!(
        r#"
        UPDATE policy_builder_configs
        SET active_version          = $1,
            active_capsule_hash_b64 = $2,
            state                   = 'active',
            activated_at            = NOW(),
            activated_by            = $3,
            draft_version           = draft_version + 1,
            updated_at              = NOW()
        WHERE id = $4
        "#,
        draft_version,
        target.ast_hash_b64, // Option<String> — sqlx handles nullable
        claims.sub,
        config_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to activate rollback: {e}")))?;

    write_audit(
        &state.db,
        PolicyAuditEvent {
            tenant_id: &claims.tenant_id,
            config_id: Some(&config_id),
            action_key: Some(&config.action_key),
            event_type: "config_rolled_back",
            actor_id: &claims.sub,
            actor_ip: None,
            description: Some(format!(
                "Config rolled back to version {} (new version: {})",
                target.version_number, draft_version
            )),
            metadata: Some(serde_json::json!({
                "rolled_back_to_version_id":     version_id,
                "rolled_back_to_version_number": target.version_number,
                "new_version_id":                new_version_id,
                "new_version_number":            draft_version,
                "ast_hash_b64":                  target.ast_hash_b64,
            })),
        },
    )
    .await;

    tracing::info!(
        tenant_id  = %claims.tenant_id,
        config_id  = %config_id,
        rolled_back_to = target.version_number,
        new_version    = draft_version,
        "Policy builder config rolled back"
    );

    Ok(Json(serde_json::json!({
        "status":                        "rolled_back",
        "config_id":                     config_id,
        "rolled_back_to_version_number": target.version_number,
        "new_version_id":                new_version_id,
        "new_version_number":            draft_version,
        "ast_hash_b64":                  target.ast_hash_b64,
        "activated_by":                  claims.sub,
    })))
}

// ============================================================================
// Diff
// ============================================================================

/// POST /policy-builder/configs/:id/versions/:vid/diff
///
/// Body: `{ "compare_to": "pbv_yyy" }` (optional; defaults to the version
/// immediately before `:vid` if omitted).
///
/// Returns a list of `DiffChange` records describing what changed between
/// the two versions.
pub async fn diff_versions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, version_id)): Path<(String, String)>,
    Json(req): Json<DiffRequest>,
) -> Result<Json<DiffResponse>, AppError> {
    verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    // Fetch the "from" version (the one specified in the path)
    let from_row = sqlx::query!(
        r#"
        SELECT id, version_number, rule_snapshot, ast_hash_b64, compiled_at
        FROM policy_builder_versions
        WHERE id = $1 AND config_id = $2
        "#,
        version_id,
        config_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch from-version: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Version not found: {version_id}")))?;

    struct TargetVersion {
        id: String,
        version_number: i32,
        rule_snapshot: serde_json::Value,
        ast_hash_b64: Option<String>,
        compiled_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let to_row = if let Some(ref compare_to_id) = req.compare_to {
        let r = sqlx::query!(
            r#"
            SELECT id, version_number, rule_snapshot, ast_hash_b64, compiled_at
            FROM policy_builder_versions
            WHERE id = $1 AND config_id = $2
            "#,
            compare_to_id,
            config_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch to-version: {e}")))?
        .ok_or_else(|| {
            AppError::NotFound(format!("compare_to version not found: {compare_to_id}"))
        })?;

        TargetVersion {
            id: r.id,
            version_number: r.version_number,
            rule_snapshot: r.rule_snapshot,
            ast_hash_b64: r.ast_hash_b64,
            compiled_at: r.compiled_at,
        }
    } else {
        // Default: the version immediately before from_row
        let r = sqlx::query!(
            r#"
            SELECT id, version_number, rule_snapshot, ast_hash_b64, compiled_at
            FROM policy_builder_versions
            WHERE config_id = $1 AND version_number < $2
            ORDER BY version_number DESC
            LIMIT 1
            "#,
            config_id,
            from_row.version_number
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch previous version: {e}")))?
        .ok_or_else(|| {
            AppError::BadRequest(
                "No previous version to compare against. Provide 'compare_to' explicitly.".into(),
            )
        })?;

        TargetVersion {
            id: r.id,
            version_number: r.version_number,
            rule_snapshot: r.rule_snapshot,
            ast_hash_b64: r.ast_hash_b64,
            compiled_at: r.compiled_at,
        }
    };

    // Compute diff between the two rule_snapshots
    let changes = compute_snapshot_diff(&from_row.rule_snapshot, &to_row.rule_snapshot);

    Ok(Json(DiffResponse {
        from_version_id: from_row.id,
        from_version_number: from_row.version_number,
        from_hash: from_row.ast_hash_b64,
        from_compiled_at: from_row.compiled_at,
        to_version_id: to_row.id,
        to_version_number: to_row.version_number,
        to_hash: to_row.ast_hash_b64,
        to_compiled_at: to_row.compiled_at,
        changes_count: changes.len(),
        changes,
    }))
}

// ============================================================================
// Per-version export
// ============================================================================

/// GET /policy-builder/configs/:id/versions/:vid/export-ast
pub async fn export_version_ast(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((config_id, version_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let config = verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    let row = sqlx::query!(
        r#"
        SELECT id, version_number, ast_snapshot, ast_hash_b64, source, compiled_at
        FROM policy_builder_versions
        WHERE id = $1 AND config_id = $2
        "#,
        version_id,
        config_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to fetch version: {e}")))?
    .ok_or_else(|| AppError::NotFound(format!("Version not found: {version_id}")))?;

    let export = serde_json::json!({
        "authstar_policy_export": true,
        "export_version":         "2.0",
        "config_id":              config_id,
        "action_key":             config.action_key,
        "version_number":         row.version_number,
        "ast_hash_b64":           row.ast_hash_b64,   // Option<String>
        "source":                 row.source,
        "compiled_at":            row.compiled_at,    // Option<DateTime<Utc>>
        "ast":                    row.ast_snapshot,
    });

    let body = serde_json::to_string_pretty(&export)
        .map_err(|e| AppError::Internal(format!("Failed to serialise export: {e}")))?;

    let filename = format!(
        "authstar-policy-{}-v{}.json",
        config.action_key.replace(':', "-"),
        row.version_number
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(axum::body::Body::from(body))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

// ============================================================================
// Diff engine
// ============================================================================

/// Compute a structural diff between two rule snapshots.
/// Returns a list of human-readable change records.
fn compute_snapshot_diff(from: &serde_json::Value, to: &serde_json::Value) -> Vec<DiffChange> {
    let mut changes = Vec::new();

    let from_groups = snapshot_groups(from);
    let to_groups = snapshot_groups(to);

    // Groups added in "to" that weren't in "from"
    for (gid, g) in &to_groups {
        if !from_groups.contains_key(gid) {
            changes.push(DiffChange {
                change_type: "group_added".into(),
                path: format!("groups/{gid}"),
                description: format!(
                    "Group '{}' was added",
                    g.get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(gid)
                ),
                from_value: None,
                to_value: Some(g.clone()),
            });
        }
    }

    // Groups removed from "from" that aren't in "to"
    for (gid, g) in &from_groups {
        if !to_groups.contains_key(gid) {
            changes.push(DiffChange {
                change_type: "group_removed".into(),
                path: format!("groups/{gid}"),
                description: format!(
                    "Group '{}' was removed",
                    g.get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(gid)
                ),
                from_value: Some(g.clone()),
                to_value: None,
            });
        }
    }

    // Groups present in both — check for changes
    for (gid, from_g) in &from_groups {
        if let Some(to_g) = to_groups.get(gid) {
            // Check match_mode change
            diff_field(&mut changes, gid, "match_mode", from_g, to_g);
            diff_field(&mut changes, gid, "on_match", from_g, to_g);
            diff_field(&mut changes, gid, "on_no_match", from_g, to_g);
            diff_field(&mut changes, gid, "is_enabled", from_g, to_g);

            // Diff rules within the group
            let from_rules = snapshot_rules(from_g);
            let to_rules = snapshot_rules(to_g);

            for (rid, r) in &to_rules {
                if !from_rules.contains_key(rid) {
                    changes.push(DiffChange {
                        change_type: "rule_added".into(),
                        path: format!("groups/{gid}/rules/{rid}"),
                        description: format!(
                            "Rule '{}' was added to group '{}'",
                            r.get("display_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(rid),
                            from_g
                                .get("display_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(gid)
                        ),
                        from_value: None,
                        to_value: Some(r.clone()),
                    });
                }
            }

            for (rid, r) in &from_rules {
                if !to_rules.contains_key(rid) {
                    changes.push(DiffChange {
                        change_type: "rule_removed".into(),
                        path: format!("groups/{gid}/rules/{rid}"),
                        description: format!(
                            "Rule '{}' was removed from group '{}'",
                            r.get("display_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(rid),
                            from_g
                                .get("display_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(gid)
                        ),
                        from_value: Some(r.clone()),
                        to_value: None,
                    });
                }
            }

            // Rules present in both — check param_values changes
            for (rid, from_r) in &from_rules {
                if let Some(to_r) = to_rules.get(rid) {
                    diff_field(&mut changes, rid, "param_values", from_r, to_r);
                    diff_field(&mut changes, rid, "is_enabled", from_r, to_r);

                    // Diff conditions
                    let from_conds = snapshot_conditions(from_r);
                    let to_conds = snapshot_conditions(to_r);

                    for (cid, c) in &to_conds {
                        if !from_conds.contains_key(cid) {
                            changes.push(DiffChange {
                                change_type: "condition_added".into(),
                                path: format!("groups/{gid}/rules/{rid}/conditions/{cid}"),
                                description: format!(
                                    "Condition '{}' was added to rule '{}'",
                                    c.get("condition_type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(cid),
                                    from_r
                                        .get("display_name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(rid)
                                ),
                                from_value: None,
                                to_value: Some(c.clone()),
                            });
                        }
                    }

                    for (cid, c) in &from_conds {
                        if !to_conds.contains_key(cid) {
                            changes.push(DiffChange {
                                change_type: "condition_removed".into(),
                                path: format!("groups/{gid}/rules/{rid}/conditions/{cid}"),
                                description: format!(
                                    "Condition '{}' was removed from rule '{}'",
                                    c.get("condition_type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(cid),
                                    from_r
                                        .get("display_name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or(rid)
                                ),
                                from_value: Some(c.clone()),
                                to_value: None,
                            });
                        }
                    }

                    for (cid, from_c) in &from_conds {
                        if let Some(to_c) = to_conds.get(cid) {
                            diff_field(&mut changes, cid, "condition_params", from_c, to_c);
                            diff_field(&mut changes, cid, "next_operator", from_c, to_c);
                        }
                    }
                }
            }
        }
    }

    changes
}

// ============================================================================
// Diff helpers
// ============================================================================

type SnapshotMap = std::collections::HashMap<String, serde_json::Value>;

fn snapshot_groups(snapshot: &serde_json::Value) -> SnapshotMap {
    snapshot
        .get("groups")
        .and_then(|g| g.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|g| {
                    g.get("id")
                        .and_then(|v| v.as_str())
                        .map(|id| (id.to_string(), g.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn snapshot_rules(group: &serde_json::Value) -> SnapshotMap {
    group
        .get("rules")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    r.get("id")
                        .and_then(|v| v.as_str())
                        .map(|id| (id.to_string(), r.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn snapshot_conditions(rule: &serde_json::Value) -> SnapshotMap {
    rule.get("conditions")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.get("id")
                        .and_then(|v| v.as_str())
                        .map(|id| (id.to_string(), c.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn diff_field(
    changes: &mut Vec<DiffChange>,
    entity_id: &str,
    field: &str,
    from: &serde_json::Value,
    to: &serde_json::Value,
) {
    let from_val = from.get(field);
    let to_val = to.get(field);

    if from_val != to_val {
        changes.push(DiffChange {
            change_type: "field_changed".into(),
            path: format!("{entity_id}/{field}"),
            description: format!("Field '{field}' changed on entity '{entity_id}'"),
            from_value: from_val.cloned(),
            to_value: to_val.cloned(),
        });
    }
}
