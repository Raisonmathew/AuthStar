//! AST compiler for the Unified Policy Builder.
//!
//! Converts the structured rule groups / rules / conditions stored in the
//! database into the canonical AuthStar capsule AST (JSON) that the
//! capsule runtime can execute.
//!
//! # AST shape (top-level)
//! ```json
//! {
//!   "version": 2,
//!   "action": "auth:login",
//!   "groups": [
//!     {
//!       "id": "pbg_xxx",
//!       "display_name": "High-Risk Block",
//!       "match_mode": "any",
//!       "on_match": "deny",
//!       "on_no_match": "continue",
//!       "stepup_methods": [],
//!       "rules": [
//!         {
//!           "id": "pbr_yyy",
//!           "template": "risk_threshold",
//!           "params": { "threshold": 80 },
//!           "conditions": [
//!             { "type": "risk_above", "params": { "threshold": 80 }, "next_op": "and" }
//!           ]
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```

use shared_types::AppError;
use super::types::{GroupDetail, RuleDetail, GroupSummary, RuleSummary};

pub mod condition_compiler;

/// Compile a full config (list of groups) into the capsule AST JSON.
///
/// Returns `(ast_json, group_summaries)` where `group_summaries` is used
/// for the simulation trace and the preview endpoint.
pub fn compile_config_to_ast(
    groups: &[GroupDetail],
    action_key: &str,
) -> Result<(serde_json::Value, Vec<GroupSummary>), AppError> {
    let mut ast_groups = Vec::with_capacity(groups.len());
    let mut summaries  = Vec::with_capacity(groups.len());

    for group in groups {
        if !group.is_enabled {
            continue;
        }

        let (ast_group, summary) = compile_group(group, action_key)?;
        ast_groups.push(ast_group);
        summaries.push(summary);
    }

    let ast = serde_json::json!({
        "version":  2,
        "action":   action_key,
        "groups":   ast_groups,
    });

    Ok((ast, summaries))
}

/// Compile a single group into its AST node.
fn compile_group(
    group: &GroupDetail,
    _action_key: &str,
) -> Result<(serde_json::Value, GroupSummary), AppError> {
    let mut ast_rules   = Vec::new();
    let mut rule_summaries = Vec::new();

    for rule in &group.rules {
        if !rule.is_enabled {
            continue;
        }

        let (ast_rule, rule_summary) = compile_rule(rule)?;
        ast_rules.push(ast_rule);
        rule_summaries.push(rule_summary);
    }

    if ast_rules.is_empty() {
        // A group with no enabled rules is a no-op; treat as "continue"
        tracing::warn!(
            group_id = %group.id,
            "Rule group has no enabled rules — will be skipped during evaluation"
        );
    }

    let ast_group = serde_json::json!({
        "id":            group.id,
        "display_name":  group.display_name,
        "match_mode":    group.match_mode,
        "on_match":      group.on_match,
        "on_no_match":   group.on_no_match,
        "stepup_methods": group.stepup_methods,
        "rules":         ast_rules,
    });

    let summary = GroupSummary {
        group_id:     group.id.clone(),
        display_name: group.display_name.clone(),
        match_mode:   group.match_mode.clone(),
        on_match:     group.on_match.clone(),
        on_no_match:  group.on_no_match.clone(),
        rule_count:   rule_summaries.len(),
        rules:        rule_summaries,
    };

    Ok((ast_group, summary))
}

/// Compile a single rule into its AST node.
fn compile_rule(rule: &RuleDetail) -> Result<(serde_json::Value, RuleSummary), AppError> {
    // Compile conditions into the AST condition chain
    let ast_conditions = condition_compiler::compile_conditions(&rule.conditions)?;

    // Merge template param_defaults with rule param_values
    let params = rule.param_values.clone().unwrap_or(serde_json::json!({}));

    let ast_rule = serde_json::json!({
        "id":         rule.id,
        "template":   rule.template_slug,
        "display_name": rule.display_name,
        "params":     params,
        "conditions": ast_conditions,
    });

    let summary = RuleSummary {
        rule_id:       rule.id.clone(),
        template_slug: rule.template_slug.clone(),
        display_name:  rule.display_name.clone(),
        condition_count: rule.conditions.len(),
    };

    Ok((ast_rule, summary))
}

/// Validate the compiled AST for semantic correctness.
/// Returns a list of validation warnings (non-fatal) and errors (fatal).
pub fn validate_ast(
    ast: &serde_json::Value,
    _action_key: &str,
) -> Result<Vec<String>, AppError> {
    let mut warnings = Vec::new();

    let groups = ast.get("groups")
        .and_then(|g| g.as_array())
        .ok_or_else(|| AppError::Internal("AST missing 'groups' array".into()))?;

    if groups.is_empty() {
        warnings.push(
            "Policy has no enabled rule groups. All requests will be allowed by default.".into(),
        );
        return Ok(warnings);
    }

    for (gi, group) in groups.iter().enumerate() {
        let gid = group.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let rules = group.get("rules").and_then(|r| r.as_array());

        let rules_empty = rules.map(|r| r.is_empty()).unwrap_or(true);
        if rules_empty {
            warnings.push(format!(
                "Group {} (index {}) has no enabled rules and will be skipped.",
                gid, gi
            ));
        } else {
            let rules_arr = rules.unwrap();
            for (ri, rule) in rules_arr.iter().enumerate() {
                let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let conditions = rule.get("conditions").and_then(|c| c.as_array());

                if conditions.map(|c| c.is_empty()).unwrap_or(true) {
                    warnings.push(format!(
                        "Rule {} (group {}, index {}) has no conditions — \
                         it will always match.",
                        rid, gid, ri
                    ));
                }
            }
        }

        // Warn if last group has on_no_match = "continue" (implicit allow)
        if gi == groups.len() - 1 {
            let on_no_match = group
                .get("on_no_match")
                .and_then(|v| v.as_str())
                .unwrap_or("continue");
            if on_no_match == "continue" {
                warnings.push(format!(
                    "Last group {} has on_no_match='continue', which means requests \
                     that don't match any rule will be allowed. Consider setting \
                     on_no_match='deny' for a deny-by-default posture.",
                    gid
                ));
            }
        }
    }

    Ok(warnings)
}
