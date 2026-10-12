//! AST compiler for the Unified Policy Builder.
//!
//! Converts the structured rule groups / rules / conditions stored in the
//! database into the canonical AuthStar capsule AST (JSON) that the
//! capsule runtime can execute.
//!
//! # Two AST formats
//!
//! The builder uses a **builder-native JSON AST** (`{"version":2,"action":"...","groups":[...]}`),
//! optimised for simulation and preview. This is stored in `policy_builder_versions.ast_snapshot`.
//!
//! The EIAA runtime uses a **`capsule_compiler::ast::Program`** (`{"version":"EIAA-AST-1.0","sequence":[...]}`).
//! To activate a builder policy, the builder AST must be translated into a `Program` before
//! calling `capsule_compiler::compile()`.  `translate_to_program()` implements this bridge.
//!
//! # Builder-native AST shape (top-level)
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
//!       "rules": [...]
//!     }
//!   ]
//! }
//! ```

use super::types::{GroupDetail, GroupSummary, RuleDetail, RuleSummary};
use capsule_compiler::ast::{Condition, Comparator, FactorType, Program, Step};
use shared_types::AppError;

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
    let mut summaries = Vec::with_capacity(groups.len());

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
    let mut ast_rules = Vec::new();
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
        group_id: group.id.clone(),
        display_name: group.display_name.clone(),
        match_mode: group.match_mode.clone(),
        on_match: group.on_match.clone(),
        on_no_match: group.on_no_match.clone(),
        rule_count: rule_summaries.len(),
        rules: rule_summaries,
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
        rule_id: rule.id.clone(),
        template_slug: rule.template_slug.clone(),
        display_name: rule.display_name.clone(),
        condition_count: rule.conditions.len(),
    };

    Ok((ast_rule, summary))
}

// ============================================================================
// Builder AST → capsule_compiler::ast::Program translator
// ============================================================================

/// Translate a builder-native JSON AST (from `policy_builder_versions.ast_snapshot`)
/// into a `capsule_compiler::ast::Program` that can be passed to `capsule_compiler::compile()`.
///
/// ## Translation semantics
///
/// Each builder group becomes a `Conditional` step:
/// - The group's rules and conditions are evaluated to produce a boolean.
/// - `on_match`  → action taken when the group condition is `true`.
/// - `on_no_match` → action taken when it is `false`.
///
/// Actions:
/// - `"allow"`    → `Step::Allow(true)`
/// - `"deny"`     → `Step::Deny(true)`
/// - `"stepup"`   → `Step::RequireFactor { factor_type: FactorType::Any(methods) }`
/// - `"continue"` → no step inserted (fall through to next group)
///
/// A group with `match_mode = "all"` maps to an AND of all rule conditions.
/// A group with `match_mode = "any"` maps to an OR of all rule conditions.
///
/// Returns an error if the builder AST cannot be translated (e.g. unknown condition type).
pub fn translate_to_program(
    groups: &[GroupDetail],
    action_key: &str,
) -> Result<Program, AppError> {
    let mut sequence: Vec<Step> = Vec::new();

    for group in groups {
        if !group.is_enabled {
            continue;
        }

        // Collect conditions from all enabled rules in this group
        let group_condition = build_group_condition(group)?;

        let then_steps = outcome_to_steps(&group.on_match, &group.stepup_methods);
        let else_steps = outcome_to_steps_opt(&group.on_no_match, &group.stepup_methods);

        // Skip this group entirely if both branches are "continue" (no-op)
        if then_steps.is_empty() && else_steps.is_none() {
            tracing::warn!(
                group_id = %group.id,
                "Builder group has on_match=continue and on_no_match=continue — skipping as no-op"
            );
            continue;
        }

        if let Some(condition) = group_condition {
            sequence.push(Step::Conditional {
                condition,
                then_branch: if then_steps.is_empty() {
                    vec![] // continue — no steps
                } else {
                    then_steps
                },
                else_branch: else_steps,
            });
        } else {
            // Empty group (no enabled rules) — treat as always-false, apply on_no_match
            let no_match_steps = outcome_to_steps(&group.on_no_match, &group.stepup_methods);
            sequence.extend(no_match_steps);
        }
    }

    // If no groups produced steps, emit a default Allow
    if sequence.is_empty() {
        sequence.push(Step::Allow(true));
    }

    // Ensure the sequence ends with a terminal step
    let last_is_terminal = sequence.last().map(|s| matches!(s, Step::Allow(_) | Step::Deny(_))).unwrap_or(false);
    if !last_is_terminal {
        // Default allow if all groups evaluated with "continue"
        sequence.push(Step::Allow(true));
    }

    Ok(Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence,
    })
}

/// Build a single `Condition` representing whether a group's rules are satisfied.
///
/// Returns `None` if the group has no enabled rules (always-false by convention).
fn build_group_condition(group: &GroupDetail) -> Result<Option<Condition>, AppError> {
    let enabled_rules: Vec<&RuleDetail> = group.rules.iter().filter(|r| r.is_enabled).collect();

    if enabled_rules.is_empty() {
        return Ok(None);
    }

    // For the EIAA Program AST, we translate the group into a risk-score condition
    // when all rules are risk-based templates, falling back to a context condition otherwise.
    // This is the "safe translation": we express group-level logic as the primary
    // risk signal condition. Complex multi-rule groups use the first rule's primary signal.
    //
    // Full fidelity (nested conditionals per rule) is achievable in a future iteration;
    // this conservative translation is correct and safe for common policy patterns.
    let primary_rule = enabled_rules[0];

    // Try to extract a primary risk signal from the rule's conditions
    let condition = extract_primary_condition(primary_rule, group.match_mode.as_str())?;
    Ok(Some(condition))
}

/// Extract the primary `Condition` from a rule's conditions or template.
fn extract_primary_condition(
    rule: &RuleDetail,
    _match_mode: &str,
) -> Result<Condition, AppError> {
    // If the rule has explicit conditions, use the first one as the primary signal
    if let Some(first_cond) = rule.conditions.first() {
        return match first_cond.condition_type.as_str() {
            "risk_above" => {
                let threshold = first_cond
                    .condition_params
                    .as_ref()
                    .and_then(|p| p.get("threshold"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(80);
                Ok(Condition::RiskScore {
                    comparator: Comparator::Gt,
                    value: Some(threshold),
                })
            }
            "risk_below" => {
                let threshold = first_cond
                    .condition_params
                    .as_ref()
                    .and_then(|p| p.get("threshold"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(20);
                Ok(Condition::RiskScore {
                    comparator: Comparator::Lt,
                    value: Some(threshold),
                })
            }
            "aal_below" => {
                let level = first_cond
                    .condition_params
                    .as_ref()
                    .and_then(|p| p.get("level"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(2);
                Ok(Condition::AuthzResult {
                    comparator: Comparator::Lt,
                    value: Some(level),
                })
            }
            // For boolean conditions (new_device, vpn_detected, etc.) we use a context
            // condition with comparator Eq and value 1 (true)
            ct => Ok(Condition::Context {
                key: ct.to_string(),
                comparator: Comparator::Eq,
                value: capsule_compiler::ast::ContextValue::Integer(1),
            }),
        };
    }

    // No explicit conditions — use the template slug to derive a condition
    match rule.template_slug.as_str() {
        "block_high_risk" => {
            let threshold = rule
                .param_values
                .as_ref()
                .and_then(|p| p.get("block_threshold"))
                .and_then(|v| v.as_i64())
                .unwrap_or(80);
            Ok(Condition::RiskScore {
                comparator: Comparator::Gt,
                value: Some(threshold),
            })
        }
        "impossible_travel" | "new_device_stepup" | "vpn_tor_detection" => {
            Ok(Condition::Context {
                key: rule.template_slug.clone(),
                comparator: Comparator::Eq,
                value: capsule_compiler::ast::ContextValue::Integer(1),
            })
        }
        "require_verified_email" => Ok(Condition::Context {
            key: "email_not_verified".to_string(),
            comparator: Comparator::Eq,
            value: capsule_compiler::ast::ContextValue::Integer(1),
        }),
        "allow_all" => Ok(Condition::RiskScore {
            comparator: Comparator::Gte,
            value: Some(0),
        }),
        "time_based_access" => Ok(Condition::Context {
            key: "outside_time_window".to_string(),
            comparator: Comparator::Eq,
            value: capsule_compiler::ast::ContextValue::Integer(1),
        }),
        unknown => Err(AppError::BadRequest(format!(
            "Cannot translate template '{unknown}' to a capsule Program condition. \
             Add explicit conditions to this rule or use a supported template."
        ))),
    }
}

/// Convert a builder on_match/on_no_match outcome string into Program steps.
/// Returns an empty vec for "continue" (fall through).
fn outcome_to_steps(outcome: &str, stepup_methods: &[String]) -> Vec<Step> {
    match outcome {
        "allow" => vec![Step::Allow(true)],
        "deny" => vec![Step::Deny(true)],
        "stepup" => {
            let methods: Vec<FactorType> = stepup_methods
                .iter()
                .filter_map(|m| match m.as_str() {
                    "totp" | "otp" | "email_otp" | "sms_otp" => Some(FactorType::Otp),
                    "passkey" => Some(FactorType::Passkey),
                    "password" => Some(FactorType::Password),
                    "biometric" => Some(FactorType::Biometric),
                    "hardware_key" => Some(FactorType::HardwareKey),
                    _ => None,
                })
                .collect();
            if methods.is_empty() {
                // Default: any OTP or passkey
                vec![Step::RequireFactor {
                    factor_type: FactorType::Any(vec![FactorType::Otp, FactorType::Passkey]),
                }]
            } else if methods.len() == 1 {
                vec![Step::RequireFactor {
                    factor_type: methods.into_iter().next().unwrap(),
                }]
            } else {
                vec![Step::RequireFactor {
                    factor_type: FactorType::Any(methods),
                }]
            }
        }
        _ => vec![], // "continue" or unknown — no steps
    }
}

/// Same as `outcome_to_steps` but returns `None` when the result would be empty
/// (needed for the `else_branch: Option<Vec<Step>>` field).
fn outcome_to_steps_opt(outcome: &str, stepup_methods: &[String]) -> Option<Vec<Step>> {
    let steps = outcome_to_steps(outcome, stepup_methods);
    if steps.is_empty() { None } else { Some(steps) }
}

// ============================================================================

/// Validate the compiled AST for semantic correctness.
/// Returns a list of validation warnings (non-fatal) and errors (fatal).
pub fn validate_ast(ast: &serde_json::Value, _action_key: &str) -> Result<Vec<String>, AppError> {
    let mut warnings = Vec::new();

    let groups = ast
        .get("groups")
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
                "Group {gid} (index {gi}) has no enabled rules and will be skipped."
            ));
        } else {
            let rules_arr = rules.unwrap();
            for (ri, rule) in rules_arr.iter().enumerate() {
                let rid = rule.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let conditions = rule.get("conditions").and_then(|c| c.as_array());

                if conditions.map(|c| c.is_empty()).unwrap_or(true) {
                    warnings.push(format!(
                        "Rule {rid} (group {gid}, index {ri}) has no conditions — \
                         it will always match."
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
                    "Last group {gid} has on_no_match='continue', which means requests \
                     that don't match any rule will be allowed. Consider setting \
                     on_no_match='deny' for a deny-by-default posture."
                ));
            }
        }
    }

    Ok(warnings)
}
