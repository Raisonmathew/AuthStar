//! Condition compiler: converts `ConditionDetail` records into AST condition nodes.
//!
//! Each condition node in the AST has the shape:
//! ```json
//! {
//!   "type":    "risk_above",
//!   "params":  { "threshold": 80 },
//!   "next_op": "and"   // null for the last condition in a rule
//! }
//! ```
//!
//! The `next_op` field tells the runtime evaluator how to combine this
//! condition's result with the next one:
//!   - `"and"` → both must be true
//!   - `"or"`  → either may be true
//!   - `null`  → last condition (no chaining)
//!
//! # Evaluation semantics
//!
//! The runtime evaluates conditions left-to-right using short-circuit logic:
//!
//! ```text
//! result = eval(cond[0])
//! for i in 1..n:
//!     if cond[i-1].next_op == "and":
//!         result = result AND eval(cond[i])
//!     else:  // "or"
//!         result = result OR eval(cond[i])
//! ```
//!
//! This is equivalent to a flat boolean expression without parentheses.
//! For grouped sub-expressions, use multiple rule groups.

use super::super::types::ConditionDetail;
use shared_types::AppError;

/// Compile a slice of `ConditionDetail` into the AST condition array.
pub fn compile_conditions(
    conditions: &[ConditionDetail],
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut ast_conditions = Vec::with_capacity(conditions.len());

    for (i, cond) in conditions.iter().enumerate() {
        let is_last = i == conditions.len() - 1;

        // next_op is null for the last condition
        let next_op: serde_json::Value = if is_last {
            serde_json::Value::Null
        } else {
            cond.next_operator
                .as_deref()
                .map(|op| serde_json::Value::String(op.to_string()))
                .unwrap_or(serde_json::Value::String("and".to_string()))
        };

        let params = cond
            .condition_params
            .clone()
            .unwrap_or(serde_json::json!({}));

        // Validate and normalise params per condition type
        let normalised_params = normalise_condition_params(&cond.condition_type, params)?;

        ast_conditions.push(serde_json::json!({
            "type":    cond.condition_type,
            "params":  normalised_params,
            "next_op": next_op,
        }));
    }

    Ok(ast_conditions)
}

/// Normalise and validate condition params at compile time.
/// This is a second-pass validation (first pass is at write time in conditions.rs).
/// Returns the normalised params or an error with a human-readable message.
fn normalise_condition_params(
    condition_type: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, AppError> {
    match condition_type {
        "risk_above" | "risk_below" => {
            let threshold = params
                .get("threshold")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| {
                    AppError::BadRequest(format!(
                        "Condition '{condition_type}': 'threshold' must be a number"
                    ))
                })?;

            if !(0.0..=100.0).contains(&threshold) {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': threshold must be between 0 and 100, got {threshold}"
                )));
            }

            Ok(serde_json::json!({ "threshold": threshold }))
        }

        "country_in" | "country_not_in" => {
            let countries = params
                .get("countries")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    AppError::BadRequest(format!(
                        "Condition '{condition_type}': 'countries' must be an array"
                    ))
                })?;

            if countries.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': 'countries' must not be empty"
                )));
            }

            // Normalise to uppercase ISO-3166 codes
            let normalised: Vec<String> = countries
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_uppercase())
                .collect();

            if normalised.len() != countries.len() {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': all country codes must be strings"
                )));
            }

            Ok(serde_json::json!({ "countries": normalised }))
        }

        "new_device" | "email_not_verified" | "vpn_detected" | "tor_detected" => {
            // No params needed
            Ok(serde_json::json!({}))
        }

        "aal_below" => {
            let level = params
                .get("level")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    AppError::BadRequest("Condition 'aal_below': 'level' must be an integer".into())
                })?;

            if !(1..=3).contains(&level) {
                return Err(AppError::BadRequest(format!(
                    "Condition 'aal_below': level must be 1, 2, or 3, got {level}"
                )));
            }

            Ok(serde_json::json!({ "level": level }))
        }

        "outside_time_window" => {
            let start = params
                .get("start_hour")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'outside_time_window': 'start_hour' must be an integer".into(),
                    )
                })?;

            let end = params
                .get("end_hour")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'outside_time_window': 'end_hour' must be an integer".into(),
                    )
                })?;

            let tz = params
                .get("timezone")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'outside_time_window': 'timezone' must be a string".into(),
                    )
                })?;

            if !(0..=23).contains(&start) || !(0..=23).contains(&end) {
                return Err(AppError::BadRequest(
                    "Condition 'outside_time_window': start_hour and end_hour must be 0–23".into(),
                ));
            }

            if tz.is_empty() {
                return Err(AppError::BadRequest(
                    "Condition 'outside_time_window': timezone must not be empty".into(),
                ));
            }

            Ok(serde_json::json!({
                "start_hour": start,
                "end_hour":   end,
                "timezone":   tz,
            }))
        }

        "impossible_travel" => {
            let speed = params
                .get("max_speed_kmh")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'impossible_travel': 'max_speed_kmh' must be a number".into(),
                    )
                })?;

            if speed <= 0.0 {
                return Err(AppError::BadRequest(
                    "Condition 'impossible_travel': max_speed_kmh must be > 0".into(),
                ));
            }

            Ok(serde_json::json!({ "max_speed_kmh": speed }))
        }

        "role_in" | "role_not_in" => {
            let roles = params
                .get("roles")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    AppError::BadRequest(format!(
                        "Condition '{condition_type}': 'roles' must be an array"
                    ))
                })?;

            if roles.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': 'roles' must not be empty"
                )));
            }

            let role_strs: Vec<String> = roles
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_lowercase())
                .collect();

            if role_strs.len() != roles.len() {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': all role values must be strings"
                )));
            }

            Ok(serde_json::json!({ "roles": role_strs }))
        }

        "ip_in_range" | "ip_not_in_range" => {
            let cidr = params.get("cidr").and_then(|v| v.as_str()).ok_or_else(|| {
                AppError::BadRequest(format!(
                    "Condition '{condition_type}': 'cidr' must be a string"
                ))
            })?;

            // Basic CIDR format validation (contains '/')
            if !cidr.contains('/') {
                return Err(AppError::BadRequest(format!(
                    "Condition '{condition_type}': 'cidr' must be in CIDR notation (e.g. '10.0.0.0/8'), got '{cidr}'"
                )));
            }

            Ok(serde_json::json!({ "cidr": cidr }))
        }

        "custom_claim" => {
            let key = params
                .get("claim_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'custom_claim': 'claim_key' must be a string".into(),
                    )
                })?;

            let value = params
                .get("claim_value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Condition 'custom_claim': 'claim_value' must be a string".into(),
                    )
                })?;

            if key.is_empty() {
                return Err(AppError::BadRequest(
                    "Condition 'custom_claim': 'claim_key' must not be empty".into(),
                ));
            }

            Ok(serde_json::json!({
                "claim_key":   key,
                "claim_value": value,
            }))
        }

        unknown => {
            // Unknown condition types are rejected at compile time
            Err(AppError::BadRequest(format!(
                "Unknown condition type '{unknown}' encountered during compilation. \
                 This condition was accepted at write time but is no longer valid. \
                 Please remove or update it."
            )))
        }
    }
}

// ============================================================================
// Simulation evaluator
// ============================================================================

/// Evaluate a compiled condition array against a test context.
/// Returns `true` if the condition chain matches.
pub fn evaluate_conditions(conditions: &[serde_json::Value], ctx: &SimulationContext) -> bool {
    if conditions.is_empty() {
        // No conditions → rule always matches
        return true;
    }

    let mut result = evaluate_single_condition(&conditions[0], ctx);

    for i in 1..conditions.len() {
        let prev_op = conditions[i - 1]
            .get("next_op")
            .and_then(|v| v.as_str())
            .unwrap_or("and");

        let next_result = evaluate_single_condition(&conditions[i], ctx);

        result = if prev_op == "or" {
            result || next_result
        } else {
            result && next_result
        };
    }

    result
}

/// Evaluate a single condition node against the simulation context.
fn evaluate_single_condition(condition: &serde_json::Value, ctx: &SimulationContext) -> bool {
    let ct = match condition.get("type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return false,
    };
    let params = condition
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    match ct {
        "risk_above" => {
            let threshold = params
                .get("threshold")
                .and_then(|v| v.as_f64())
                .unwrap_or(100.0);
            ctx.risk_score.unwrap_or(0.0) > threshold
        }
        "risk_below" => {
            let threshold = params
                .get("threshold")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            ctx.risk_score.unwrap_or(0.0) < threshold
        }
        "country_in" => {
            let countries: Vec<String> = params
                .get("countries")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
                        .collect()
                })
                .unwrap_or_default();
            ctx.country_code
                .as_ref()
                .map(|c| countries.contains(&c.to_uppercase()))
                .unwrap_or(false)
        }
        "country_not_in" => {
            let countries: Vec<String> = params
                .get("countries")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
                        .collect()
                })
                .unwrap_or_default();
            ctx.country_code
                .as_ref()
                .map(|c| !countries.contains(&c.to_uppercase()))
                .unwrap_or(true)
        }
        "new_device" => ctx.is_new_device.unwrap_or(false),
        "email_not_verified" => !ctx.email_verified.unwrap_or(true),
        "vpn_detected" => ctx.vpn_detected.unwrap_or(false),
        "tor_detected" => ctx.tor_detected.unwrap_or(false),
        "aal_below" => {
            let required = params.get("level").and_then(|v| v.as_i64()).unwrap_or(1);
            (ctx.aal_level.unwrap_or(1) as i64) < required
        }
        "outside_time_window" => {
            // Simplified: compare against ctx.current_hour if provided
            let start = params
                .get("start_hour")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let end = params
                .get("end_hour")
                .and_then(|v| v.as_i64())
                .unwrap_or(23);
            if let Some(hour) = ctx.current_hour {
                let h = hour as i64;
                if start <= end {
                    !(start <= h && h <= end)
                } else {
                    // Wraps midnight: allowed window is [start..23] ∪ [0..end]
                    !(h >= start || h <= end)
                }
            } else {
                false // can't evaluate without time context
            }
        }
        "impossible_travel" => ctx.impossible_travel.unwrap_or(false),
        "role_in" => {
            let roles: Vec<String> = params
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default();
            ctx.user_roles
                .iter()
                .any(|r| roles.contains(&r.to_lowercase()))
        }
        "role_not_in" => {
            let roles: Vec<String> = params
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default();
            !ctx.user_roles
                .iter()
                .any(|r| roles.contains(&r.to_lowercase()))
        }
        "ip_in_range" => {
            // Simplified: exact prefix match for simulation purposes
            let cidr = params.get("cidr").and_then(|v| v.as_str()).unwrap_or("");
            ctx.ip_address
                .as_ref()
                .map(|ip| ip_in_cidr(ip, cidr))
                .unwrap_or(false)
        }
        "ip_not_in_range" => {
            let cidr = params.get("cidr").and_then(|v| v.as_str()).unwrap_or("");
            ctx.ip_address
                .as_ref()
                .map(|ip| !ip_in_cidr(ip, cidr))
                .unwrap_or(true)
        }
        "custom_claim" => {
            let key = params
                .get("claim_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let value = params
                .get("claim_value")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            ctx.custom_claims
                .get(key)
                .map(|v| v == value)
                .unwrap_or(false)
        }
        _ => false,
    }
}

/// Simulation context — all fields optional so callers can provide partial contexts.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize, Clone)]
pub struct SimulationContext {
    pub risk_score: Option<f64>,
    pub country_code: Option<String>,
    pub is_new_device: Option<bool>,
    pub email_verified: Option<bool>,
    pub vpn_detected: Option<bool>,
    pub tor_detected: Option<bool>,
    pub aal_level: Option<u8>,
    pub current_hour: Option<u8>,
    pub impossible_travel: Option<bool>,
    pub user_roles: Vec<String>,
    pub ip_address: Option<String>,
    pub custom_claims: std::collections::HashMap<String, String>,
}

/// Very simplified CIDR check for simulation (IPv4 only, /prefix notation).
/// Production runtime uses a proper IP library; this is good enough for dry-run.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let network_ip = parts[0];

    let ip_u32 = ipv4_to_u32(ip);
    let net_u32 = ipv4_to_u32(network_ip);

    match (ip_u32, net_u32) {
        (Some(i), Some(n)) => {
            if prefix_len == 0 {
                return true;
            }
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            (i & mask) == (n & mask)
        }
        _ => false,
    }
}

fn ipv4_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    Some(
        ((parts[0] as u32) << 24)
            | ((parts[1] as u32) << 16)
            | ((parts[2] as u32) << 8)
            | (parts[3] as u32),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidr() {
        assert!(ip_in_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(!ip_in_cidr("192.168.2.1", "192.168.1.0/24"));
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1", "10.0.0.0/8"));
        assert!(ip_in_cidr("1.2.3.4", "0.0.0.0/0")); // match all
    }

    #[test]
    fn test_evaluate_risk_above() {
        let conditions = vec![serde_json::json!({
            "type": "risk_above",
            "params": { "threshold": 70.0 },
            "next_op": null
        })];
        let ctx = SimulationContext {
            risk_score: Some(85.0),
            ..Default::default()
        };
        assert!(evaluate_conditions(&conditions, &ctx));

        let ctx_low = SimulationContext {
            risk_score: Some(50.0),
            ..Default::default()
        };
        assert!(!evaluate_conditions(&conditions, &ctx_low));
    }

    #[test]
    fn test_evaluate_and_chain() {
        let conditions = vec![
            serde_json::json!({ "type": "risk_above", "params": { "threshold": 70.0 }, "next_op": "and" }),
            serde_json::json!({ "type": "new_device", "params": {}, "next_op": null }),
        ];
        let ctx = SimulationContext {
            risk_score: Some(85.0),
            is_new_device: Some(true),
            ..Default::default()
        };
        assert!(evaluate_conditions(&conditions, &ctx));

        let ctx_no_new = SimulationContext {
            risk_score: Some(85.0),
            is_new_device: Some(false),
            ..Default::default()
        };
        assert!(!evaluate_conditions(&conditions, &ctx_no_new));
    }

    #[test]
    fn test_evaluate_or_chain() {
        let conditions = vec![
            serde_json::json!({ "type": "vpn_detected", "params": {}, "next_op": "or" }),
            serde_json::json!({ "type": "tor_detected", "params": {}, "next_op": null }),
        ];
        let ctx_vpn = SimulationContext {
            vpn_detected: Some(true),
            ..Default::default()
        };
        assert!(evaluate_conditions(&conditions, &ctx_vpn));

        let ctx_tor = SimulationContext {
            tor_detected: Some(true),
            ..Default::default()
        };
        assert!(evaluate_conditions(&conditions, &ctx_tor));

        let ctx_none = SimulationContext::default();
        assert!(!evaluate_conditions(&conditions, &ctx_none));
    }
}
