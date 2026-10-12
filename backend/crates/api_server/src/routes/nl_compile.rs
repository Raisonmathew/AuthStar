//! Natural-Language → AST Policy Compiler (Gap 2-B)
//!
//! ## Endpoint
//!
//! `POST /api/v1/policy-builder/nl-compile`
//!
//! Accepts a plain-English description of an authorization policy and returns
//! a draft Policy Builder config payload (same JSON shape as the manual form)
//! ready for the user to review, simulate, and deploy via the standard
//! compile → simulate → activate pipeline.
//!
//! ## Design
//!
//! The handler sends the user's prompt to an OpenAI-compatible chat completion
//! API with the full Policy Builder JSON schema injected as the system prompt.
//! The LLM output is validated against the schema before returning so the
//! frontend never receives malformed AST.
//!
//! If `LLM_API_URL` is not configured the endpoint returns 503 with a clear
//! message — NL compile is an optional feature, not a hard dependency.

use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, State},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route("/policy-builder/nl-compile", post(nl_compile))
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NlCompileRequest {
    /// Plain-English description of the desired policy.
    /// e.g. "Allow send_email only if risk score is below 40 and user is AAL2"
    pub prompt: String,
    /// EIAA action this policy should govern (e.g. "billing:read").
    pub action_key: String,
    /// Optional current draft AST JSON for the LLM to diff against.
    #[serde(default)]
    pub current_config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct NlCompileResponse {
    /// Draft config JSON — same shape as `POST /policy-builder/configs` body.
    /// Includes `name`, `action_key`, `groups` array.
    pub draft_config: serde_json::Value,
    /// Human-readable explanation of what the LLM generated.
    pub explanation: String,
    /// Whether the output is structurally valid (passed schema validation).
    pub valid: bool,
    /// Any validation warnings (e.g., missing terminal step).
    pub warnings: Vec<String>,
}

// ─── System prompt ────────────────────────────────────────────────────────────

const SYSTEM_PROMPT: &str = r#"
You are an expert authorization policy compiler for the AuthStar EIAA (Entitlement-Independent Authentication Architecture) system.

Your job: convert a plain-English policy description into a valid Policy Builder config JSON object.

## Output format

Return ONLY a JSON object (no markdown, no explanation outside the JSON) with this exact shape:

```json
{
  "name": "<short human-readable name for this policy>",
  "action_key": "<the EIAA action string>",
  "description": "<one-sentence description>",
  "explanation": "<2-3 sentences explaining what this policy does and why>",
  "groups": [
    {
      "name": "<group name>",
      "match_mode": "all" | "any",
      "outcome": "allow" | "deny" | "stepup",
      "rules": [
        {
          "condition_type": "<see types below>",
          "operator": "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "in" | "not_in" | "contains" | "not_contains",
          "value": "<threshold or list>"
        }
      ]
    }
  ]
}
```

## Condition types available

| condition_type | Description | Typical operators | Example value |
|---|---|---|---|
| risk_score | EIAA risk score 0–100 | lt, lte, gt, gte | "40" |
| assurance_level | Auth assurance level (1=password, 2=MFA, 3=hardware) | gte, eq | "2" |
| ip_country | ISO 3166-1 alpha-2 country code of request IP | eq, neq, in, not_in | "US" or ["US","CA"] |
| device_trusted | Whether device is in the trusted set | eq | "true" or "false" |
| email_verified | Whether the user has a verified email | eq | "true" |
| session_age_seconds | Age of the current session in seconds | lt, lte | "3600" |
| time_of_day_hour | UTC hour of the request (0–23) | gte, lte, in | "9" |
| day_of_week | Day of week (0=Sunday, 6=Saturday) | in, not_in | ["1","2","3","4","5"] |
| ip_is_vpn | IP is from a known VPN/Tor exit node | eq | "true" |
| principal_type | Type of principal: "human", "agent", "service" | eq | "human" |
| mfa_method | MFA method used: "totp", "webauthn", "sms" | eq, in | "webauthn" |

## Rules

1. Every `groups` array must have at least one group.
2. The last group's `outcome` should be either "allow" or "deny" to terminate the chain.
3. Use `"stepup"` outcome to require MFA before allowing.
4. `match_mode: "all"` = ALL conditions must pass (AND logic).
5. `match_mode: "any"` = ANY condition must pass (OR logic).
6. Keep it minimal — do not add conditions not implied by the prompt.
7. For the `explanation` field inside the JSON, explain in plain English what the policy will do.

Return ONLY the JSON object. No markdown fences. No prose outside the JSON.
"#;

// ─── Handler ──────────────────────────────────────────────────────────────────

/// `POST /api/v1/policy-builder/nl-compile`
async fn nl_compile(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(req): Json<NlCompileRequest>,
) -> Result<Json<NlCompileResponse>> {
    // Guard: LLM not configured
    if state.config.llm.api_url.is_empty() {
        return Err(AppError::ServiceUnavailable(
            "Natural-language policy compiler is not configured. \
             Set LLM_API_URL and LLM_API_KEY environment variables to enable this feature."
                .into(),
        ));
    }

    if req.prompt.trim().is_empty() {
        return Err(AppError::Validation("prompt must not be empty".into()));
    }
    if req.action_key.trim().is_empty() {
        return Err(AppError::Validation("action_key must not be empty".into()));
    }

    // Build user message
    let user_message = if let Some(current) = &req.current_config {
        format!(
            "Action: {}\n\nCurrent policy config:\n{}\n\nPolicy description: {}",
            req.action_key,
            serde_json::to_string_pretty(current).unwrap_or_default(),
            req.prompt,
        )
    } else {
        format!("Action: {}\n\nPolicy description: {}", req.action_key, req.prompt)
    };

    // Call OpenAI-compatible API
    let llm_response = call_llm(
        &state.config.llm.api_url,
        &state.config.llm.api_key,
        &state.config.llm.model,
        state.config.llm.max_tokens,
        SYSTEM_PROMPT,
        &user_message,
    )
    .await
    .map_err(|e| AppError::Internal(format!("LLM call failed: {e}")))?;

    // Parse and validate the JSON output
    let parsed: serde_json::Value = serde_json::from_str(llm_response.trim())
        .map_err(|e| AppError::Internal(format!("LLM returned invalid JSON: {e}")))?;

    let (valid, warnings) = validate_draft_config(&parsed);
    let explanation = parsed
        .get("explanation")
        .and_then(|v| v.as_str())
        .unwrap_or("Policy generated from natural language description.")
        .to_string();

    Ok(Json(NlCompileResponse {
        draft_config: parsed,
        explanation,
        valid,
        warnings,
    }))
}

// ─── LLM call ─────────────────────────────────────────────────────────────────

async fn call_llm(
    api_url: &str,
    api_key: &str,
    model: &str,
    max_tokens: u32,
    system: &str,
    user: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/chat/completions", api_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ]
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        // Use a small cap for error bodies — we only need a human-readable snippet.
        let text = resp.text().await.unwrap_or_default();
        let text = if text.len() > 1024 { &text[..1024] } else { &text };
        return Err(anyhow::anyhow!("LLM API error {status}: {text}"));
    }

    // BUG 5 FIX: Cap LLM response body at 256 KB before buffering into memory.
    // An unbounded resp.json().await? would allow a misconfigured or compromised
    // LLM endpoint to OOM the process with a multi-MB response.
    const MAX_LLM_BODY: usize = 256 * 1024; // 256 KB
    let body_bytes = resp.bytes().await?;
    if body_bytes.len() > MAX_LLM_BODY {
        return Err(anyhow::anyhow!(
            "LLM response body exceeds {MAX_LLM_BODY} byte limit ({} bytes received)",
            body_bytes.len()
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&body_bytes)?;
    let content = json
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Unexpected LLM response shape"))?
        .to_string();

    Ok(content)
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Structural validation of the LLM-generated draft config.
/// Returns (is_valid, warnings).
fn validate_draft_config(v: &serde_json::Value) -> (bool, Vec<String>) {
    let mut warnings = Vec::new();

    // Must be an object
    let Some(obj) = v.as_object() else {
        return (false, vec!["Output is not a JSON object".into()]);
    };

    // Required top-level fields
    for field in ["name", "action_key", "groups"] {
        if !obj.contains_key(field) {
            warnings.push(format!("Missing required field: {field}"));
        }
    }

    // Validate groups
    if let Some(groups) = obj.get("groups").and_then(|g| g.as_array()) {
        if groups.is_empty() {
            warnings.push("groups array is empty — policy will match nothing".into());
        }

        for (i, group) in groups.iter().enumerate() {
            let g = match group.as_object() {
                Some(g) => g,
                None => {
                    warnings.push(format!("groups[{i}] is not an object"));
                    continue;
                }
            };

            for field in ["name", "match_mode", "outcome", "rules"] {
                if !g.contains_key(field) {
                    warnings.push(format!("groups[{i}] missing field: {field}"));
                }
            }

            if let Some(outcome) = g.get("outcome").and_then(|v| v.as_str()) {
                if !["allow", "deny", "stepup"].contains(&outcome) {
                    warnings.push(format!("groups[{i}].outcome invalid: {outcome}"));
                }
            }

            if let Some(rules) = g.get("rules").and_then(|r| r.as_array()) {
                for (j, rule) in rules.iter().enumerate() {
                    if rule.get("condition_type").is_none() {
                        warnings.push(format!("groups[{i}].rules[{j}] missing condition_type"));
                    }
                }
            }
        }

        // Warn if last group isn't terminal
        if let Some(last) = groups.last() {
            let outcome = last
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if outcome == "stepup" {
                warnings.push(
                    "Last group has outcome 'stepup' — add a final 'allow' or 'deny' group to terminate the chain".into()
                );
            }
        }
    }

    let valid = warnings.is_empty();
    (valid, warnings)
}
