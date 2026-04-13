//! All request/response types for the Unified Policy Builder API v2.0.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Templates
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemplateItem {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub applicable_actions: Vec<String>,
    pub icon: Option<String>,
    /// JSON Schema for param_values validation (NOT NULL in DB — always present)
    pub param_schema: serde_json::Value,
    /// Default param values (NOT NULL in DB — always present)
    pub param_defaults: serde_json::Value,
    pub supported_conditions: Vec<String>,
    pub owner_tenant_id: Option<String>,
    pub is_deprecated: bool,
    pub deprecated_reason: Option<String>,
    pub migration_guide: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTemplateRequest {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub applicable_actions: Option<Vec<String>>,
    pub icon: Option<String>,
    pub param_schema: Option<serde_json::Value>,
    pub param_defaults: Option<serde_json::Value>,
    pub supported_conditions: Option<Vec<String>>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTemplateRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub applicable_actions: Option<Vec<String>>,
    pub icon: Option<String>,
    pub param_schema: Option<serde_json::Value>,
    pub param_defaults: Option<serde_json::Value>,
    pub supported_conditions: Option<Vec<String>>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct DeprecateTemplateRequest {
    pub reason: String,
    pub migration_guide: Option<String>,
}

// ============================================================================
// Condition type catalog
// ============================================================================

/// Metadata for a single condition type — used by the UI condition picker.
/// Returned by GET /templates/:slug/conditions and GET /condition-types.
#[derive(Debug, Serialize)]
pub struct ConditionTypeItem {
    pub condition_type: String,
    pub display_name: String,
    pub description: String,
    pub params_schema: serde_json::Value,
}

// ============================================================================
// Actions
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ActionItem {
    pub id: String,
    pub action_key: String,
    pub display_name: String,
    pub description: Option<String>,
    pub category: String,
    pub is_platform: bool,
    pub tenant_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateActionRequest {
    pub action_key: String,
    pub display_name: String,
    pub description: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateActionRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
}

// ============================================================================
// Configs
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ConfigSummary {
    pub id: String,
    pub tenant_id: String,
    pub action_key: String,
    pub display_name: Option<String>,
    pub state: String,
    pub draft_version: i32,
    pub active_version: Option<i32>,
    pub group_count: i64,
    pub rule_count: i64,
    pub activated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ConfigDetail {
    pub id: String,
    pub tenant_id: String,
    pub action_key: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub state: String,
    pub draft_version: i32,
    pub active_version: Option<i32>,
    pub active_capsule_hash_b64: Option<String>,
    pub groups: Vec<GroupDetail>,
    pub activated_at: Option<DateTime<Utc>>,
    pub activated_by: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateConfigRequest {
    pub action_key: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
}

// ============================================================================
// Rule Groups
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupDetail {
    pub id: String,
    pub config_id: String,
    pub sort_order: i32,
    pub display_name: String,
    pub description: Option<String>,
    pub match_mode: String, // 'all' | 'any'
    pub on_match: String,   // 'continue' | 'deny' | 'stepup' | 'allow'
    pub on_no_match: String,
    pub stepup_methods: Vec<String>,
    pub is_enabled: bool,
    pub rules: Vec<RuleDetail>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Used by compiler/simulate for group-level summaries
#[derive(Debug, Serialize, Clone)]
pub struct GroupSummary {
    pub group_id: String,
    pub display_name: String,
    pub match_mode: String,
    pub on_match: String,
    pub on_no_match: String,
    pub rule_count: usize,
    pub rules: Vec<RuleSummary>,
}

/// Used by compiler for rule-level summaries
#[derive(Debug, Serialize, Clone)]
pub struct RuleSummary {
    pub rule_id: String,
    pub template_slug: String,
    pub display_name: String,
    pub condition_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct AddGroupRequest {
    pub display_name: String,
    pub description: Option<String>,
    pub match_mode: String,          // required: 'all' | 'any'
    pub on_match: String,            // required: 'continue' | 'deny' | 'stepup' | 'allow'
    pub on_no_match: String,         // required
    pub stepup_methods: Vec<String>, // required (may be empty)
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub match_mode: Option<String>,
    pub on_match: Option<String>,
    pub on_no_match: Option<String>,
    pub stepup_methods: Option<Vec<String>>,
    pub is_enabled: Option<bool>,
}

/// Generic reorder request — `order` is the full ordered list of IDs
#[derive(Debug, Deserialize)]
pub struct ReorderRequest {
    pub order: Vec<String>,
}

// ============================================================================
// Rules
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleDetail {
    pub id: String,
    pub group_id: String,
    pub template_slug: String,
    pub display_name: String,
    pub param_values: Option<serde_json::Value>,
    pub is_enabled: bool,
    pub sort_order: i32,
    pub conditions: Vec<ConditionDetail>,
    pub template: TemplateItem,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub template_slug: String,
    pub display_name: String,
    pub param_values: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub display_name: Option<String>,
    pub param_values: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
}

// ============================================================================
// Conditions
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConditionDetail {
    pub id: String,
    pub rule_id: String,
    pub condition_type: String,
    pub condition_params: Option<serde_json::Value>,
    pub next_operator: Option<String>, // 'and' | 'or' | null (last condition)
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AddConditionRequest {
    pub condition_type: String,
    pub condition_params: Option<serde_json::Value>,
    pub next_operator: Option<String>, // default: 'and'
}

#[derive(Debug, Deserialize)]
pub struct UpdateConditionRequest {
    pub condition_type: Option<String>,
    pub condition_params: Option<serde_json::Value>,
    pub next_operator: Option<String>,
    pub sort_order: Option<i32>,
}

// ============================================================================
// Compile / Preview / Simulate / Activate
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub config_id: String,
    pub action_key: String,
    pub ast: serde_json::Value,
    pub group_count: usize,
    pub rule_count: usize,
    pub warnings: Vec<String>,
    pub groups: Vec<GroupSummary>,
}

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    pub context: TestContext,
}

/// Synthetic test context for simulation.
/// All fields are optional — omitted fields are treated as "unknown" / default.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TestContext {
    pub risk_score: Option<f64>,
    pub country_code: Option<String>,
    pub is_new_device: Option<bool>,
    pub email_verified: Option<bool>,
    pub vpn_detected: Option<bool>,
    pub tor_detected: Option<bool>,
    pub aal_level: Option<u8>,
    pub current_hour: Option<u8>,
    pub impossible_travel: Option<bool>,
    pub user_roles: Option<Vec<String>>,
    pub ip_address: Option<String>,
    pub custom_claims: Option<HashMap<String, String>>,
    pub password_breach_count: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SimulateResponse {
    pub config_id: String,
    pub action_key: String,
    pub decision: String, // 'allow' | 'deny' | 'stepup'
    pub groups_evaluated: Vec<GroupEvalResult>,
    pub human_explanation: Vec<String>,
    pub test_context: TestContext,
}

/// Per-group evaluation result for simulation trace
#[derive(Debug, Serialize)]
pub struct GroupEvalResult {
    pub group_id: String,
    pub display_name: String,
    pub matched: bool,
    pub outcome: String,
    pub rules: Vec<RuleEvalResult>,
}

/// Per-rule evaluation result for simulation trace
#[derive(Debug, Serialize)]
pub struct RuleEvalResult {
    pub rule_id: String,
    pub display_name: String,
    pub matched: bool,
}

#[derive(Debug, Serialize)]
pub struct CompileResponse {
    pub config_id: String,
    pub version_id: String,
    pub version_number: i32,
    pub ast_hash_b64: String,
    pub group_count: usize,
    pub rule_count: usize,
    pub warnings: Vec<String>,
    pub compiled_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ImportAstRequest {
    pub ast: serde_json::Value,
}

// ============================================================================
// Versions
// ============================================================================

#[derive(Debug, Serialize)]
pub struct VersionSummary {
    pub id: String,
    pub config_id: String,
    pub version_number: i32,
    /// SHA-256 of canonical AST JSON, base64-encoded. Nullable in DB.
    pub ast_hash_b64: Option<String>,
    /// User ID who compiled this version. Nullable in DB.
    pub compiled_by: Option<String>,
    pub source: String, // 'builder' | 'ast_import' | 'rollback'
    pub is_active: bool,
    /// When this version was compiled. Nullable in DB (DEFAULT NOW()).
    pub compiled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct VersionDetail {
    pub id: String,
    pub config_id: String,
    pub version_number: i32,
    pub rule_snapshot: serde_json::Value,
    pub ast_snapshot: serde_json::Value,
    pub ast_hash_b64: Option<String>,
    pub compiled_by: Option<String>,
    pub source: String,
    pub is_active: bool,
    pub compiled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct DiffRequest {
    /// ID of the version to compare against (optional; defaults to previous version)
    pub compare_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiffResponse {
    pub from_version_id: String,
    pub from_version_number: i32,
    pub from_hash: Option<String>,
    pub from_compiled_at: Option<DateTime<Utc>>,
    pub to_version_id: String,
    pub to_version_number: i32,
    pub to_hash: Option<String>,
    pub to_compiled_at: Option<DateTime<Utc>>,
    pub changes_count: usize,
    pub changes: Vec<DiffChange>,
}

#[derive(Debug, Serialize)]
pub struct DiffChange {
    pub change_type: String,
    pub path: String,
    pub description: String,
    pub from_value: Option<serde_json::Value>,
    pub to_value: Option<serde_json::Value>,
}

// ============================================================================
// Audit
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub tenant_id: String,
    pub config_id: Option<String>,
    pub action_key: Option<String>,
    pub event_type: String,
    pub actor_id: String,
    pub actor_ip: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub limit: Option<u32>,
    pub before: Option<String>,     // cursor: last seen id
    pub action_key: Option<String>, // filter by action
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    pub items: Vec<AuditEntry>,
    pub next_cursor: Option<String>,
    pub limit: u32,
}
