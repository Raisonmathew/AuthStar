/**
 * TypeScript types for the Unified Policy Builder API v2.0.
 * Mirrors backend/crates/api_server/src/routes/policy_builder/types.rs
 */

// ============================================================================
// Templates
// ============================================================================

export interface TemplateItem {
  slug: string;
  display_name: string;
  description: string;
  category: string;
  applicable_actions: string[];
  icon: string | null;
  param_schema: Record<string, any>;
  param_defaults: Record<string, any>;
  supported_conditions: string[];
  owner_tenant_id: string | null;
  is_deprecated: boolean;
  deprecated_reason: string | null;
  migration_guide: string | null;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface CreateTemplateRequest {
  slug: string;
  display_name: string;
  description: string;
  category: string;
  applicable_actions?: string[];
  icon?: string;
  param_schema?: Record<string, any>;
  param_defaults?: Record<string, any>;
  supported_conditions?: string[];
  sort_order?: number;
}

// ============================================================================
// Condition Types
// ============================================================================

export interface ConditionTypeItem {
  condition_type: string;
  display_name: string;
  description: string;
  params_schema: Record<string, any>;
}

// ============================================================================
// Actions
// ============================================================================

export interface ActionItem {
  id: string;
  action_key: string;
  display_name: string;
  description: string | null;
  category: string;
  is_platform: boolean;
  tenant_id: string | null;
  created_at: string;
}

export interface CreateActionRequest {
  action_key: string;
  display_name: string;
  description?: string;
  category?: string;
}

// ============================================================================
// Configs
// ============================================================================

export interface ConfigSummary {
  id: string;
  tenant_id: string;
  action_key: string;
  display_name: string | null;
  state: 'draft' | 'compiled' | 'active' | 'archived';
  draft_version: number;
  active_version: number | null;
  group_count: number;
  rule_count: number;
  activated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConfigDetail {
  id: string;
  tenant_id: string;
  action_key: string;
  display_name: string | null;
  description: string | null;
  state: 'draft' | 'compiled' | 'active' | 'archived';
  draft_version: number;
  active_version: number | null;
  active_capsule_hash_b64: string | null;
  groups: GroupDetail[];
  activated_at: string | null;
  activated_by: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CreateConfigRequest {
  action_key: string;
  display_name?: string;
  description?: string;
}

export interface UpdateConfigRequest {
  display_name?: string;
  description?: string;
}

// ============================================================================
// Rule Groups
// ============================================================================

export type MatchMode = 'all' | 'any';
export type OnMatch = 'continue' | 'deny' | 'stepup' | 'allow';

export interface GroupDetail {
  id: string;
  config_id: string;
  sort_order: number;
  display_name: string;
  description: string | null;
  match_mode: MatchMode;
  on_match: OnMatch;
  on_no_match: OnMatch;
  stepup_methods: string[];
  is_enabled: boolean;
  rules: RuleDetail[];
  created_at: string;
  updated_at: string;
}

export interface AddGroupRequest {
  display_name: string;
  description?: string;
  match_mode: MatchMode;
  on_match: OnMatch;
  on_no_match: OnMatch;
  stepup_methods: string[];
}

export interface UpdateGroupRequest {
  display_name?: string;
  description?: string;
  match_mode?: MatchMode;
  on_match?: OnMatch;
  on_no_match?: OnMatch;
  stepup_methods?: string[];
  is_enabled?: boolean;
}

export interface ReorderRequest {
  order: string[];
}

// ============================================================================
// Rules
// ============================================================================

export interface RuleDetail {
  id: string;
  group_id: string;
  template_slug: string;
  display_name: string;
  param_values: Record<string, any> | null;
  is_enabled: boolean;
  sort_order: number;
  conditions: ConditionDetail[];
  template: TemplateItem;
  created_at: string;
  updated_at: string;
}

export interface AddRuleRequest {
  template_slug: string;
  display_name: string;
  param_values?: Record<string, any>;
}

export interface UpdateRuleRequest {
  display_name?: string;
  param_values?: Record<string, any>;
  is_enabled?: boolean;
}

// ============================================================================
// Conditions
// ============================================================================

export type NextOperator = 'and' | 'or';

export interface ConditionDetail {
  id: string;
  rule_id: string;
  condition_type: string;
  condition_params: Record<string, any> | null;
  next_operator: NextOperator | null;
  sort_order: number;
  created_at: string;
}

export interface AddConditionRequest {
  condition_type: string;
  condition_params?: Record<string, any>;
  next_operator?: NextOperator;
}

export interface UpdateConditionRequest {
  condition_type?: string;
  condition_params?: Record<string, any>;
  next_operator?: NextOperator | null;
  sort_order?: number;
}

// ============================================================================
// Compile / Preview / Simulate / Activate
// ============================================================================

export interface PreviewResponse {
  config_id: string;
  action_key: string;
  ast: Record<string, any>;
  group_count: number;
  rule_count: number;
  warnings: string[];
  groups: GroupSummary[];
}

export interface GroupSummary {
  group_id: string;
  display_name: string;
  match_mode: string;
  on_match: string;
  on_no_match: string;
  rule_count: number;
  rules: RuleSummary[];
}

export interface RuleSummary {
  rule_id: string;
  template_slug: string;
  display_name: string;
  condition_count: number;
}

export interface TestContext {
  risk_score?: number;
  country_code?: string;
  is_new_device?: boolean;
  email_verified?: boolean;
  vpn_detected?: boolean;
  tor_detected?: boolean;
  aal_level?: number;
  current_hour?: number;
  impossible_travel?: boolean;
  user_roles?: string[];
  ip_address?: string;
  custom_claims?: Record<string, string>;
}

export interface SimulateRequest {
  context: TestContext;
}

export interface SimulateResponse {
  config_id: string;
  action_key: string;
  decision: 'allow' | 'deny' | 'stepup';
  groups_evaluated: GroupEvalResult[];
  human_explanation: string[];
  test_context: TestContext;
}

export interface GroupEvalResult {
  group_id: string;
  display_name: string;
  matched: boolean;
  outcome: string;
  rules: RuleEvalResult[];
}

export interface RuleEvalResult {
  rule_id: string;
  display_name: string;
  matched: boolean;
}

export interface CompileResponse {
  config_id: string;
  version_id: string;
  version_number: number;
  ast_hash_b64: string;
  group_count: number;
  rule_count: number;
  warnings: string[];
  compiled_at: string;
}

// ============================================================================
// Versions
// ============================================================================

export interface VersionSummary {
  id: string;
  config_id: string;
  version_number: number;
  ast_hash_b64: string | null;
  compiled_by: string | null;
  source: 'builder' | 'ast_import' | 'rollback';
  is_active: boolean;
  compiled_at: string | null;
}

export interface VersionDetail {
  id: string;
  config_id: string;
  version_number: number;
  rule_snapshot: Record<string, any>;
  ast_snapshot: Record<string, any>;
  ast_hash_b64: string | null;
  compiled_by: string | null;
  source: string;
  is_active: boolean;
  compiled_at: string | null;
}

export interface DiffChange {
  change_type: string;
  path: string;
  description: string;
  from_value: any;
  to_value: any;
}

export interface DiffResponse {
  from_version_id: string;
  from_version_number: number;
  from_hash: string | null;
  from_compiled_at: string | null;
  to_version_id: string;
  to_version_number: number;
  to_hash: string | null;
  to_compiled_at: string | null;
  changes_count: number;
  changes: DiffChange[];
}

// ============================================================================
// Audit
// ============================================================================

export interface AuditEntry {
  id: string;
  tenant_id: string;
  config_id: string | null;
  action_key: string | null;
  event_type: string;
  actor_id: string;
  actor_ip: string | null;
  description: string | null;
  metadata: Record<string, any> | null;
  created_at: string;
}

export interface AuditPage {
  items: AuditEntry[];
  next_cursor: string | null;
  limit: number;
}