-- Rollback migration 043: Policy Builder Compilation Speed Optimization
-- Drops materialized view, triggers, and helper functions.

-- Drop triggers first
DROP TRIGGER IF EXISTS trigger_condition_refresh ON policy_builder_conditions;
DROP TRIGGER IF EXISTS trigger_rule_refresh ON policy_builder_rules;
DROP TRIGGER IF EXISTS trigger_group_refresh ON policy_builder_rule_groups;
DROP TRIGGER IF EXISTS trigger_config_refresh ON policy_builder_configs;

-- Drop functions
DROP FUNCTION IF EXISTS get_policy_config_for_compilation(VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS trigger_refresh_policy_compiled();
DROP FUNCTION IF EXISTS refresh_policy_config_compiled(VARCHAR);

-- Drop materialized view and its indexes
DROP MATERIALIZED VIEW IF EXISTS policy_builder_configs_compiled;
