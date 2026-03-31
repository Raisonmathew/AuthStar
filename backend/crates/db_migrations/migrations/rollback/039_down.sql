-- Rollback migration 039: Policy Builder System
-- Drops all policy builder tables and reverts eiaa_policies columns.
-- WARNING: All policy builder data will be permanently lost.

-- Drop RLS policies first
DROP POLICY IF EXISTS builder_audit_tenant_isolation ON policy_builder_audit;
DROP POLICY IF EXISTS builder_rules_tenant_isolation ON policy_builder_rules;
DROP POLICY IF EXISTS builder_configs_tenant_isolation ON policy_builder_configs;
DROP POLICY IF EXISTS policy_actions_tenant_isolation ON policy_actions;

-- Revert eiaa_policies columns added in 039
ALTER TABLE eiaa_policies DROP COLUMN IF EXISTS source;
ALTER TABLE eiaa_policies DROP COLUMN IF EXISTS builder_config_id;

-- Drop tables in dependency order
DROP TABLE IF EXISTS policy_builder_audit CASCADE;
DROP TABLE IF EXISTS policy_builder_rules CASCADE;
DROP TABLE IF EXISTS policy_builder_configs CASCADE;
DROP TABLE IF EXISTS policy_templates CASCADE;
DROP TABLE IF EXISTS policy_actions CASCADE;
