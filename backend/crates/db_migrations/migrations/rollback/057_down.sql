-- 057_down.sql — Rollback tier1_auth_completion
-- Drops required_actions, credential_attempt_counters, credential_lockout_policies,
-- auth_flows, auth_flow_executions added by migration 057.
DROP TABLE IF EXISTS auth_flow_executions CASCADE;
DROP TABLE IF EXISTS auth_flows CASCADE;
DROP TABLE IF EXISTS credential_attempt_counters CASCADE;
DROP TABLE IF EXISTS credential_lockout_policies CASCADE;
DROP TABLE IF EXISTS required_actions CASCADE;
