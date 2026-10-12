-- 068_down.sql — Rollback P0 identity security foundation
-- Drops groups, group_memberships, group_role_bindings, password_policies,
-- credential_lockout_policies (if not already from 057).
DROP TABLE IF EXISTS group_role_bindings CASCADE;
DROP TABLE IF EXISTS group_memberships CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS password_policies CASCADE;
-- credential_lockout_policies may have been added in 057; drop idempotently
DROP TABLE IF EXISTS credential_lockout_policies CASCADE;
