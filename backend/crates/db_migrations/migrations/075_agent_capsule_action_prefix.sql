-- Migration 075: Agent capsule action prefix index (Sprint B.4)
--
-- `eiaa_capsules` already stores capsules keyed by (tenant_id, action).
-- Sprint B.4 introduces agent-specific capsule keys by prefixing the action
-- string with "agent:" (e.g. "agent:billing:read"). The existing composite
-- index on (tenant_id, action) covers these rows, but a partial index on
-- agent-prefixed actions allows the DB to quickly answer "does an agent
-- capsule exist for this tenant?" without scanning human capsule rows.
--
-- This migration is additive: no data is changed and the index is created
-- CONCURRENTLY to avoid locking the table during deployment.

CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_agent_action
    ON eiaa_capsules(tenant_id, action)
    WHERE action LIKE 'agent:%';

COMMENT ON INDEX idx_eiaa_capsules_agent_action IS
    'Sprint B.4 — fast lookup for agent-prefixed capsule dispatch keys (agent:<action>)';
