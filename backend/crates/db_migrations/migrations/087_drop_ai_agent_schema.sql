-- Migration 087: Remove AI-agent authorization schema
--
-- AI agent authN/authZ (agent principals, delegations, task grants, blueprints,
-- agent webhooks, task-chain audit) has been removed from the product.
-- Migrations 072-082 are immutable history; this forward-only migration drops
-- the objects they created.
--
-- NOTE: This is destructive. Agent data (principals, tool-call audits,
-- delegations, webhooks, DLQ rows, and the agent_* columns on eiaa_executions /
-- eiaa_capsules) is permanently deleted.

-- ── Tables ────────────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS task_grants        CASCADE;
DROP TABLE IF EXISTS agent_blueprints   CASCADE;
DROP TABLE IF EXISTS webhook_dlq        CASCADE;
DROP TABLE IF EXISTS tenant_webhooks    CASCADE;
DROP TABLE IF EXISTS agent_delegations  CASCADE;
DROP TABLE IF EXISTS tool_call_audits   CASCADE;
DROP TABLE IF EXISTS agent_principals   CASCADE;

-- ── eiaa_capsules: remove agent-scoped capsules, indexes and columns ─────────
DELETE FROM eiaa_capsules WHERE principal_type = 'agent' OR action LIKE 'agent:%';

DROP INDEX IF EXISTS idx_eiaa_capsules_agent_action;
DROP INDEX IF EXISTS idx_eiaa_capsules_agent_identity;
DROP INDEX IF EXISTS idx_eiaa_capsules_resolution;

ALTER TABLE eiaa_capsules
    DROP COLUMN IF EXISTS principal_type,
    DROP COLUMN IF EXISTS agent_id,
    DROP COLUMN IF EXISTS model_id;

-- Migration 077 dropped the unique capsule-hash index (agent capsules could share
-- a hash). Restore it when the remaining data allows; the policy builder's
-- `ON CONFLICT (capsule_hash_b64)` upsert depends on it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM eiaa_capsules
        GROUP BY capsule_hash_b64 HAVING COUNT(*) > 1
    ) THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_eiaa_capsules_hash
            ON eiaa_capsules (capsule_hash_b64);
    ELSE
        RAISE WARNING 'duplicate capsule_hash_b64 rows exist; idx_eiaa_capsules_hash not restored';
    END IF;
END $$;

-- ── eiaa_executions: remove task-chain / agent columns and indexes ───────────
DROP INDEX IF EXISTS idx_eiaa_executions_task_chain;
DROP INDEX IF EXISTS idx_eiaa_executions_agent;
DROP INDEX IF EXISTS idx_eiaa_executions_parent;
DROP INDEX IF EXISTS idx_eiaa_executions_principal_type;

ALTER TABLE eiaa_executions
    DROP COLUMN IF EXISTS task_id,
    DROP COLUMN IF EXISTS parent_action_id,
    DROP COLUMN IF EXISTS delegation_depth,
    DROP COLUMN IF EXISTS principal_type,
    DROP COLUMN IF EXISTS agent_id,
    DROP COLUMN IF EXISTS model_id,
    DROP COLUMN IF EXISTS tool_name,
    DROP COLUMN IF EXISTS tool_args_hash;
