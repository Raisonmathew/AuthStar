-- Migration 074: EIAA Executions — Task Chain Columns (Sprint C)
--
-- Adds agent task-chain fields to eiaa_executions without touching
-- existing rows or indexes.  All new columns are nullable / have
-- defaults so existing inserts continue to work with no code change.
--
-- Once this migration is applied, the AuditWriter picks up the new
-- columns on the next deploy and starts populating them for agent
-- tool-call records.

ALTER TABLE eiaa_executions
    ADD COLUMN IF NOT EXISTS task_id          TEXT,
    ADD COLUMN IF NOT EXISTS parent_action_id TEXT,
    ADD COLUMN IF NOT EXISTS delegation_depth INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS principal_type   TEXT        NOT NULL DEFAULT 'human',
    ADD COLUMN IF NOT EXISTS agent_id         TEXT,
    ADD COLUMN IF NOT EXISTS model_id         TEXT,
    ADD COLUMN IF NOT EXISTS tool_name        TEXT,
    ADD COLUMN IF NOT EXISTS tool_args_hash   TEXT;

-- Task chain: all tool calls within a task, ordered by time
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_task_chain
    ON eiaa_executions (task_id, created_at ASC)
    WHERE task_id IS NOT NULL;

-- Per-agent history
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_agent
    ON eiaa_executions (agent_id, created_at DESC)
    WHERE agent_id IS NOT NULL;

-- Parent-child linkage (low-cardinality, fast lookup)
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_parent
    ON eiaa_executions (parent_action_id)
    WHERE parent_action_id IS NOT NULL;

-- Segment queries by principal type (agent vs human)
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_principal_type
    ON eiaa_executions (principal_type, created_at DESC);
