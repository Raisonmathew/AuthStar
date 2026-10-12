-- 074_down.sql — Rollback EIAA executions task-chain columns (Sprint C)
ALTER TABLE eiaa_executions
    DROP COLUMN IF EXISTS task_id,
    DROP COLUMN IF EXISTS parent_action_id,
    DROP COLUMN IF EXISTS delegation_depth,
    DROP COLUMN IF EXISTS principal_type,
    DROP COLUMN IF EXISTS agent_id,
    DROP COLUMN IF EXISTS model_id,
    DROP COLUMN IF EXISTS tool_name,
    DROP COLUMN IF EXISTS tool_args_hash;

DROP INDEX IF EXISTS idx_eiaa_executions_task_chain;
DROP INDEX IF EXISTS idx_eiaa_executions_agent;
DROP INDEX IF EXISTS idx_eiaa_executions_parent;
DROP INDEX IF EXISTS idx_eiaa_executions_principal_type;
