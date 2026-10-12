-- 077_down.sql — Rollback agent capsule identity columns and unique index
DROP INDEX IF EXISTS idx_eiaa_capsules_agent_identity;
DROP INDEX IF EXISTS idx_eiaa_capsules_resolution;

ALTER TABLE eiaa_capsules
    DROP COLUMN IF EXISTS principal_type,
    DROP COLUMN IF EXISTS agent_id,
    DROP COLUMN IF EXISTS model_id;
