-- Rollback migration 036: Session EIAA Decision Reference
-- Removes decision_ref, aal_level columns and associated indexes from sessions.
-- WARNING: decision_ref and aal_level data will be lost.

DROP INDEX IF EXISTS idx_eiaa_executions_user_tenant;
DROP INDEX IF EXISTS idx_sessions_aal_level;
DROP INDEX IF EXISTS idx_sessions_decision_ref;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS aal_level,
    DROP COLUMN IF EXISTS decision_ref;