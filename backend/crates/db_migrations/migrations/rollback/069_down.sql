-- 069_down.sql — Rollback identity management completion
-- Drops user_attributes and removes impersonation metadata columns from sessions.
DROP TABLE IF EXISTS user_attributes CASCADE;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS impersonated_by,
    DROP COLUMN IF EXISTS impersonation_reason;
