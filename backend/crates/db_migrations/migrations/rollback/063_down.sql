-- 063_down.sql — Rollback SAML 2.0 enhancements
ALTER TABLE sessions
    DROP COLUMN IF EXISTS sso_metadata,
    DROP COLUMN IF EXISTS sso_name_id,
    DROP COLUMN IF EXISTS sso_session_index,
    DROP COLUMN IF EXISTS sso_connection_id;

DROP INDEX IF EXISTS idx_sessions_sso_name_id;
DROP INDEX IF EXISTS idx_sessions_impersonated_by;

-- Remove impersonation columns if added in 063
ALTER TABLE sessions
    DROP COLUMN IF EXISTS impersonated_by,
    DROP COLUMN IF EXISTS impersonation_reason;
