-- Migration 063: SAML 2.0 Keycloak-parity enhancements
-- Adds SSO session metadata for SLO (name_id, session_index, connection_id)

-- Store SAML session context needed for Single Logout (SLO)
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sso_metadata JSONB;

-- Index for looking up sessions by SAML name_id (needed for IdP-initiated SLO)
CREATE INDEX IF NOT EXISTS idx_sessions_sso_name_id
    ON sessions ((sso_metadata->>'name_id'))
    WHERE sso_metadata IS NOT NULL;
