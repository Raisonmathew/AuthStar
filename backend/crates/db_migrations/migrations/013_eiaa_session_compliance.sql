-- Add decision_ref to sessions table for EIAA compliance
-- Each session MUST reference the decision artifact that authorized its creation

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS decision_ref VARCHAR(64);

-- Add index for lookup
CREATE INDEX IF NOT EXISTS idx_sessions_decision_ref ON sessions(decision_ref);

-- Add tenant_id for multi-tenancy context
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions(tenant_id);

-- Add session_type for EIAA compliance
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_type VARCHAR(50) DEFAULT 'end_user';

COMMENT ON COLUMN sessions.decision_ref IS 'Reference to the login decision artifact that authorized this session';
COMMENT ON COLUMN sessions.tenant_id IS 'Tenant context for the session';
COMMENT ON COLUMN sessions.session_type IS 'Session type: end_user, admin, flow, service';
