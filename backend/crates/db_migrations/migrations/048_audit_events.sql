-- General Audit Events table
-- Captures all security-relevant operations: logins, logouts, config changes,
-- API key operations, SSO changes, session revocations, etc.
--
-- This is separate from eiaa_executions which stores cryptographic capsule proofs.

CREATE TABLE IF NOT EXISTS audit_events (
    id          VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('evt'),
    tenant_id   VARCHAR(64) NOT NULL,
    event_type  VARCHAR(64) NOT NULL,
    actor_id    VARCHAR(64),
    actor_email VARCHAR(255),
    target_type VARCHAR(64),
    target_id   VARCHAR(64),
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_events_tenant_created ON audit_events(tenant_id, created_at DESC);
CREATE INDEX idx_audit_events_tenant_type ON audit_events(tenant_id, event_type, created_at DESC);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id, created_at DESC) WHERE actor_id IS NOT NULL;

-- Enable RLS for tenant isolation (consistent with other tables)
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE audit_events IS 'General audit trail for all security-relevant operations';
COMMENT ON COLUMN audit_events.event_type IS 'Dotted event type: user.login_success, org.config_updated, etc.';
COMMENT ON COLUMN audit_events.actor_id IS 'User who performed the action (NULL for system events)';
COMMENT ON COLUMN audit_events.target_type IS 'Type of affected entity: user, org, sso_connection, api_key, etc.';
COMMENT ON COLUMN audit_events.target_id IS 'ID of the affected entity';
COMMENT ON COLUMN audit_events.metadata IS 'Event-specific details as JSON';
