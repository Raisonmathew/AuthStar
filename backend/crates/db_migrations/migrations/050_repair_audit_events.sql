-- Repair migration: ensure audit_events exists even on environments
-- that previously booted with an out-of-date compiled migration bundle.

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

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created
    ON audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_type
    ON audit_events(tenant_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor
    ON audit_events(actor_id, created_at DESC) WHERE actor_id IS NOT NULL;

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
