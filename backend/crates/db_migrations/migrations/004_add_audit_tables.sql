-- Audit & Security Domain

-- Audit logs table
CREATE TABLE audit_logs (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('audit'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id VARCHAR(64),
    actor_session_id VARCHAR(64),
    actor_ip_address INET,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(64),
    organization_id VARCHAR(64),
    changes JSONB,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_audit_logs_actor_user ON audit_logs(actor_user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);

-- Webhook events table (for idempotency)
CREATE TABLE webhook_events (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('whevt'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provider VARCHAR(50) NOT NULL,
    event_id VARCHAR(255) NOT NULL UNIQUE,
    event_type VARCHAR(100) NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    error TEXT,
    payload JSONB NOT NULL
);

CREATE INDEX idx_webhook_events_event_id ON webhook_events(event_id);
CREATE INDEX idx_webhook_events_processed ON webhook_events(processed) WHERE NOT processed;

-- Rate limits table (alternative to Redis for persistence)
CREATE TABLE rate_limits (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('rlimit'),
    key VARCHAR(255) NOT NULL UNIQUE,
    count INT NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_rate_limits_key ON rate_limits(key);
CREATE INDEX idx_rate_limits_window ON rate_limits(window_end);

COMMENT ON TABLE audit_logs IS 'Immutable audit trail for compliance';
COMMENT ON TABLE webhook_events IS 'Idempotent webhook processing log';
COMMENT ON TABLE rate_limits IS 'Persistent rate limiting (Redis alternative)';
