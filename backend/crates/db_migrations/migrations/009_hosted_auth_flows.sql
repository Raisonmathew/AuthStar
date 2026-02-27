-- Hosted Authentication Flows State Storage
CREATE TABLE IF NOT EXISTS hosted_auth_flows (
    flow_id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('flow'),
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_id VARCHAR(64),
    redirect_uri TEXT,
    state_param TEXT,
    
    -- EIAA Execution State
    execution_state JSONB NOT NULL DEFAULT '{}',
    current_step VARCHAR(50) DEFAULT 'email',
    
    -- Security & Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes',
    attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 5,
    
    -- Tracking
    ip_address INET,
    user_agent TEXT,
    completed BOOLEAN DEFAULT FALSE,
    decision_ref VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_flows_org ON hosted_auth_flows(org_id);
CREATE INDEX IF NOT EXISTS idx_flows_expires ON hosted_auth_flows(expires_at);
CREATE INDEX IF NOT EXISTS idx_flows_decision ON hosted_auth_flows(decision_ref) WHERE decision_ref IS NOT NULL;

COMMENT ON TABLE hosted_auth_flows IS 'State storage for EIAA-driven hosted login flows';
