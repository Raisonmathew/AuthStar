-- Create risk_states table for Risk Decay Service
-- Tracks persistent risk signals that decay over time or require stabilization

CREATE TABLE IF NOT EXISTS risk_states (
    id VARCHAR(50) PRIMARY KEY,
    subject_type VARCHAR(20) NOT NULL, -- 'user', 'device', 'ip'
    subject_id VARCHAR(255) NOT NULL,
    signal_type VARCHAR(50) NOT NULL, -- e.g., 'new_device', 'suspicious_ip', 'failed_login_spike'
    
    value TEXT NOT NULL,              -- Context value (e.g., the IP address or Device ID)
    initial_score DOUBLE PRECISION NOT NULL,
    severity VARCHAR(20) NOT NULL,    -- 'low', 'medium', 'high', 'critical'
    
    decay_model VARCHAR(20) NOT NULL, -- 'temporal', 'sticky', 'non_decaying'
    decay_config JSONB,               -- { "half_life_hours": 24 } or { "required_event": "... " }
    
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    
    stabilized_at TIMESTAMPTZ,        -- For sticky risks
    cleared_at TIMESTAMPTZ,           -- For non-decaying risks
    
    metadata JSONB,
    
    CONSTRAINT uq_risk_state_subject_signal UNIQUE (subject_type, subject_id, signal_type, value)
);

CREATE INDEX IF NOT EXISTS idx_risk_states_subject ON risk_states(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_risk_states_cleanup ON risk_states(last_seen_at) WHERE cleared_at IS NOT NULL;
