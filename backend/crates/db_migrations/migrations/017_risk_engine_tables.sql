-- EIAA Risk Engine Tables
-- Migration 017: Risk states, device records, risk evaluations, security events, auth attempts

-- Risk State Storage (for decay)
CREATE TABLE IF NOT EXISTS risk_states (
    id VARCHAR(255) PRIMARY KEY,
    subject_type VARCHAR(50) NOT NULL DEFAULT 'user',  -- 'user' | 'device' | 'session'
    subject_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    signal_type VARCHAR(50) NOT NULL,      -- 'device_trust' | 'ip_reputation' | etc
    value VARCHAR(50) NOT NULL,            -- 'new' | 'unknown' | 'compromised' etc
    initial_score DECIMAL(5,2) NOT NULL DEFAULT 0,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',  -- 'low' | 'medium' | 'high'
    decay_model VARCHAR(20) NOT NULL DEFAULT 'temporal',  -- 'temporal' | 'sticky' | 'none'
    half_life_hours INTEGER,               -- For temporal only
    stabilizing_event VARCHAR(50),         -- For sticky only
    decay_config JSONB,                    -- Full decay model config
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stabilized_at TIMESTAMPTZ,             -- When sticky risk was stabilized
    cleared_at TIMESTAMPTZ,                -- When non-decaying risk was cleared
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(subject_type, subject_id, signal_type)
);

CREATE INDEX idx_risk_states_subject ON risk_states(subject_type, subject_id);
CREATE INDEX idx_risk_states_org ON risk_states(org_id);
CREATE INDEX idx_risk_states_active ON risk_states(decay_model, stabilized_at, cleared_at)
    WHERE cleared_at IS NULL;
CREATE INDEX idx_risk_states_expires ON risk_states(last_seen_at)
    WHERE decay_model = 'temporal' AND cleared_at IS NULL;

-- Device Records (for device binding and trust)
CREATE TABLE IF NOT EXISTS device_records (
    id VARCHAR(255) PRIMARY KEY,
    device_id VARCHAR(255) NOT NULL UNIQUE,  -- Server-issued device ID
    subject_id VARCHAR(255) NOT NULL,        -- User ID this device is bound to
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    platform VARCHAR(50) NOT NULL DEFAULT 'web',  -- 'web' | 'ios' | 'android'
    signals_hash VARCHAR(64) NOT NULL,       -- SHA256 of device fingerprint signals
    trust_state VARCHAR(20) NOT NULL DEFAULT 'new',  -- 'unknown' | 'new' | 'known' | 'changed' | 'compromised'
    compromise_flags JSONB NOT NULL DEFAULT '[]'::jsonb,  -- List of compromise indicators
    successful_auths INTEGER NOT NULL DEFAULT 0,
    last_ip VARCHAR(45),                     -- Last seen IP (for geo velocity)
    last_country VARCHAR(2),                 -- Last seen country code
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_records_subject ON device_records(subject_id);
CREATE INDEX idx_device_records_org ON device_records(org_id);
CREATE INDEX idx_device_records_trust ON device_records(trust_state)
    WHERE trust_state IN ('compromised', 'changed');

-- Risk Evaluations (for audit trail)
CREATE TABLE IF NOT EXISTS risk_evaluations (
    id VARCHAR(255) PRIMARY KEY,
    subject_id VARCHAR(255),                 -- User ID if known
    org_id VARCHAR(255) REFERENCES organizations(id) ON DELETE CASCADE,
    flow_id VARCHAR(255),                    -- Associated auth flow
    session_id VARCHAR(255),                 -- Session if re-evaluation
    risk_snapshot JSONB NOT NULL,            -- Normalized RiskContext at evaluation time
    constraints_derived JSONB NOT NULL,      -- Derived RiskConstraints
    request_hash VARCHAR(64),                -- Hash of request context for replay detection
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_evaluations_subject ON risk_evaluations(subject_id);
CREATE INDEX idx_risk_evaluations_org ON risk_evaluations(org_id);
CREATE INDEX idx_risk_evaluations_flow ON risk_evaluations(flow_id);
CREATE INDEX idx_risk_evaluations_time ON risk_evaluations(evaluated_at);

-- Security Events (for account stability signals)
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,         -- 'password_reset' | 'mfa_reset' | 'lockout' | 'login_success' | 'login_failure'
    severity VARCHAR(20) NOT NULL DEFAULT 'info',  -- 'info' | 'warning' | 'critical'
    ip_address VARCHAR(45),
    user_agent TEXT,
    country VARCHAR(2),
    metadata JSONB,                          -- Event-specific data
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_user ON security_events(user_id);
CREATE INDEX idx_security_events_org ON security_events(org_id);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_time ON security_events(created_at);
-- Note: Partial indexes with NOW() removed - use queries with date ranges instead

-- Auth Attempts (for failed attempt tracking)
CREATE TABLE IF NOT EXISTS auth_attempts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255),                    -- NULL for unknown users
    org_id VARCHAR(255) REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255),                      -- Email used in attempt
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),             -- 'invalid_password' | 'user_not_found' | 'locked_out' etc
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_id VARCHAR(255),
    flow_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_attempts_user ON auth_attempts(user_id);
CREATE INDEX idx_auth_attempts_org ON auth_attempts(org_id);
CREATE INDEX idx_auth_attempts_email ON auth_attempts(email);
CREATE INDEX idx_auth_attempts_success ON auth_attempts(success);
CREATE INDEX idx_auth_attempts_user_time ON auth_attempts(user_id, created_at);
CREATE INDEX idx_auth_attempts_failed ON auth_attempts(user_id, created_at) WHERE success = false;
-- Note: Time-based filtering happens in queries, not index predicates

-- Alter sessions table to add AAL tracking (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE tablename = 'sessions') THEN
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS assurance_level VARCHAR(10) DEFAULT 'AAL0';
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS verified_capabilities JSONB DEFAULT '[]'::jsonb;
        ALTER TABLE sessions ADD COLUMN IF NOT EXISTS risk_context_snapshot JSONB;
    END IF;
END $$;

-- Alter organizations table to add baseline assurance config (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE tablename = 'organizations') THEN
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS baseline_assurance VARCHAR(10) DEFAULT 'AAL1';
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS enabled_capabilities JSONB DEFAULT '["password", "totp", "passkey_synced"]'::jsonb;
        ALTER TABLE organizations ADD COLUMN IF NOT EXISTS risk_settings JSONB DEFAULT '{}'::jsonb;
    END IF;
END $$;

-- Alter apps table to add required assurance (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE tablename = 'apps') THEN
        ALTER TABLE apps ADD COLUMN IF NOT EXISTS required_assurance VARCHAR(10) DEFAULT 'AAL1';
        ALTER TABLE apps ADD COLUMN IF NOT EXISTS require_phishing_resistant BOOLEAN DEFAULT false;
        ALTER TABLE apps ADD COLUMN IF NOT EXISTS allowed_capabilities JSONB;
    END IF;
END $$;

-- User factors table (enrolled authentication methods)
CREATE TABLE IF NOT EXISTS user_factors (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    factor_type VARCHAR(50) NOT NULL,        -- 'password' | 'totp' | 'passkey' | 'sms' | etc
    capability VARCHAR(50) NOT NULL,         -- Maps to Capability enum
    verified BOOLEAN NOT NULL DEFAULT false,
    last_used_at TIMESTAMPTZ,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,                          -- Factor-specific data (e.g., truncated phone for SMS)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, factor_type)
);

CREATE INDEX idx_user_factors_user ON user_factors(user_id);
CREATE INDEX idx_user_factors_org ON user_factors(org_id);
CREATE INDEX idx_user_factors_capability ON user_factors(capability);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to new tables
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_risk_states_updated_at') THEN
        CREATE TRIGGER update_risk_states_updated_at
            BEFORE UPDATE ON risk_states
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_device_records_updated_at') THEN
        CREATE TRIGGER update_device_records_updated_at
            BEFORE UPDATE ON device_records
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_user_factors_updated_at') THEN
        CREATE TRIGGER update_user_factors_updated_at
            BEFORE UPDATE ON user_factors
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;
