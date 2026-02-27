-- EIAA Executions: Cryptographic Audit Trail
-- Stores attestations for all EIAA decisions (signup, login, authorization)

-- Drop if exists (for idempotency during development)
DROP TABLE IF EXISTS eiaa_executions CASCADE;

CREATE TABLE eiaa_executions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('exec'),
    decision_ref VARCHAR(64) UNIQUE NOT NULL,
    
    -- Capsule identification
    capsule_hash_b64 TEXT NOT NULL,
    capsule_version TEXT NOT NULL,
    action TEXT NOT NULL, -- 'signup', 'login', 'authorize', etc.
    tenant_id VARCHAR(64) NOT NULL,
    
    -- Execution context
    input_digest TEXT NOT NULL, -- SHA-256 of execution inputs
    nonce_b64 TEXT NOT NULL,
    
    -- Decision
    decision JSONB NOT NULL, -- {"allow": bool, "reason": string}
    
    -- Attestation (cryptographic proof)
    attestation_signature_b64 TEXT NOT NULL,
    attestation_timestamp TIMESTAMPTZ NOT NULL,
    attestation_hash_b64 TEXT,
    
    -- Metadata
    user_id VARCHAR(64), -- Only populated after identity creation
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast lookup
CREATE INDEX idx_eiaa_executions_decision_ref ON eiaa_executions(decision_ref);
CREATE INDEX idx_eiaa_executions_tenant_action ON eiaa_executions(tenant_id, action);
CREATE INDEX idx_eiaa_executions_created_at ON eiaa_executions(created_at DESC);
CREATE INDEX idx_eiaa_executions_user_id ON eiaa_executions(user_id) WHERE user_id IS NOT NULL;

-- Comments for documentation
COMMENT ON TABLE eiaa_executions IS 'Cryptographic audit trail for all EIAA execution decisions';
COMMENT ON COLUMN eiaa_executions.decision_ref IS 'Unique reference linking to the attested decision';
COMMENT ON COLUMN eiaa_executions.capsule_hash_b64 IS 'Hash of the compiled WASM capsule that made the decision';
COMMENT ON COLUMN eiaa_executions.attestation_signature_b64 IS 'Ed25519 signature proving decision authenticity';
