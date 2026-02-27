-- EIAA Core Schema

-- Policies defined by tenants; versioned immutable specs
CREATE TABLE eiaa_policies (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('eipol'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    version INT NOT NULL,
    spec JSONB NOT NULL,
    UNIQUE(tenant_id, action, version)
);

-- Compiled & signed capsules (immutable)
CREATE TABLE eiaa_capsules (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('eicap'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    policy_version INT NOT NULL,
    meta JSONB NOT NULL,
    policy_hash_b64 VARCHAR(255) NOT NULL,
    capsule_hash_b64 VARCHAR(255) NOT NULL,
    compiler_kid VARCHAR(255) NOT NULL,
    compiler_sig_b64 TEXT NOT NULL
);
CREATE INDEX idx_eiaa_capsules_tenant_action ON eiaa_capsules(tenant_id, action);
CREATE UNIQUE INDEX idx_eiaa_capsules_hash ON eiaa_capsules(capsule_hash_b64);

-- Executions + attestation artifacts (append-only)
CREATE TABLE eiaa_executions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('eiexec'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    capsule_id VARCHAR(64),
    capsule_hash_b64 VARCHAR(255) NOT NULL,
    decision JSONB NOT NULL,
    attestation JSONB NOT NULL,
    nonce_b64 VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    ip_address INET
);
CREATE INDEX idx_eiaa_exec_capsule_hash ON eiaa_executions(capsule_hash_b64);
CREATE INDEX idx_eiaa_exec_created_at ON eiaa_executions(created_at);

-- Replay protection store (optional, broker-side)
CREATE TABLE eiaa_replay_nonces (
    nonce_b64 VARCHAR(255) PRIMARY KEY,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
