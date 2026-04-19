-- Migration 047: Publishable Keys
--
-- Publishable keys are PUBLIC identifiers embedded in client-side code.
-- Format: pk_{environment}_{org_slug}
-- Example: pk_test_acme, pk_live_acme123
--
-- Unlike API keys (secret, hashed), publishable keys are NOT secret.
-- They identify the tenant + environment for SDK initialization.
-- Stored in plaintext (they're public by design).

CREATE TABLE IF NOT EXISTS publishable_keys (
    id              VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('pkey'),
    tenant_id       VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The full key value: pk_{env}_{slug}
    key             TEXT        NOT NULL UNIQUE,
    -- Environment: 'test' or 'live'
    environment     TEXT        NOT NULL CHECK (environment IN ('test', 'live')),
    -- Human-readable label (e.g. "Production key", "Staging key")
    name            TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

-- One active key per environment per tenant
CREATE UNIQUE INDEX IF NOT EXISTS publishable_keys_unique_env_per_tenant
    ON publishable_keys(tenant_id, environment)
    WHERE revoked_at IS NULL;

-- Fast lookup by key value (most common operation during SDK init)
CREATE INDEX IF NOT EXISTS publishable_keys_key_idx ON publishable_keys(key)
    WHERE revoked_at IS NULL AND is_active = TRUE;

-- Tenant listing (for management UI)
CREATE INDEX IF NOT EXISTS publishable_keys_tenant_idx ON publishable_keys(tenant_id)
    WHERE revoked_at IS NULL;

-- Row Level Security: tenant isolation
ALTER TABLE publishable_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY publishable_keys_tenant_isolation ON publishable_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));

-- Cross-tenant lookup for SDK validation (SELECT only, no tenant context needed)
CREATE POLICY publishable_keys_public_lookup ON publishable_keys
    FOR SELECT
    USING (
        current_setting('app.current_tenant_id', true) IS NULL
        OR current_setting('app.current_tenant_id', true) = ''
    );

ALTER TABLE publishable_keys FORCE ROW LEVEL SECURITY;
