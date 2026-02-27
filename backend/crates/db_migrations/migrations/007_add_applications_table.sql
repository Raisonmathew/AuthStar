-- Applications / Relying Parties
CREATE TABLE IF NOT EXISTS applications (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('app'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('web', 'mobile', 'api', 'machine')),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255), -- Nullable for public clients
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    allowed_flows JSONB NOT NULL DEFAULT '["authorization_code"]',
    public_config JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_applications_tenant_id ON applications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id);
DROP TRIGGER IF EXISTS update_applications_updated_at ON applications;
CREATE TRIGGER update_applications_updated_at BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE applications IS 'OIDC/OAuth2 Clients registered by tenants';
