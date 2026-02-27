CREATE TABLE sso_connections (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL, -- References organizations(id) but we might not have FK if testing without orgs
    type VARCHAR(50) NOT NULL CHECK (type IN ('oauth', 'oidc', 'saml')),
    provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'microsoft', 'apple', 'custom'
    name VARCHAR(255) NOT NULL, -- Display name e.g. "Corporate Google"
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL, -- Encrypted in app logic? For now plain/env ref
    redirect_uri VARCHAR(512) NOT NULL,
    discovery_url VARCHAR(512), -- For OIDC
    authorization_url VARCHAR(512), -- For OAuth2
    token_url VARCHAR(512), -- For OAuth2
    userinfo_url VARCHAR(512), -- For OAuth2
    scope VARCHAR(512) DEFAULT 'openid email profile',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sso_connections_tenant_id ON sso_connections(tenant_id);
CREATE UNIQUE INDEX idx_sso_connections_tenant_provider ON sso_connections(tenant_id, provider) WHERE type = 'oauth';
