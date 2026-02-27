-- Organization & B2B Domain

-- Organizations table
CREATE TABLE organizations (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('org'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    logo_url TEXT,
    stripe_customer_id VARCHAR(255) UNIQUE,
    max_allowed_memberships INT DEFAULT 5,
    public_metadata JSONB DEFAULT '{}',
    private_metadata JSONB DEFAULT '{}',
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_stripe_customer_id ON organizations(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Memberships table
CREATE TABLE memberships (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('memb'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member', 'billing_manager', 'guest')),
    permissions JSONB DEFAULT '[]',
    UNIQUE(organization_id, user_id)
);

CREATE INDEX idx_memberships_org_user ON memberships(organization_id, user_id);
CREATE INDEX idx_memberships_user_id ON memberships(user_id);
CREATE TRIGGER update_memberships_updated_at BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Organization invitations table
CREATE TABLE org_invitations (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('inv'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    email_address VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    inviter_user_id VARCHAR(64) REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    token VARCHAR(255) NOT NULL UNIQUE
);

CREATE INDEX idx_org_invitations_org_id ON org_invitations(organization_id);
CREATE INDEX idx_org_invitations_email ON org_invitations(email_address);
CREATE INDEX idx_org_invitations_token ON org_invitations(token);
CREATE INDEX idx_org_invitations_expires_at ON org_invitations(expires_at);

-- Custom roles table
CREATE TABLE roles (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('role'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN DEFAULT FALSE,
    UNIQUE(organization_id, name)
);

CREATE INDEX idx_roles_org_name ON roles(organization_id, name);

-- Add foreign key to sessions for active organization
ALTER TABLE sessions 
    ADD CONSTRAINT fk_sessions_active_org 
    FOREIGN KEY (active_organization_id) 
    REFERENCES organizations(id) ON DELETE SET NULL;

COMMENT ON TABLE organizations IS 'Multi-tenant organization/workspace';
COMMENT ON TABLE memberships IS 'User-Organization relationship with roles';
COMMENT ON TABLE org_invitations IS 'Pending organization invitations';
COMMENT ON TABLE roles IS 'Custom role definitions with permissions';
