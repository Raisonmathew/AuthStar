-- Migration 005: Multi-Tenancy with Row-Level Security
-- Add organization isolation and branding configuration

-- Add organization branding and configuration
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS branding JSONB DEFAULT '{}'::jsonb;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS auth_config JSONB DEFAULT '{}'::jsonb;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS custom_domain TEXT;

-- Branding structure:
-- {
--   "logo_url": "https://...",
--   "primary_color": "#3B82F6",
--   "background_color": "#FFFFFF",
--   "text_color": "#1F2937",
--   "font_family": "Inter"
-- }

-- Auth config structure:
-- {
--   "fields": {
--     "email": true,
--     "password": true,
--     "phone": false,
--     "custom_fields": [{"name": "employee_id", "type": "text", "required": false}]
--   },
--   "oauth": {
--     "google": {"enabled": true, "client_id": "...", "client_secret": "..."},
--     "github": {"enabled": true, "client_id": "...", "client_secret": "..."},
--     "microsoft": {"enabled": false}
--   },
--   "custom_css": "",
--   "redirect_urls": ["http://localhost:3000/callback"]
-- }

COMMENT ON COLUMN organizations.branding IS 'Visual customization: logo, colors, fonts';
COMMENT ON COLUMN organizations.auth_config IS 'Authentication settings: fields, OAuth providers, custom CSS';
COMMENT ON COLUMN organizations.custom_domain IS 'Custom domain for hosted pages (Pro feature)';

-- Add organization_id to all user-related tables if not exists
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(id);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(id);
ALTER TABLE mfa_factors ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(id);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org_id ON sessions(organization_id);
CREATE INDEX IF NOT EXISTS idx_mfa_org_id ON mfa_factors(organization_id);

-- Enable Row-Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE passwords ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for organization isolation
-- Users can only see data from their organization

-- Policy for users table
CREATE POLICY user_org_isolation ON users
    USING (organization_id = current_setting('app.current_org_id', true)::text);

CREATE POLICY user_org_insert ON users
    FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::text);

CREATE POLICY user_org_update ON users
    FOR UPDATE
    USING (organization_id = current_setting('app.current_org_id', true)::text);

-- Policy for sessions table
CREATE POLICY session_org_isolation ON sessions
    USING (organization_id = current_setting('app.current_org_id', true)::text);

CREATE POLICY session_org_insert ON sessions
    FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::text);

-- Policy for identities table
CREATE POLICY identity_org_isolation ON identities
    USING (EXISTS (
        SELECT 1 FROM users 
        WHERE users.id = identities.user_id 
        AND users.organization_id = current_setting('app.current_org_id', true)::text
    ));

-- Policy for passwords table
CREATE POLICY password_org_isolation ON passwords
    USING (EXISTS (
        SELECT 1 FROM users 
        WHERE users.id = passwords.user_id 
        AND users.organization_id = current_setting('app.current_org_id', true)::text
    ));

-- Policy for MFA factors table
CREATE POLICY mfa_org_isolation ON mfa_factors
    USING (organization_id = current_setting('app.current_org_id', true)::text);

-- Policy for organization members table
CREATE POLICY org_member_isolation ON memberships
    USING (organization_id = current_setting('app.current_org_id', true)::text);

-- Create function to set organization context
CREATE OR REPLACE FUNCTION set_org_context(org_id TEXT)
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_org_id', org_id, false);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION set_org_context IS 'Set the current organization context for RLS';

-- Create function to get organization by slug
CREATE OR REPLACE FUNCTION get_org_by_slug(org_slug TEXT)
RETURNS TABLE (
    id TEXT,
    name TEXT,
    slug TEXT,
    branding JSONB,
    auth_config JSONB,
    custom_domain TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        organizations.id,
        organizations.name,
        organizations.slug,
        organizations.branding,
        organizations.auth_config,
        organizations.custom_domain
    FROM organizations
    WHERE organizations.slug = org_slug;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_org_by_slug IS 'Retrieve organization by slug for subdomain routing';

-- Add default branding for existing organizations
UPDATE organizations
SET branding = jsonb_build_object(
    'logo_url', '',
    'primary_color', '#3B82F6',
    'background_color', '#FFFFFF',
    'text_color', '#1F2937',
    'font_family', 'Inter'
)
WHERE branding = '{}'::jsonb OR branding IS NULL;

-- Add default auth config for existing organizations
UPDATE organizations
SET auth_config = jsonb_build_object(
    'fields', jsonb_build_object(
        'email', true,
        'password', true,
        'phone', false,
        'custom_fields', '[]'::jsonb
    ),
    'oauth', jsonb_build_object(
        'google', jsonb_build_object('enabled', false),
        'github', jsonb_build_object('enabled', false),
        'microsoft', jsonb_build_object('enabled', false)
    ),
    'custom_css', '',
    'redirect_urls', '["http://localhost:3000/callback"]'::jsonb
)
WHERE auth_config = '{}'::jsonb OR auth_config IS NULL;
