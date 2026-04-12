-- OAuth 2.0 Authorization Server tables
-- Supports: authorization_code, refresh_token, client_credentials grants
-- Integrated with EIAA capsule-based authorization

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. OAuth Refresh Tokens
-- ═══════════════════════════════════════════════════════════════════════════════
-- Opaque refresh tokens (NOT JWTs) stored as SHA-256 hashes.
-- Supports one-time-use rotation with reuse detection (family revocation).
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id              TEXT PRIMARY KEY,
    token_hash      TEXT NOT NULL UNIQUE,            -- SHA-256(token), never store plaintext
    client_id       TEXT NOT NULL,                   -- FK to applications.client_id
    user_id         TEXT NOT NULL,                   -- FK to users.id
    session_id      TEXT NOT NULL,                   -- Links to sessions table
    tenant_id       TEXT NOT NULL,                   -- Tenant scope
    scope           TEXT NOT NULL DEFAULT '',         -- Space-separated granted scopes
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,                     -- NULL = active
    replaced_by     TEXT REFERENCES oauth_refresh_tokens(id), -- Rotation chain
    decision_ref    TEXT,                             -- EIAA audit trail
    ip_address      INET,
    user_agent      TEXT
);

-- Fast lookup by token hash (only active tokens)
CREATE INDEX IF NOT EXISTS idx_oauth_rt_token_hash
    ON oauth_refresh_tokens(token_hash) WHERE revoked_at IS NULL;

-- List active tokens per user+client (consent management UI)
CREATE INDEX IF NOT EXISTS idx_oauth_rt_user_client
    ON oauth_refresh_tokens(user_id, client_id) WHERE revoked_at IS NULL;

-- Cleanup job: expired tokens
CREATE INDEX IF NOT EXISTS idx_oauth_rt_expires
    ON oauth_refresh_tokens(expires_at) WHERE revoked_at IS NULL;

-- Tenant scoped queries
CREATE INDEX IF NOT EXISTS idx_oauth_rt_tenant
    ON oauth_refresh_tokens(tenant_id);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. OAuth User Consents
-- ═══════════════════════════════════════════════════════════════════════════════
-- Records what scopes a user has consented to for each client application.
-- One consent record per (user, client, tenant) — upserted on re-consent.
CREATE TABLE IF NOT EXISTS oauth_consents (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,                   -- Space-separated consented scopes
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,                     -- NULL = active
    decision_ref    TEXT,                             -- EIAA capsule decision that approved consent

    CONSTRAINT uq_oauth_consent_user_client_tenant UNIQUE(user_id, client_id, tenant_id)
);

-- User's active consents (consent management page)
CREATE INDEX IF NOT EXISTS idx_oauth_consent_user
    ON oauth_consents(user_id) WHERE revoked_at IS NULL;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. Application extensions for OAuth AS
-- ═══════════════════════════════════════════════════════════════════════════════
-- Extend the existing applications table with OAuth AS-specific fields.
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS allowed_scopes  JSONB    NOT NULL DEFAULT '["openid", "profile", "email"]',
    ADD COLUMN IF NOT EXISTS is_first_party  BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS token_lifetime_secs      INT NOT NULL DEFAULT 900,
    ADD COLUMN IF NOT EXISTS refresh_token_lifetime_secs INT NOT NULL DEFAULT 2592000;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. RLS Policies for OAuth tables
-- ═══════════════════════════════════════════════════════════════════════════════
ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_consents ENABLE ROW LEVEL SECURITY;

-- Refresh tokens: tenant-scoped access
DROP POLICY IF EXISTS oauth_rt_tenant_isolation ON oauth_refresh_tokens;
CREATE POLICY oauth_rt_tenant_isolation ON oauth_refresh_tokens
    USING (tenant_id = current_setting('app.current_org_id', true));

-- Consents: tenant-scoped access
DROP POLICY IF EXISTS oauth_consent_tenant_isolation ON oauth_consents;
CREATE POLICY oauth_consent_tenant_isolation ON oauth_consents
    USING (tenant_id = current_setting('app.current_org_id', true));
