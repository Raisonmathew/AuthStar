-- Migration 037: API Keys
--
-- B-4 FIX: Implements the api_keys table for the developer API keys feature.
--
-- Design decisions:
--   1. Key format: ask_<8-char-prefix>_<48-char-base58-random>
--      The prefix is the first 8 chars of the random portion, stored in key_prefix
--      for fast lookup without scanning hashes.
--   2. Storage: Only key_prefix (shown in UI) and key_hash (argon2id) are stored.
--      The full key is returned ONCE on creation and never stored in plaintext.
--   3. RLS: tenant_id column with policy matching the existing pattern from migration 005.
--   4. Soft delete: revoked_at timestamp preserves audit trail.
--   5. Scopes: text[] for flexible, forward-compatible permission model.
--
-- NOTE: Uses VARCHAR(64) for id/tenant_id/user_id to match the project-wide
--       prefixed ID convention (users.id = VARCHAR(64), organizations.id = VARCHAR(64)).
--       Original migration incorrectly used UUID which would fail FK creation.

CREATE TABLE IF NOT EXISTS api_keys (
    id              VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('akey'),
    tenant_id       VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    -- First 8 chars of the random key portion, used for fast lookup during auth.
    -- Never the full key. Format: first 8 chars after "ask_<prefix>_"
    key_prefix      TEXT        NOT NULL CHECK (char_length(key_prefix) = 8),
    -- Argon2id hash of the full key (m=19456, t=2, p=1 per OWASP minimum)
    key_hash        TEXT        NOT NULL,
    -- Free-form permission scopes, e.g. {"read:users", "write:sessions"}
    scopes          TEXT[]      NOT NULL DEFAULT '{}',
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Soft delete: set on revocation, preserves audit trail
    revoked_at      TIMESTAMPTZ,
    -- Prevent duplicate key names per user
    CONSTRAINT api_keys_unique_name_per_user UNIQUE (user_id, name)
);

-- Fast lookup by prefix during authentication (most common operation)
CREATE INDEX IF NOT EXISTS api_keys_prefix_idx ON api_keys(key_prefix)
    WHERE revoked_at IS NULL;

-- Tenant + user listing (for management UI)
CREATE INDEX IF NOT EXISTS api_keys_tenant_user_idx ON api_keys(tenant_id, user_id)
    WHERE revoked_at IS NULL;

-- Expiry cleanup job support
CREATE INDEX IF NOT EXISTS api_keys_expires_at_idx ON api_keys(expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;

-- Row Level Security: tenant isolation
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));

-- Allow service role to bypass RLS (for background jobs and migrations)
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;