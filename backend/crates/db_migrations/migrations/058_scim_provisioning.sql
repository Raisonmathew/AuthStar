-- ============================================================================
-- 058_scim_provisioning.sql
-- ----------------------------------------------------------------------------
-- Tier 3 — SCIM 2.0 Inbound Provisioning (RFC 7643 / RFC 7644)
--
-- Enables enterprise IdPs (Okta, Azure AD, OneLogin, etc.) to push user and
-- group data into AuthStar via the SCIM 2.0 protocol. Each tenant gets its
-- own SCIM endpoint, secured by a per-tenant Bearer token stored here.
--
-- Design decisions:
--   * scim_tokens: one or more long-lived Bearer tokens per tenant. Stored as
--     SHA-256 hashes (raw token never persisted after creation).
--   * scim_users: SCIM-side identity record. Maps to `users` via
--     `local_user_id`. Tracks the external SCIM `external_id` for IdP
--     correlation, plus the full canonical display name and active flag.
--   * scim_groups: SCIM-side group record. Maps to `tenant_memberships`
--     (group membership rows) for enforcement; display_name kept separate.
--   * scim_group_members: join table for SCIM group membership (by SCIM user).
--
-- EIAA invariant: SCIM provisioning is a directory sync operation. It creates
-- or deactivates users/memberships. Authorization to act as a provisioned user
-- still goes through the capsule. Provisioning here only affects identity data,
-- not authorization policy.
--
-- All tables use VARCHAR(64) PKs (NanoID, same as the rest of the project).
-- RLS is applied via `tenant_id` on every row.
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- scim_tokens: per-tenant SCIM API tokens
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_tokens (
    id              VARCHAR(64)     PRIMARY KEY,
    tenant_id       VARCHAR(64)     NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- SHA-256 hex of the raw bearer token
    token_hash      VARCHAR(64)     NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked         BOOLEAN         NOT NULL DEFAULT FALSE,
    created_by      VARCHAR(64),    -- user_id that generated the token
    CONSTRAINT uq_scim_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_tenant ON scim_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash   ON scim_tokens (token_hash);

-- ─────────────────────────────────────────────────────────────────────────────
-- scim_users: SCIM-managed users, linked to the canonical users table
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_users (
    -- SCIM resource id (also the SCIM `id` attribute returned to the IdP)
    id              VARCHAR(64)     PRIMARY KEY,
    tenant_id       VARCHAR(64)     NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The canonical user row this SCIM record owns/created
    local_user_id   VARCHAR(64)     REFERENCES users(id) ON DELETE SET NULL,
    -- Stable identifier from the upstream IdP (SCIM `externalId`)
    external_id     VARCHAR(255),
    -- SCIM userName (typically email or UPN)
    user_name       VARCHAR(255)    NOT NULL,
    -- Structured name
    formatted_name  TEXT,
    family_name     VARCHAR(255),
    given_name      VARCHAR(255),
    -- Primary email (may duplicate users.email; source of truth is this row
    -- for SCIM-managed users)
    primary_email   VARCHAR(255),
    -- SCIM active flag; FALSE => user is suspended / deprovisioned
    active          BOOLEAN         NOT NULL DEFAULT TRUE,
    -- Full SCIM resource body as last sent by IdP (for read-back / ETag)
    raw_scim        JSONB,
    -- RFC 7644 §3.14 resource version for ETag / conditional updates
    version         VARCHAR(64)     NOT NULL DEFAULT '1',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_scim_user_tenant_username UNIQUE (tenant_id, user_name),
    CONSTRAINT uq_scim_user_tenant_external UNIQUE (tenant_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_users_tenant        ON scim_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_local_user    ON scim_users (local_user_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_username      ON scim_users (tenant_id, user_name);

-- ─────────────────────────────────────────────────────────────────────────────
-- scim_groups: SCIM-managed groups
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_groups (
    id              VARCHAR(64)     PRIMARY KEY,
    tenant_id       VARCHAR(64)     NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id     VARCHAR(255),
    display_name    VARCHAR(255)    NOT NULL,
    raw_scim        JSONB,
    version         VARCHAR(64)     NOT NULL DEFAULT '1',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_scim_group_tenant_name UNIQUE (tenant_id, display_name),
    CONSTRAINT uq_scim_group_tenant_external UNIQUE (tenant_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups (tenant_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- scim_group_members: group membership (SCIM User → SCIM Group)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id        VARCHAR(64)     NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id         VARCHAR(64)     NOT NULL REFERENCES scim_users(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members (user_id);
