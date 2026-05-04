-- Migration 064: Complete LDAP federation schema
--
-- Adds the remaining columns needed for:
-- - STARTTLS
-- - Group federation
-- - UUID-based stable user tracking
-- - Delta sync timestamps
-- - Manual sync rate-limiting
-- - Stable ldap_uuid in federated_users

-- ── Extend ldap_connections ────────────────────────────────────────────────────

ALTER TABLE ldap_connections
    -- Transport
    ADD COLUMN IF NOT EXISTS start_tls BOOLEAN NOT NULL DEFAULT FALSE,
    -- User attribute mapping
    ADD COLUMN IF NOT EXISTS uuid_attr VARCHAR(64) NOT NULL DEFAULT 'entryUUID',
    ADD COLUMN IF NOT EXISTS username_attr VARCHAR(64) NOT NULL DEFAULT 'uid',
    -- Group federation
    ADD COLUMN IF NOT EXISTS groups_dn VARCHAR(512),
    ADD COLUMN IF NOT EXISTS group_name_attr VARCHAR(64) NOT NULL DEFAULT 'cn',
    ADD COLUMN IF NOT EXISTS group_object_class VARCHAR(64) NOT NULL DEFAULT 'groupOfNames',
    ADD COLUMN IF NOT EXISTS group_membership_attr VARCHAR(64) NOT NULL DEFAULT 'member',
    ADD COLUMN IF NOT EXISTS group_membership_type VARCHAR(8) NOT NULL DEFAULT 'DN'
        CHECK (group_membership_type IN ('DN', 'UID')),
    -- Sync timestamps
    ADD COLUMN IF NOT EXISTS last_full_sync_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_delta_sync_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_manual_sync_at TIMESTAMPTZ,
    -- AD vendor preset flags
    ADD COLUMN IF NOT EXISTS trust_email BOOLEAN NOT NULL DEFAULT TRUE;

-- Fix: migrate existing last_sync_at into last_full_sync_at
UPDATE ldap_connections
    SET last_full_sync_at = last_sync_at
    WHERE last_sync_at IS NOT NULL AND last_full_sync_at IS NULL;

-- ── Extend ldap_federated_users ────────────────────────────────────────────────

ALTER TABLE ldap_federated_users
    ADD COLUMN IF NOT EXISTS ldap_uuid VARCHAR(128),
    ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}';

-- Add a unique index on (connection_id, ldap_uuid) for UUID-based stable lookup.
-- Allow NULLs (servers without entryUUID still fall back to DN).
CREATE UNIQUE INDEX IF NOT EXISTS idx_ldap_federated_users_uuid
    ON ldap_federated_users(connection_id, ldap_uuid)
    WHERE ldap_uuid IS NOT NULL;

-- ── ldap_groups: synced group memberships ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS ldap_groups (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    connection_id   VARCHAR(64) NOT NULL
                        REFERENCES ldap_connections(id) ON DELETE CASCADE,
    ldap_dn         TEXT NOT NULL,
    ldap_uuid       VARCHAR(128),
    name            VARCHAR(255) NOT NULL,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (connection_id, ldap_dn)
);

CREATE INDEX IF NOT EXISTS idx_ldap_groups_connection
    ON ldap_groups(connection_id);

-- Group membership links
CREATE TABLE IF NOT EXISTS ldap_group_members (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    group_id        VARCHAR(64) NOT NULL
                        REFERENCES ldap_groups(id) ON DELETE CASCADE,
    user_id         VARCHAR(64) NOT NULL
                        REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_ldap_group_members_user
    ON ldap_group_members(user_id);
