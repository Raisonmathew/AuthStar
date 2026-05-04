-- Migration 062: LDAP Keycloak-parity schema enhancements
--
-- Adds Keycloak User Federation parity columns to ldap_connections,
-- plus three new tables: ldap_sync_runs, ldap_federated_users, ldap_mappers.

-- ── Extend ldap_connections ──────────────────────────────────────────────────

ALTER TABLE ldap_connections
    ADD COLUMN IF NOT EXISTS vendor VARCHAR(32) NOT NULL DEFAULT 'other',
    ADD COLUMN IF NOT EXISTS edit_mode VARCHAR(16) NOT NULL DEFAULT 'READ_ONLY'
        CHECK (edit_mode IN ('READ_ONLY', 'WRITABLE', 'UNSYNCED')),
    ADD COLUMN IF NOT EXISTS sync_interval_minutes INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS connection_timeout_secs INTEGER NOT NULL DEFAULT 10,
    ADD COLUMN IF NOT EXISTS read_timeout_secs INTEGER NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS referral_mode VARCHAR(16) NOT NULL DEFAULT 'ignore'
        CHECK (referral_mode IN ('ignore', 'follow')),
    ADD COLUMN IF NOT EXISTS search_scope VARCHAR(16) NOT NULL DEFAULT 'subtree'
        CHECK (search_scope IN ('subtree', 'one', 'base')),
    ADD COLUMN IF NOT EXISTS attr_map_username VARCHAR(128) NOT NULL DEFAULT 'uid',
    ADD COLUMN IF NOT EXISTS attr_map_firstname VARCHAR(128) NOT NULL DEFAULT 'givenName',
    ADD COLUMN IF NOT EXISTS attr_map_lastname VARCHAR(128) NOT NULL DEFAULT 'sn',
    ADD COLUMN IF NOT EXISTS attr_map_phone VARCHAR(128) NOT NULL DEFAULT 'telephoneNumber',
    ADD COLUMN IF NOT EXISTS page_size INTEGER NOT NULL DEFAULT 100,
    -- Stores an opaque reference to the encrypted bind password
    -- (see FactorEncryption: 'enc:nonce:ciphertext' or plaintext for dev)
    -- Replaces the misleadingly-named bind_password_enc column (kept for compat).
    ADD COLUMN IF NOT EXISTS bind_password_ref TEXT NOT NULL DEFAULT '';

-- Backfill bind_password_ref from bind_password_enc where it's not already set
UPDATE ldap_connections
    SET bind_password_ref = bind_password_enc
    WHERE bind_password_ref = '' AND bind_password_enc != '';

-- ── ldap_sync_runs ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ldap_sync_runs (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    connection_id   VARCHAR(64) NOT NULL
                        REFERENCES ldap_connections(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          VARCHAR(16) NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'failed')),
    users_found     INTEGER NOT NULL DEFAULT 0,
    users_created   INTEGER NOT NULL DEFAULT 0,
    users_updated   INTEGER NOT NULL DEFAULT 0,
    users_disabled  INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_ldap_sync_runs_connection_id
    ON ldap_sync_runs(connection_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ldap_sync_runs_tenant_id
    ON ldap_sync_runs(tenant_id, started_at DESC);

-- ── ldap_federated_users ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ldap_federated_users (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    connection_id   VARCHAR(64) NOT NULL
                        REFERENCES ldap_connections(id) ON DELETE CASCADE,
    user_id         VARCHAR(64) NOT NULL
                        REFERENCES users(id) ON DELETE CASCADE,
    ldap_dn         TEXT NOT NULL,
    ldap_uid        VARCHAR(255) NOT NULL,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (connection_id, ldap_dn)
);

CREATE INDEX IF NOT EXISTS idx_ldap_federated_users_user_id
    ON ldap_federated_users(user_id);
CREATE INDEX IF NOT EXISTS idx_ldap_federated_users_tenant_id
    ON ldap_federated_users(tenant_id);

-- ── ldap_mappers ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ldap_mappers (
    id              VARCHAR(64) PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    connection_id   VARCHAR(64) NOT NULL
                        REFERENCES ldap_connections(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    mapper_type     VARCHAR(64) NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (connection_id, name)
);

CREATE INDEX IF NOT EXISTS idx_ldap_mappers_connection_id
    ON ldap_mappers(connection_id);
