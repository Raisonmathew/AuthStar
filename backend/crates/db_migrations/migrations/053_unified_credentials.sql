-- ============================================================================
-- 053_unified_credentials.sql
-- ----------------------------------------------------------------------------
-- T1.6 Phase 1 (EXPAND) — create the unified `credentials` table.
--
-- This migration is **schema-only**. It does NOT:
--   * copy data from `mfa_factors` or `user_factors`,
--   * change any reads or writes in the application,
--   * touch existing tables.
--
-- It adds a new table that the `CredentialProvider` adapters can later
-- dual-write to (Phase 2) and eventually read from (Phase 3) before the
-- old tables are dropped (Phase 4). Each phase is a separate ops event,
-- gated on production observability.
--
-- ─── Why this shape ─────────────────────────────────────────────────────────
--
-- The two legacy tables disagree on:
--   * id type/prefix (`mfa_*` vs UUID-style `uf_*`),
--   * tenancy column (`organization_id` vs `tenant_id`),
--   * payload location (dedicated `totp_secret` col vs `factor_data` JSONB),
--   * status model (`enabled`+`verified` flags vs `status` string).
--
-- The unified row reconciles these:
--   * `id`         — new prefix `cred_*`, generated fresh per row (legacy
--                    ids are kept verbatim in `legacy_factor_id` so audit
--                    rows referencing the old ids stay resolvable via JOIN).
--   * `tenant_id`  — single canonical column.
--   * `kind`       — closed enum string matching `FactorKind::as_str()` in
--                    the Rust trait (`totp|passkey|sms_otp|email_otp|`
--                    `backup_codes|password`).
--   * `status`     — closed enum (`pending|active|disabled`); replaces the
--                    `enabled`+`verified`+`status` triplet.
--   * `secret_ciphertext` — opaque encrypted bytes (TOTP seed, etc.).
--                    The wrapper key lives in `FactorEncryption`; this
--                    column never holds plaintext.
--   * `public_data` — JSONB for non-secret material (passkey public key,
--                    SMS last-4, backup code hashes).
--
-- ─── EIAA invariants preserved ──────────────────────────────────────────────
-- * No JWT shape change.
-- * Authorization decisions still flow through capsules; this table is
--   pure authentication input.
-- * Append-only audit: existing audit rows that reference legacy ids
--   continue to resolve via `legacy_factor_id`. This migration adds no
--   `DELETE` paths.
-- * CP/DP separation: rows are tenant-scoped (`tenant_id`) and protected
--   by RLS using the same `app.current_org_id` GUC convention as the rest
--   of the multi-tenant tables (see migration 005).
--
-- ─── Rollback ───────────────────────────────────────────────────────────────
-- Pure additive. Drop the table to revert (no application reads or writes
-- to it yet, so a drop is safe). See `rollback/053_unified_credentials.sql`.
-- ============================================================================

CREATE TABLE IF NOT EXISTS credentials (
    -- New surrogate id. Existing legacy rows are linked via legacy_factor_id.
    id                  TEXT        PRIMARY KEY,

    user_id             TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           TEXT        NOT NULL,

    -- Closed enum mirrored in Rust as `FactorKind`. CHECK constraint
    -- intentionally narrow — adding a kind requires a deliberate migration.
    kind                TEXT        NOT NULL
        CHECK (kind IN ('totp', 'passkey', 'sms_otp', 'email_otp', 'backup_codes', 'password')),

    -- Closed enum mirrored in Rust as `CredentialStatus`.
    status              TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'disabled')),

    -- Optional human label ("iPhone passkey", "YubiKey 5C").
    label               TEXT,

    -- Encrypted secret material. NULL for kinds that have no server-side
    -- secret (e.g. passkey, where only the public key is stored).
    --
    -- Stored as TEXT in the same `base64(nonce):base64(ciphertext)` format
    -- produced by `FactorEncryption::encrypt` (see
    -- api_server/src/services/factor_encryption.rs). This lets the backfill
    -- migration copy legacy ciphertext byte-for-byte without re-encrypting.
    secret_material     TEXT,

    -- Cipher metadata so we can rotate the wrapper key without ambiguity.
    -- 'aes-256-gcm-v1' for FactorEncryption::v1.
    cipher_alg          TEXT,

    -- Non-secret public material (passkey public key, SMS last-4, backup
    -- code hashes, TOTP algorithm/digits/period).
    public_data         JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- Lifecycle timestamps.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrolled_at         TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    disabled_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Cross-reference for the migration window. After Phase 4 these
    -- columns become historical-only.
    legacy_factor_id    TEXT,
    legacy_table        TEXT
        CHECK (legacy_table IS NULL OR legacy_table IN ('mfa_factors', 'user_factors'))
);

-- ─── Indexes ────────────────────────────────────────────────────────────────
-- Primary read path: "list active credentials for this user in this tenant".
CREATE INDEX IF NOT EXISTS idx_credentials_user_tenant
    ON credentials (user_id, tenant_id);

-- Filter on kind is common (e.g. "does this user have any passkey?").
CREATE INDEX IF NOT EXISTS idx_credentials_kind_active
    ON credentials (user_id, tenant_id, kind)
    WHERE status = 'active';

-- Tenant-wide scans (admin views).
CREATE INDEX IF NOT EXISTS idx_credentials_tenant
    ON credentials (tenant_id);

-- Fast JOIN-back from audit rows that reference legacy ids, AND idempotency
-- guard for the backfill in migration 054 (UNIQUE so re-runs are no-ops).
CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_legacy_factor_id
    ON credentials (legacy_factor_id)
    WHERE legacy_factor_id IS NOT NULL;

-- ─── Uniqueness ─────────────────────────────────────────────────────────────
-- A user may have multiple passkeys / multiple labelled TOTP secrets;
-- but only one *active* credential per (user, tenant, kind, label) tuple.
-- A NULL label is treated as a distinct value by Postgres in UNIQUE
-- indexes, which is exactly what we want for "default" entries.
CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_active_per_label
    ON credentials (user_id, tenant_id, kind, label)
    WHERE status = 'active';

-- ─── updated_at trigger (reuses helper from migration 017) ──────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_credentials_updated_at'
    ) THEN
        CREATE TRIGGER update_credentials_updated_at
            BEFORE UPDATE ON credentials
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- ─── Row-Level Security (matches the convention in migration 005) ───────────
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
-- FORCE so even superuser-owned connections must set the GUC. Keeps the
-- defense-in-depth identical to other tenant-scoped tables.
ALTER TABLE credentials FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'current_schema'::name AND tablename = 'credentials'
          AND policyname = 'credentials_tenant_isolation'
    ) THEN
        CREATE POLICY credentials_tenant_isolation ON credentials
            USING (tenant_id = current_setting('app.current_org_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true)::text);
    END IF;
END $$;

COMMENT ON TABLE credentials IS
    'Unified credential store (T1.6). Phase 1 — created but not yet read or written by application code. '
    'Targeted by the CredentialProvider trait in api_server. See doc-comment on services/credentials/mod.rs.';

COMMENT ON COLUMN credentials.legacy_factor_id IS
    'Original id from mfa_factors or user_factors during the unification window. NULL once Phase 4 completes.';

COMMENT ON COLUMN credentials.secret_material IS
    'Encrypted secret material in `base64(nonce):base64(ciphertext)` format produced by FactorEncryption. NEVER plaintext. NULL for kinds with no server-side secret (e.g. passkey).';
