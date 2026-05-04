-- T1.6 Phase 2.5 — Tenant-scope `passkey_credentials`
--
-- Background
-- ----------
-- The `passkey_credentials` table (migration 014) predates the multi-tenant
-- RLS work (migration 005) and never carried a `tenant_id` column. As a
-- result, a passkey enrolled by user U while operating in tenant A could
-- silently authenticate sessions for U in tenant B — the WebAuthn
-- `cred_id` lookup was tenant-blind. This violates the EIAA tenant-isolation
-- invariant that other authentication factors (`mfa_factors`, `user_factors`)
-- already honor.
--
-- This migration follows the same expand/migrate/contract pattern used by
-- `024_user_factors.sql` for the equivalent fix on `user_factors`:
--   1. Add `tenant_id` NULLABLE so the schema change is non-breaking
--   2. Backfill existing rows with the platform sentinel (`'platform'`)
--   3. Promote to NOT NULL
--   4. Index `(user_id, tenant_id)` for the hot-path lookup
--   5. Enable + FORCE Row-Level Security with the
--      `app.current_org_id`-based policy mirroring `credentials` (053)
--
-- Application code (PasskeyService) is updated in the same patch to thread
-- `tenant_id` through every read/write so the policy is satisfied.

ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);

UPDATE passkey_credentials
SET tenant_id = 'platform'
WHERE tenant_id IS NULL;

ALTER TABLE passkey_credentials
    ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_tenant
    ON passkey_credentials(user_id, tenant_id);

-- ─── Row-Level Security (mirrors `credentials` policy in 053) ────────────
ALTER TABLE passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'current_schema'::name
          AND tablename = 'passkey_credentials'
          AND policyname = 'passkey_credentials_tenant_isolation'
    ) THEN
        CREATE POLICY passkey_credentials_tenant_isolation ON passkey_credentials
            USING (tenant_id = current_setting('app.current_org_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true)::text);
    END IF;
END $$;

COMMENT ON COLUMN passkey_credentials.tenant_id IS
    'Tenant (organization) the passkey is bound to. Set at registration time '
    'from the authenticated session''s tenant_id. Pre-existing rows backfilled '
    'with the ''platform'' sentinel by migration 055.';
