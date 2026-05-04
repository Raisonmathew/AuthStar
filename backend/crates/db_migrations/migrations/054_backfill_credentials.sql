-- ============================================================================
-- 054_backfill_credentials.sql
-- ----------------------------------------------------------------------------
-- T1.6 Phase 2 (MIGRATE) — copy data from `mfa_factors` and `user_factors`
-- into the unified `credentials` table created in migration 053.
--
-- ## Authorisation context
--
-- Run by user request: target environment is **test data only**, so a
-- one-shot backfill is acceptable in lieu of an expand/dual-write/contract
-- rollout. For a production environment this would be split into separate
-- ops events with observability between each phase.
--
-- ## Safety properties
--
-- * **Idempotent.** Inserts are gated on `legacy_factor_id` via the partial
--   UNIQUE index `uq_credentials_legacy_factor_id`. Re-running the migration
--   is a no-op (`ON CONFLICT … DO NOTHING`).
-- * **Non-destructive.** Legacy tables (`mfa_factors`, `user_factors`) are
--   NOT touched. They remain the source of truth until Phase 3 (read-switch)
--   and Phase 4 (drop) are executed in subsequent migrations.
-- * **Audit-link preserving.** Every new row carries the original id in
--   `legacy_factor_id` so existing audit rows referencing the legacy id stay
--   joinable.
-- * **Encryption preserving.** The `secret_material` column is `TEXT` and
--   uses the same `base64(nonce):base64(ciphertext)` layout produced by
--   `FactorEncryption::encrypt`, so legacy ciphertext is copied verbatim
--   without re-encryption (and without ever decrypting).
--
-- ## Mapping rules
--
-- ### `mfa_factors` → `credentials`
-- | source                       | target                                  |
-- |------------------------------|-----------------------------------------|
-- | `id`                         | `legacy_factor_id` (`legacy_table` = 'mfa_factors') |
-- | `generate_prefixed_id('cred')`| `id`                                   |
-- | `user_id`                    | `user_id`                               |
-- | `COALESCE(organization_id, 'platform')` | `tenant_id`                  |
-- | `type` mapped: 'totp'→'totp', 'sms'→'sms_otp', 'backup_codes'→'backup_codes' | `kind` |
-- | `verified` + `enabled`       | `status` (see CASE below)               |
-- | `totp_secret`                | `secret_material` (TEXT, opaque)        |
-- | `totp_algorithm`, `backup_codes` | `public_data` (JSONB)               |
-- | `created_at`                 | `created_at`                            |
-- | `verified_at`                | `verified_at`, `enrolled_at`            |
-- | `totp_last_used_at`          | `last_used_at`                          |
--
-- ### `user_factors` → `credentials`
-- | source                       | target                                  |
-- |------------------------------|-----------------------------------------|
-- | `id`                         | `legacy_factor_id` (`legacy_table` = 'user_factors') |
-- | `generate_prefixed_id('cred')`| `id`                                   |
-- | `user_id`, `tenant_id`       | `user_id`, `tenant_id`                  |
-- | `factor_type` mapped: 'totp'→'totp', 'passkey'→'passkey', 'sms'→'sms_otp', 'email'→'email_otp', 'password'→'password' | `kind` |
-- | `status` mapped: 'active'/'pending'/'disabled'; if `disabled_at IS NOT NULL` → 'disabled' | `status` |
-- | `factor_data->>'secret'`     | `secret_material`                       |
-- | `factor_data` minus `secret` | `public_data`                           |
-- | `created_at`, `enrolled_at`, `last_used_at`, `disabled_at` | same      |
--
-- Rows whose `factor_type` is not in the closed enum (legacy debris) are
-- skipped via the inner `WHERE` clause so the CHECK constraint never fires.
-- ============================================================================

-- ─── mfa_factors backfill ───────────────────────────────────────────────────
INSERT INTO credentials (
    id, user_id, tenant_id, kind, status, label,
    secret_material, cipher_alg, public_data,
    created_at, enrolled_at, verified_at, last_used_at, disabled_at,
    legacy_factor_id, legacy_table
)
SELECT
    generate_prefixed_id('cred'),
    m.user_id,
    COALESCE(m.organization_id, 'platform'),
    CASE m.type
        WHEN 'totp'         THEN 'totp'
        WHEN 'sms'          THEN 'sms_otp'
        WHEN 'backup_codes' THEN 'backup_codes'
    END                                                         AS kind,
    CASE
        WHEN m.enabled  AND m.verified THEN 'active'
        WHEN m.verified                THEN 'active'   -- pre-enable verified
        WHEN m.enabled                 THEN 'pending'  -- enabled but not verified yet
        ELSE 'pending'
    END                                                         AS status,
    NULL                                                        AS label,
    -- TOTP secret is already encrypted ciphertext text in legacy schema.
    -- Copy verbatim. NULL for non-TOTP rows.
    CASE WHEN m.type = 'totp' THEN m.totp_secret END            AS secret_material,
    CASE WHEN m.type = 'totp' AND m.totp_secret IS NOT NULL
         THEN 'aes-256-gcm-v1' END                              AS cipher_alg,
    -- Carry forward non-secret material into public_data.
    jsonb_strip_nulls(jsonb_build_object(
        'algorithm',    m.totp_algorithm,
        'backup_codes', m.backup_codes
    ))                                                          AS public_data,
    m.created_at,
    m.verified_at                                               AS enrolled_at,
    m.verified_at,
    m.totp_last_used_at,
    NULL                                                        AS disabled_at,
    m.id                                                        AS legacy_factor_id,
    'mfa_factors'                                               AS legacy_table
FROM mfa_factors m
WHERE m.type IN ('totp', 'sms', 'backup_codes')
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = m.user_id)
ON CONFLICT DO NOTHING;

-- ─── user_factors backfill ──────────────────────────────────────────────────
INSERT INTO credentials (
    id, user_id, tenant_id, kind, status, label,
    secret_material, cipher_alg, public_data,
    created_at, enrolled_at, verified_at, last_used_at, disabled_at,
    legacy_factor_id, legacy_table
)
SELECT
    generate_prefixed_id('cred'),
    f.user_id,
    f.tenant_id,
    CASE f.factor_type
        WHEN 'totp'     THEN 'totp'
        WHEN 'passkey'  THEN 'passkey'
        WHEN 'sms'      THEN 'sms_otp'
        WHEN 'email'    THEN 'email_otp'
        WHEN 'password' THEN 'password'
    END                                                         AS kind,
    CASE
        WHEN f.disabled_at IS NOT NULL                           THEN 'disabled'
        WHEN f.status IN ('active', 'pending', 'disabled')       THEN f.status
        WHEN f.verified                                          THEN 'active'
        ELSE 'pending'
    END                                                         AS status,
    NULL                                                        AS label,
    -- factor_data may store the encrypted secret under a 'secret' key
    -- (UserFactorService writes it that way for TOTP enrollment).
    NULLIF(f.factor_data ->> 'secret', '')                      AS secret_material,
    CASE WHEN NULLIF(f.factor_data ->> 'secret', '') IS NOT NULL
         THEN 'aes-256-gcm-v1' END                              AS cipher_alg,
    -- Public data = factor_data with the secret stripped.
    COALESCE(f.factor_data, '{}'::jsonb) - 'secret'             AS public_data,
    f.created_at,
    f.enrolled_at,
    CASE WHEN f.verified THEN f.enrolled_at END                 AS verified_at,
    f.last_used_at,
    f.disabled_at,
    f.id                                                        AS legacy_factor_id,
    'user_factors'                                              AS legacy_table
FROM user_factors f
WHERE f.factor_type IN ('totp', 'passkey', 'sms', 'email', 'password')
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = f.user_id)
ON CONFLICT (legacy_factor_id) WHERE legacy_factor_id IS NOT NULL DO NOTHING;

-- ─── Sanity counts (logged via psql NOTICE) ─────────────────────────────────
DO $$
DECLARE
    v_total       INTEGER;
    v_from_mfa    INTEGER;
    v_from_uf     INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_total      FROM credentials;
    SELECT COUNT(*) INTO v_from_mfa   FROM credentials WHERE legacy_table = 'mfa_factors';
    SELECT COUNT(*) INTO v_from_uf    FROM credentials WHERE legacy_table = 'user_factors';
    RAISE NOTICE 'credentials backfill complete: total=% from_mfa=% from_user_factors=%',
        v_total, v_from_mfa, v_from_uf;
END $$;
