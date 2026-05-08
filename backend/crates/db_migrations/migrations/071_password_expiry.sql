-- Migration 071: Password expiry & forced rotation
--
-- Adds the columns needed to enforce `password_policies.max_age_days` and
-- `password_policies.force_rotation` at signin time:
--   * `passwords.password_changed_at` — set to NOW() on every successful change
--     (and backfilled from `created_at` for existing rows).
--   * `passwords.must_change` — set to TRUE by an admin to force rotation at
--     next login; cleared automatically when the user updates the password.
--
-- The `update_password` required action evaluator checks both columns against
-- the per-tenant `password_policies` row to surface a pending action whenever
-- the credential has expired or has been administratively flagged.

ALTER TABLE passwords
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE passwords
    ADD COLUMN IF NOT EXISTS must_change BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill: existing rows should not look "just changed" — preserve the
-- original creation time as the last-changed timestamp. NOW() default only
-- applies to brand-new rows because `password_changed_at` is already populated
-- here.
UPDATE passwords
SET password_changed_at = created_at
WHERE password_changed_at >= NOW() - INTERVAL '1 minute'
  AND created_at < NOW() - INTERVAL '1 minute';

-- Index helps the required-action evaluator's age check on large tenants.
CREATE INDEX IF NOT EXISTS idx_passwords_changed_at
    ON passwords (password_changed_at);
