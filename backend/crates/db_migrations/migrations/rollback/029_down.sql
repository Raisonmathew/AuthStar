-- Rollback: 029_security_fixes.sql
-- Reverts all security fixes in reverse order of application.
-- WARNING: Some changes (e.g. nulling private_key_DEPRECATED) are NOT reversible
-- without a backup. This script reverts schema changes only.

-- ─── Revert MEDIUM-11: risk_states unique constraint ─────────────────────────
ALTER TABLE risk_states
    DROP CONSTRAINT IF EXISTS risk_states_org_subject_signal_unique;

-- Restore the old (non-tenant-scoped) unique constraint
ALTER TABLE risk_states
    ADD CONSTRAINT risk_states_subject_type_subject_id_signal_type_key
    UNIQUE (subject_type, subject_id, signal_type);

-- ─── Revert MEDIUM-10: cleanup function ──────────────────────────────────────
DROP FUNCTION IF EXISTS cleanup_expired_records();

-- ─── Revert HIGH-14: jwks_keys private_key rename ────────────────────────────
-- NOTE: Private key values are NOT restored (they were nulled for security).
-- Rename the column back to private_key.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'jwks_keys' AND column_name = 'private_key_deprecated'
    ) THEN
        ALTER TABLE jwks_keys RENAME COLUMN private_key_DEPRECATED TO private_key;
    END IF;
END $$;

-- ─── Revert HIGH-13: RLS on signup_tickets ───────────────────────────────────
DROP POLICY IF EXISTS signup_ticket_org_isolation ON signup_tickets;
ALTER TABLE signup_tickets DISABLE ROW LEVEL SECURITY;
ALTER TABLE signup_tickets ALTER COLUMN organization_id DROP NOT NULL;
-- Note: We do NOT drop the organization_id column to avoid data loss.
-- If you need to drop it: ALTER TABLE signup_tickets DROP COLUMN IF EXISTS organization_id;

-- ─── Revert HIGH-6: identities multi-tenancy ─────────────────────────────────
DROP POLICY IF EXISTS identity_org_isolation ON identities;

ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS identities_org_type_identifier_unique;

-- Restore the old global unique constraint
ALTER TABLE identities
    ADD CONSTRAINT identities_type_identifier_key
    UNIQUE (type, identifier);

-- Note: We do NOT drop organization_id from identities to avoid data loss.
-- If you need to drop it: ALTER TABLE identities DROP COLUMN IF EXISTS organization_id;

-- ─── Revert HIGH-1: account lockout fields ───────────────────────────────────
DROP INDEX IF EXISTS idx_users_locked;

ALTER TABLE users
    DROP COLUMN IF EXISTS failed_login_attempts,
    DROP COLUMN IF EXISTS locked,
    DROP COLUMN IF EXISTS locked_at,
    DROP COLUMN IF EXISTS last_login_at;

-- ─── Revert CRITICAL-8: stripe_webhook_events ────────────────────────────────
DROP INDEX IF EXISTS idx_stripe_webhook_events_status;
DROP TABLE IF EXISTS stripe_webhook_events;

-- ─── Revert CRITICAL-2: TOTP replay protection ───────────────────────────────
ALTER TABLE mfa_factors
    DROP COLUMN IF EXISTS totp_last_used_at;

-- Made with Bob
