-- Migration 029: Security Fixes
-- Addresses all critical and high severity database-level issues identified in the gap analysis.
--
-- Changes:
--   CRITICAL-2:  Add totp_last_used_at to mfa_factors for TOTP replay protection
--   CRITICAL-8:  Create stripe_webhook_events table for idempotency
--   HIGH-1:      Add failed_login_attempts, locked, locked_at, last_login_at to users
--   HIGH-6:      Add organization_id to identities; fix global unique constraint
--   HIGH-13:     Add RLS to signup_tickets
--   HIGH-14:     Remove private_key from jwks_keys (keys stored in env/keystore only)
--   MEDIUM-11:   Fix risk_states unique constraint to include org_id

-- ─── CRITICAL-2: TOTP Replay Protection ──────────────────────────────────────
-- Track the last time a TOTP code was successfully used.
-- verify_totp() checks this to prevent reuse within the same 30-second window.
ALTER TABLE mfa_factors
    ADD COLUMN IF NOT EXISTS totp_last_used_at TIMESTAMPTZ;

COMMENT ON COLUMN mfa_factors.totp_last_used_at IS
    'Timestamp of the last successfully verified TOTP code. Used to prevent replay attacks '
    'within the same 30-second window (RFC 6238 requirement).';

-- ─── CRITICAL-8: Stripe Webhook Idempotency ──────────────────────────────────
-- Stores processed Stripe event IDs to prevent duplicate processing.
-- Stripe guarantees at-least-once delivery; this table ensures exactly-once processing.
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    event_id        TEXT        PRIMARY KEY,
    event_type      TEXT        NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at    TIMESTAMPTZ,
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'processed', 'failed')),
    error           TEXT,       -- Error message if status = 'failed'
    CONSTRAINT stripe_webhook_events_event_id_unique UNIQUE (event_id)
);

-- Index for querying failed events for retry/investigation
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_status
    ON stripe_webhook_events (status)
    WHERE status != 'processed';

-- Auto-cleanup: delete processed events older than 90 days
-- (Stripe's idempotency window is 24 hours; 90 days is very conservative)
COMMENT ON TABLE stripe_webhook_events IS
    'Idempotency log for Stripe webhook events. Prevents duplicate processing on retry delivery.';

-- ─── HIGH-1: Account Lockout Fields ──────────────────────────────────────────
-- Track failed login attempts and account lock state.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_attempts  INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked                 BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS locked_at              TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_login_at          TIMESTAMPTZ;

COMMENT ON COLUMN users.failed_login_attempts IS
    'Consecutive failed password attempts. Reset to 0 on successful login.';
COMMENT ON COLUMN users.locked IS
    'Account is locked after too many failed login attempts. Requires admin unlock.';
COMMENT ON COLUMN users.locked_at IS
    'Timestamp when the account was locked.';

-- Index for admin queries on locked accounts
CREATE INDEX IF NOT EXISTS idx_users_locked ON users (locked) WHERE locked = true;

-- ─── HIGH-6: Fix identities Multi-Tenancy ────────────────────────────────────
-- The identities table was missing organization_id, causing a global unique constraint
-- on (type, identifier) that prevented two tenants from having users with the same email.

-- Step 1: Add organization_id column
ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE;

-- Step 2: Backfill organization_id from the users table
-- (identities.user_id → users.organization_id)
UPDATE identities i
SET organization_id = u.organization_id
FROM users u
WHERE i.user_id = u.id
  AND i.organization_id IS NULL
  AND u.organization_id IS NOT NULL;

-- Step 3: Drop the old global unique constraint (if it exists)
-- The constraint name may vary; we drop by the most common names.
DO $$
BEGIN
    -- Drop global unique constraint on (type, identifier) if it exists
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'identities_type_identifier_key'
          AND conrelid = 'identities'::regclass
    ) THEN
        ALTER TABLE identities DROP CONSTRAINT identities_type_identifier_key;
    END IF;

    -- Also drop any variant names
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'identities_identifier_type_unique'
          AND conrelid = 'identities'::regclass
    ) THEN
        ALTER TABLE identities DROP CONSTRAINT identities_identifier_type_unique;
    END IF;
END $$;

-- Step 4: Add the correct per-tenant unique constraint
-- Two tenants CAN have users with the same email; within a tenant they cannot.
ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS identities_org_type_identifier_unique;

ALTER TABLE identities
    ADD CONSTRAINT identities_org_type_identifier_unique
    UNIQUE (organization_id, type, identifier);

-- Step 5: Update RLS policy on identities to use organization_id directly
-- (Previously it used a correlated subquery through users, which was fragile)
DROP POLICY IF EXISTS identity_org_isolation ON identities;

CREATE POLICY identity_org_isolation ON identities
    USING (organization_id = current_setting('app.current_org_id', true)::text);

COMMENT ON COLUMN identities.organization_id IS
    'Tenant scoping column. Required for multi-tenant unique constraint and RLS.';

-- ─── HIGH-13: RLS on signup_tickets ──────────────────────────────────────────
-- signup_tickets had no RLS, meaning all tenants could see each other's pending signups.

-- Ensure organization_id exists on signup_tickets
ALTER TABLE signup_tickets
    ADD COLUMN IF NOT EXISTS organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE;

-- Enable RLS
ALTER TABLE signup_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_tickets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS signup_ticket_org_isolation ON signup_tickets;

CREATE POLICY signup_ticket_org_isolation ON signup_tickets
    USING (organization_id = current_setting('app.current_org_id', true)::text);

-- ─── HIGH-14: Remove private keys from jwks_keys ─────────────────────────────
-- JWT signing private keys must NEVER be stored in the database.
-- They are loaded from environment variables or a secrets manager at startup.
-- We rename the column to make it clear it's deprecated, then null it out.
-- The application code (keystore crate) reads keys from env, not from this table.

-- Rename private_key to private_key_DEPRECATED to make the intent clear
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'jwks_keys' AND column_name = 'private_key'
    ) THEN
        ALTER TABLE jwks_keys RENAME COLUMN private_key TO private_key_DEPRECATED;
        -- Null out all existing private keys — they should be in env/vault
        UPDATE jwks_keys SET private_key_DEPRECATED = NULL;
        -- Add a comment explaining why
        COMMENT ON COLUMN jwks_keys.private_key_DEPRECATED IS
            'DEPRECATED: Private keys are no longer stored in the database. '
            'They are loaded from JWKS_PRIVATE_KEY_* environment variables or a secrets manager. '
            'This column is kept for schema compatibility but is always NULL.';
    END IF;
END $$;

-- ─── MEDIUM-11: Fix risk_states Unique Constraint ────────────────────────────
-- The unique constraint was not scoped by org_id, causing cross-tenant conflicts.

DO $$
BEGIN
    -- Drop the old non-tenant-scoped constraint
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'risk_states_subject_type_subject_id_signal_type_key'
          AND conrelid = 'risk_states'::regclass
    ) THEN
        ALTER TABLE risk_states DROP CONSTRAINT risk_states_subject_type_subject_id_signal_type_key;
    END IF;
END $$;

-- Add the correct tenant-scoped unique constraint
ALTER TABLE risk_states
    DROP CONSTRAINT IF EXISTS risk_states_org_subject_signal_unique;

ALTER TABLE risk_states
    ADD CONSTRAINT risk_states_org_subject_signal_unique
    UNIQUE (org_id, subject_type, subject_id, signal_type);

-- ─── MEDIUM-10: Cleanup jobs for expired records ──────────────────────────────
-- Create a function that can be called by a cron job or pg_cron to clean up
-- expired records that accumulate over time.

CREATE OR REPLACE FUNCTION cleanup_expired_records() RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    -- Delete expired signup tickets (15-minute TTL)
    DELETE FROM signup_tickets
    WHERE expires_at < NOW() - INTERVAL '1 hour';

    -- Delete expired verification tokens (10-minute TTL)
    DELETE FROM verification_tokens
    WHERE expires_at < NOW() - INTERVAL '1 hour';

    -- Delete expired hosted auth flows (5-minute TTL)
    DELETE FROM hosted_auth_flows
    WHERE expires_at < NOW() - INTERVAL '1 hour';

    -- Delete expired sessions (30-day TTL)
    DELETE FROM sessions
    WHERE expires_at < NOW();

    -- Delete old processed webhook events (keep 90 days for audit)
    DELETE FROM stripe_webhook_events
    WHERE status = 'processed'
      AND processed_at < NOW() - INTERVAL '90 days';

    RAISE NOTICE 'cleanup_expired_records completed at %', NOW();
END;
$$;

COMMENT ON FUNCTION cleanup_expired_records() IS
    'Cleanup function for expired records. Call periodically via pg_cron or a Tokio background task. '
    'Example pg_cron schedule: SELECT cron.schedule(''cleanup-expired'', ''*/15 * * * *'', ''SELECT cleanup_expired_records()'');';

-- Made with Bob
