-- Migration 034: Flow Expiry Hardening
--
-- RENAMED from 031_flow_expiry_10min.sql to resolve migration prefix collision.
-- The original file shared the '031_' prefix with 031_eiaa_storage_columns.sql and
-- 031_reconcile_eiaa_schema.sql (now 033), causing non-deterministic execution order.
--
-- This migration is intentionally placed AFTER the EIAA schema reconciliation (033)
-- because hosted_auth_flows.decision_ref (added in 033 via signup_tickets backfill)
-- must exist before we add the expiry index on hosted_auth_flows.
--
-- C-1: Flow Expiry Hardening
--
-- 1. Change the default expires_at from 5 minutes to 10 minutes.
--    The original 5-minute window was too short for MFA flows where the user
--    needs to retrieve an email OTP, open an authenticator app, or complete
--    a passkey ceremony — all of which can take several minutes.
--
-- 2. Add a partial index on (expires_at) WHERE NOT completed to speed up
--    the background cleanup query that purges expired incomplete flows.
--
-- 3. The eiaa_flow_service.rs store_flow_context() now uses an UPSERT with
--    expires_at = NOW() + INTERVAL '10 minutes' on INSERT, and the UPDATE
--    branch includes AND expires_at > NOW() to prevent writes to expired flows.

-- Change default for new rows
ALTER TABLE hosted_auth_flows
    ALTER COLUMN expires_at SET DEFAULT NOW() + INTERVAL '10 minutes';

-- Index for efficient cleanup of expired incomplete flows
-- (used by a periodic job: DELETE FROM hosted_auth_flows WHERE expires_at < NOW() AND NOT completed)
CREATE INDEX IF NOT EXISTS idx_flows_expired_incomplete
    ON hosted_auth_flows (expires_at)
    WHERE NOT completed;

COMMENT ON COLUMN hosted_auth_flows.expires_at IS
    'Flow expiry timestamp. Default 10 minutes from creation. '
    'Flows past this timestamp return FLOW_EXPIRED (HTTP 410) to the client. '
    'The eiaa_flow_service enforces this at the application layer via load_flow_context().';

-- Made with Bob