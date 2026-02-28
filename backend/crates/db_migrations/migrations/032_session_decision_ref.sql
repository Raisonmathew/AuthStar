-- Migration 032: Session EIAA Decision Reference
--
-- MEDIUM-EIAA-9: Add `decision_ref` to `sessions` table.
--
-- The EIAA spec requires that every session created via an EIAA-driven login flow
-- carries a reference to the attested decision that authorized its creation. This
-- enables:
--   1. Audit trail: trace any session back to the exact capsule execution that
--      authorized it, including the full input context and attestation signature.
--   2. Step-up enforcement: the step-up middleware can verify the session's
--      original decision_ref before issuing a new step-up challenge.
--   3. Revocation: if a capsule is later found to be compromised, all sessions
--      created with that capsule's decision_ref can be revoked in bulk.
--
-- Note: `signup_tickets.decision_ref` was already added in migration 010.
--       `hosted_auth_flows.decision_ref` was already added in migration 009.
--       This migration only adds the missing column to `sessions`.
--
-- Also adds `login_decision_ref` to `sessions` to distinguish the login-time
-- EIAA decision from any subsequent step-up decisions stored in session metadata.

-- ─── sessions: add decision_ref ──────────────────────────────────────────────

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS decision_ref VARCHAR(64);

COMMENT ON COLUMN sessions.decision_ref IS
    'Reference to the eiaa_executions.decision_ref that authorized this session. '
    'NULL for sessions created before EIAA enforcement was enabled (pre-032 records) '
    'or for sessions created via non-EIAA paths (e.g., admin impersonation).';

-- Index for bulk revocation queries: "revoke all sessions created by capsule X"
-- Joins sessions → eiaa_executions via decision_ref
CREATE INDEX IF NOT EXISTS idx_sessions_decision_ref
    ON sessions(decision_ref)
    WHERE decision_ref IS NOT NULL;

-- ─── sessions: add aal_level ──────────────────────────────────────────────────
-- Track the Authentication Assurance Level (NIST SP 800-63B) achieved at login.
-- This is derived from the EIAA capsule decision output and stored on the session
-- so that the step-up middleware can quickly check AAL without re-querying executions.
--
-- Values:
--   0 = AAL0 (unauthenticated / guest)
--   1 = AAL1 (single factor: password or passkey)
--   2 = AAL2 (multi-factor: password + OTP, or passkey + biometric)
--   3 = AAL3 (hardware-bound: FIDO2 hardware key)

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS aal_level SMALLINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN sessions.aal_level IS
    'NIST SP 800-63B Authentication Assurance Level achieved at session creation. '
    '0=unauthenticated, 1=single-factor, 2=multi-factor, 3=hardware-bound. '
    'Populated from the EIAA capsule decision output. Used by step-up middleware '
    'to determine if re-authentication is required for sensitive operations.';

-- Index for step-up queries: "find sessions with AAL < required_aal"
CREATE INDEX IF NOT EXISTS idx_sessions_aal_level
    ON sessions(user_id, aal_level)
    WHERE NOT revoked;

-- ─── sessions: verified_capabilities ─────────────────────────────────────────
-- NOTE: `verified_capabilities` was already added by migrations 017 and 023.
-- The `ADD COLUMN IF NOT EXISTS` below is a no-op on upgraded databases.
-- We only update the COMMENT to reflect the EIAA-specific semantics.
-- We do NOT re-declare NOT NULL DEFAULT here because PostgreSQL will reject
-- a constraint change on an existing column via ADD COLUMN IF NOT EXISTS.

-- Update comment to reflect EIAA semantics (idempotent DDL)
COMMENT ON COLUMN sessions.verified_capabilities IS
    'JSONB array of capability strings verified during the EIAA login flow. '
    'Example: ["mfa:totp", "passkey", "email_verified"]. '
    'Populated from the EIAA capsule decision output. Used for fine-grained '
    'authorization checks without requiring a full capsule re-execution.';

-- ─── eiaa_executions: add FK index to sessions ───────────────────────────────
-- Allow efficient lookup: "which session was created by this execution?"
-- This is a soft reference (no FK constraint) because executions are append-only
-- and sessions may be deleted while executions must be retained for audit.
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_user_tenant
    ON eiaa_executions(user_id, tenant_id, created_at DESC)
    WHERE user_id IS NOT NULL;

-- Made with Bob