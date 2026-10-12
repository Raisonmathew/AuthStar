-- Migration 080: Unique active delegation per (tenant, user, agent)
--
-- BUG 3 FIX: Prevents a user from accumulating unlimited active delegation
-- grants for the same agent by enforcing that at most one non-revoked
-- delegation may exist per (tenant_id, user_id, agent_id) triple.
--
-- A partial unique index (WHERE revoked = FALSE) is used so that:
--   • Revoked delegations are preserved for audit history.
--   • A user may re-consent to the same agent after revoking a prior grant.
--   • The INSERT in consent.rs will fail with a unique-violation error (caught
--     as AppError::Conflict in the handler) rather than silently inserting a
--     duplicate row that the revocation UI would never surface.
--
-- Note: this is a forward-only migration. No rollback removes the constraint.

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_delegations_unique_active
    ON agent_delegations (tenant_id, user_id, agent_id)
    WHERE revoked = FALSE;
