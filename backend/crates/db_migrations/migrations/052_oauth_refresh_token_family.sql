-- T1.3 — OAuth refresh token: explicit family_id + replaced_by chain integrity
--
-- Background
-- ----------
-- OAuth 2.0 RFC 6749 §6 + RFC 6819 §5.2.2.3 mandate refresh-token rotation
-- with reuse detection. The original schema (migration 046) tracked rotation
-- *implicitly* by the (client_id, user_id, tenant_id) composite — meaning a
-- detected reuse on device A would revoke device B's still-valid tokens too
-- (over-revocation; bad UX, audit noise).
--
-- This migration introduces an *explicit* family_id chain, where every refresh
-- token carries the id of its family root. Reuse detection now revokes only
-- the affected family, leaving sibling sessions on other devices untouched.
--
-- Invariant enforced
-- ------------------
--   "At most one ACTIVE refresh token per family at any time"
--
-- via a partial UNIQUE index. Rotation MUST therefore be transactional:
-- revoke the old row, then insert the new row in the same family, in one txn.
--
-- Backfill semantics
-- ------------------
-- Existing rows are treated as their own family root (family_id = id). This
-- preserves current behaviour for in-flight tokens and never widens any
-- session's blast radius.

BEGIN;

-- 1. Add family_id, nullable initially so we can backfill safely.
ALTER TABLE oauth_refresh_tokens
    ADD COLUMN IF NOT EXISTS family_id TEXT;

-- 2. Backfill: every existing row is its own family root.
UPDATE oauth_refresh_tokens
   SET family_id = id
 WHERE family_id IS NULL;

-- 3. Lock it down.
ALTER TABLE oauth_refresh_tokens
    ALTER COLUMN family_id SET NOT NULL;

-- 4. Indexes.
--   (a) Fast lookup of active tokens by family — used by reuse detection
--       and explicit family revocation.
CREATE INDEX IF NOT EXISTS idx_oauth_rt_family_active
    ON oauth_refresh_tokens(family_id)
    WHERE revoked_at IS NULL;

--   (b) Whole-family scan (for audit / cleanup).
CREATE INDEX IF NOT EXISTS idx_oauth_rt_family
    ON oauth_refresh_tokens(family_id);

--   (c) Single-active-token-per-family invariant. Partial UNIQUE so revoked
--       rows are exempt — historical chain entries stay queryable for audit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_rt_family_one_active
    ON oauth_refresh_tokens(family_id)
    WHERE revoked_at IS NULL;

-- 5. Documentation.
COMMENT ON COLUMN oauth_refresh_tokens.family_id IS
    'Refresh-token family root id. All tokens issued via rotation from a single auth-code grant share one family_id. On detected reuse, ONLY this family is revoked (RFC 6819 §5.2.2.3).';

COMMENT ON COLUMN oauth_refresh_tokens.replaced_by IS
    'Id of the token that succeeded this one in the rotation chain. NULL on the chain head (current active token) and on revoked-without-rotation tokens.';

COMMIT;
