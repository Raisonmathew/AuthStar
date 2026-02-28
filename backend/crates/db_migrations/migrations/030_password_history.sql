-- Migration 030: Password History Enforcement
--
-- HIGH-G: Prevent users from reusing their last N passwords.
-- Without this, a forced password rotation policy is trivially bypassed by
-- cycling back to the original password immediately.
--
-- Design:
--   - `password_history` stores the last PASSWORD_HISTORY_DEPTH (default 10) hashes per user.
--   - `change_password()` in user_service.rs checks all stored hashes with Argon2id
--     before accepting the new password.
--   - A trigger automatically prunes entries beyond the depth limit so the table
--     never grows unbounded.

-- ─── Password History Table ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_history (
    id              TEXT        PRIMARY KEY,
    user_id         TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient per-user history lookups (ordered by recency)
CREATE INDEX IF NOT EXISTS idx_password_history_user_created
    ON password_history (user_id, created_at DESC);

COMMENT ON TABLE password_history IS
    'Stores hashed previous passwords per user to enforce password reuse prevention. '
    'Only the last PASSWORD_HISTORY_DEPTH entries are retained per user.';

COMMENT ON COLUMN password_history.password_hash IS
    'Argon2id hash of a previously used password. Never stores plaintext.';

-- ─── RLS: Password history is private to each user ───────────────────────────
-- Tenants must not be able to read each other''s password history.
ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY password_history_tenant_isolation ON password_history
    USING (
        user_id IN (
            SELECT u.id FROM users u
            INNER JOIN identities i ON i.user_id = u.id
            WHERE i.organization_id = current_setting('app.current_org_id', true)
        )
    );

-- ─── Prune trigger: keep only the last 10 entries per user ───────────────────
-- This fires AFTER INSERT so the new row is already present when we prune.
CREATE OR REPLACE FUNCTION prune_password_history()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM password_history
    WHERE id IN (
        SELECT id FROM password_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        OFFSET 10  -- keep the 10 most recent; delete everything older
    );
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_prune_password_history ON password_history;
CREATE TRIGGER trg_prune_password_history
    AFTER INSERT ON password_history
    FOR EACH ROW EXECUTE FUNCTION prune_password_history();

-- ─── Backfill: seed history from current passwords table ─────────────────────
-- Existing users' current password hash is inserted as their first history entry
-- so that they cannot immediately reuse their current password after a forced reset.
INSERT INTO password_history (id, user_id, password_hash, created_at)
SELECT
    'hist_' || gen_random_uuid()::text,
    p.user_id,
    p.password_hash,
    p.created_at
FROM passwords p
ON CONFLICT DO NOTHING;

-- Made with Bob
