-- 071_down.sql — Rollback password expiry columns
ALTER TABLE passwords
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS must_change;

DROP INDEX IF EXISTS idx_passwords_changed_at;
