-- Rollback for 054_backfill_credentials.sql
-- Removes only the rows inserted by the backfill (those with legacy_table set);
-- leaves any rows written natively to `credentials` (Phase 3+) intact.
DELETE FROM credentials
WHERE legacy_table IN ('mfa_factors', 'user_factors');
