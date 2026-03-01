-- Rollback migration 035: Backfill capsule bytes infrastructure
-- WARNING: This drops the backfill tracking column and all associated objects.
-- Any backfill progress data will be lost.

DROP FUNCTION IF EXISTS capsule_backfill_summary();
DROP FUNCTION IF EXISTS mark_capsule_backfill_failed(TEXT, TEXT);
DROP FUNCTION IF EXISTS mark_capsule_backfill_complete(TEXT, BYTEA, BYTEA);
DROP FUNCTION IF EXISTS get_capsules_for_backfill(INT);
DROP VIEW IF EXISTS eiaa_capsules_backfill_needed;
DROP TABLE IF EXISTS eiaa_capsule_backfill_errors;
DROP INDEX IF EXISTS idx_eiaa_capsules_backfill_pending;

ALTER TABLE eiaa_capsules
    DROP COLUMN IF EXISTS backfill_status;