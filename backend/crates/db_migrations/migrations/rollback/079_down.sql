-- Rollback 079: Remove archived_at column and its index
DROP INDEX IF EXISTS idx_eiaa_capsules_compliance_timetravel;
ALTER TABLE eiaa_capsules DROP COLUMN IF EXISTS archived_at;
