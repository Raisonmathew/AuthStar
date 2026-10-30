-- Rollback for 083_eiaa_capsules_created_by.sql
ALTER TABLE eiaa_capsules DROP COLUMN IF EXISTS created_by;
