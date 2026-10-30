-- Migration 083: Add created_by to eiaa_capsules
--
-- NFR-4 from Epic E2 (Policy Builder) requires every capsule deployment record
-- to carry the user ID of the deploying admin.  Previously this was only
-- captured in policy_builder_configs.activated_by and the audit log.
--
-- The column is nullable so existing rows are unaffected.

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(64);

COMMENT ON COLUMN eiaa_capsules.created_by IS
    'User ID of the admin who triggered this capsule compilation/deployment. '
    'NULL for capsules compiled before migration 083 or by system processes.';
