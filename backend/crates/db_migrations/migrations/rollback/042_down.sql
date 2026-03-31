-- Rollback migration 042: Remove metadata from policy_builder_audit

ALTER TABLE policy_builder_audit DROP COLUMN IF EXISTS metadata;
