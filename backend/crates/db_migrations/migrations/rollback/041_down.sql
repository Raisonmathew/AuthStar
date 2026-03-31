-- Rollback migration 041: Remove actor_ip from policy_builder_audit

ALTER TABLE policy_builder_audit DROP COLUMN IF EXISTS actor_ip;
