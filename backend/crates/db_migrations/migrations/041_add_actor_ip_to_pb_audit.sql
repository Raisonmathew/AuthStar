-- Add missing actor_ip column to policy_builder_audit
-- The 040 migration skipped creating the table because it already existed from 039,
-- but the new column was expected by api_server.

ALTER TABLE policy_builder_audit
ADD COLUMN IF NOT EXISTS actor_ip VARCHAR(50);
