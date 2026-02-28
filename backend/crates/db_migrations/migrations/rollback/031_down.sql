-- Rollback: 031_flow_expiry_10min.sql
-- Reverts the expires_at default back to 5 minutes and drops the cleanup index.

DROP INDEX IF EXISTS idx_flows_expired_incomplete;

ALTER TABLE hosted_auth_flows
    ALTER COLUMN expires_at SET DEFAULT NOW() + INTERVAL '5 minutes';

-- Made with Bob
