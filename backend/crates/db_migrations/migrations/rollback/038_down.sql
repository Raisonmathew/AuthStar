-- Rollback migration 038: API Keys Auth RLS
-- Restores the original single RLS policy from migration 037.

-- Drop the two policies added in 038
DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;
DROP POLICY IF EXISTS api_keys_auth_lookup ON api_keys;

-- Restore the original single policy from 037
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));
