-- Rollback for 055_passkey_credentials_tenant_scope.sql
DROP POLICY IF EXISTS passkey_credentials_tenant_isolation ON passkey_credentials;
ALTER TABLE passkey_credentials NO FORCE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials DISABLE ROW LEVEL SECURITY;
DROP INDEX IF EXISTS idx_passkey_credentials_user_tenant;
ALTER TABLE passkey_credentials DROP COLUMN IF EXISTS tenant_id;
