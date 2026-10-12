-- 065_down.sql — Rollback skip_tls_verify column on ldap_connections
ALTER TABLE ldap_connections DROP COLUMN IF EXISTS skip_tls_verify;
