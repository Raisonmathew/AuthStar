-- Migration 065: Add skip_tls_verify column to ldap_connections
-- Allows connecting to LDAP servers with self-signed or untrusted certificates.
-- SECURITY NOTE: Only enable this for internal/dev LDAP servers where you
-- control the certificate. Never use in production with public LDAP endpoints.

ALTER TABLE ldap_connections
    ADD COLUMN IF NOT EXISTS skip_tls_verify BOOLEAN NOT NULL DEFAULT false;
