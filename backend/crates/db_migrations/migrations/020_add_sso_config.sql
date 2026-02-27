-- Add config column to sso_connections for provider-specific settings (e.g. SAML metadata, certs)
ALTER TABLE sso_connections ADD COLUMN config JSONB;
