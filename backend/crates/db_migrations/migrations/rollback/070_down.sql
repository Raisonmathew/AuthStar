-- 070_down.sql — Rollback OAuth 2.0 / OIDC parity gaps
-- Removes token_kind column from oauth_refresh_tokens and
-- JWT client auth columns from applications.

ALTER TABLE oauth_refresh_tokens
    DROP COLUMN IF EXISTS token_kind;

ALTER TABLE applications
    DROP COLUMN IF EXISTS token_endpoint_auth_method,
    DROP COLUMN IF EXISTS jwks_uri,
    DROP COLUMN IF EXISTS jwks;

DROP INDEX IF EXISTS idx_oauth_rt_kind;
