-- Migration 070: OAuth 2.0 / OIDC parity gaps
--
-- Covers:
--   1. Offline tokens — token_kind column in oauth_refresh_tokens
--   2. JWT client authentication — token_endpoint_auth_method + jwks_uri on applications
--      (private_key_jwt, client_secret_jwt per RFC 7523)
--   3. Dynamic Client Registration (RFC 7591) — is_dynamic + registration_access_token_hash
--      + hmac_secret_b64 (raw secret for client_secret_jwt HMAC verification)
--   4. response_mode stored on authorization context — handled in Redis (no schema change)

-- ─── 1. Offline tokens ──────────────────────────────────────────────────────────
-- Distinguishes session-bound ("online") from long-lived ("offline") refresh tokens.
-- offline = issued when offline_access scope is requested; survives session expiry.

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN IF NOT EXISTS token_kind VARCHAR(16) NOT NULL DEFAULT 'online';

COMMENT ON COLUMN oauth_refresh_tokens.token_kind IS
    'online = session-bound; offline = long-lived (issued for offline_access scope)';

CREATE INDEX IF NOT EXISTS idx_oauth_rt_kind
    ON oauth_refresh_tokens(user_id, client_id, token_kind)
    WHERE revoked_at IS NULL;

-- ─── 2. JWT client authentication ───────────────────────────────────────────────
-- token_endpoint_auth_method declares how a client authenticates at /oauth/token.
-- Allowed values: client_secret_post (default), client_secret_basic,
--                 private_key_jwt, client_secret_jwt, none

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(64) NOT NULL DEFAULT 'client_secret_post';

COMMENT ON COLUMN applications.token_endpoint_auth_method IS
    'RFC 7591 §2: how the client authenticates at the token endpoint';

-- JWKS URI for private_key_jwt client authentication (RFC 7523 §2.2).
-- The AS fetches this URI to obtain public keys for verifying client assertion JWTs.

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS jwks_uri TEXT;

COMMENT ON COLUMN applications.jwks_uri IS
    'RFC 7523: JWKS endpoint for private_key_jwt client authentication';

-- Raw symmetric key (base64url, no pad) for client_secret_jwt HMAC verification.
-- Only populated for clients using client_secret_jwt auth method.
-- Stored separately from client_secret_hash because HMAC requires the raw key.

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS hmac_secret_b64 TEXT;

COMMENT ON COLUMN applications.hmac_secret_b64 IS
    'Base64url-encoded symmetric key for client_secret_jwt HMAC verification (nullable)';

-- ─── 3. Dynamic Client Registration (RFC 7591) ──────────────────────────────────
-- Marks clients that were registered programmatically via POST /oauth/register.
-- is_dynamic = TRUE enables access to the management endpoint (RFC 7591 §4).

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS is_dynamic BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN applications.is_dynamic IS
    'RFC 7591: client was registered via Dynamic Client Registration';

-- SHA-256 hash of the registration_access_token (single-use management credential).
-- Allows the client to read/update/delete its own registration (RFC 7591 §3.1).

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS registration_access_token_hash TEXT;

COMMENT ON COLUMN applications.registration_access_token_hash IS
    'SHA-256 of registration_access_token issued at DCR; protects the management endpoint';
