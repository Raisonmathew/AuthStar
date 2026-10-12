-- Migration 082: Add key_fingerprint column to api_keys
--
-- US-06: The API Keys management page must show a SHA-256 fingerprint of
-- each key so returning developers can verify which key is in use without
-- storing or re-displaying the full plaintext key.
--
-- The fingerprint is computed at key creation time as SHA-256(full_key)
-- and stored here. Existing rows are NULL (fingerprint not knowable
-- retroactively — the full key was never stored).

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS key_fingerprint TEXT;

COMMENT ON COLUMN api_keys.key_fingerprint
    IS 'SHA-256 hex digest of the full API key, prefixed "sha256:". Null for keys created before migration 082.';
