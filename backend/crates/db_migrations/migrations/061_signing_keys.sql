-- Migration 061: Persistent signing keys for capsule compiler keystore.
--
-- Stores Ed25519 private key material so the capsule compiler key survives
-- server restarts. Without this, every restart generates a new key and all
-- previously-signed capsule decisions become unverifiable.
--
-- Security: sk_hex is the raw Ed25519 private key (32 bytes) stored as hex.
-- In production, set KEYSTORE_WRAP_KEY_HEX (64-char hex = 32-byte AES key)
-- to envelope-encrypt sk_hex at the application layer before DB insertion.
-- At rest, the DB connection itself requires authentication.

CREATE TABLE IF NOT EXISTS signing_keys (
    kid        VARCHAR(64) PRIMARY KEY,
    purpose    VARCHAR(64) NOT NULL,
    sk_hex     TEXT        NOT NULL,
    pk_hex     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One active key per purpose (e.g. "capsule_compiler")
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_purpose
    ON signing_keys(purpose);
