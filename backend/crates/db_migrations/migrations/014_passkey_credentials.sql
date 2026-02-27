CREATE TABLE passkey_credentials (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports JSONB, -- Optional: array of strings ['usb', 'nfc', 'ble', 'internal']
    name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    aaguid VARCHAR(64) -- Optional: Authenticator Attestation GUID
);

CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);
