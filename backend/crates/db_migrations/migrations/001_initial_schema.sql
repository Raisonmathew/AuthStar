-- Initial schema for IDaaS platform
-- Identity & Authentication Domain

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Function to generate prefixed IDs
CREATE OR REPLACE FUNCTION generate_prefixed_id(prefix TEXT)
RETURNS TEXT AS $$
DECLARE
    encoded TEXT;
    random_bytes BYTEA;
BEGIN
    random_bytes := gen_random_bytes(16);
    encoded := encode(random_bytes, 'base64');
    -- Remove special characters and make URL-safe
    encoded := translate(encoded, '+/=', '-_');
    -- Take first 21 characters for consistent length
    encoded := substring(encoded from 1 for 21);
    RETURN prefix || '_' || encoded;
END;
$$ language 'plpgsql';

-- Users table
CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('user'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    profile_image_url TEXT,
    banned BOOLEAN DEFAULT FALSE,
    locked BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    public_metadata JSONB DEFAULT '{}',
    private_metadata JSONB DEFAULT '{}',
    unsafe_metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Identities table (email, phone, OAuth)
CREATE TABLE identities (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('ident'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('email', 'phone', 'oauth_google', 'oauth_github', 'oauth_microsoft', 'oauth_apple')),
    identifier VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    oauth_provider VARCHAR(50),
    oauth_subject VARCHAR(255),
    oauth_access_token TEXT,
    oauth_refresh_token TEXT,
    oauth_token_expires_at TIMESTAMPTZ,
    UNIQUE(type, identifier)
);

CREATE INDEX idx_identities_user_id ON identities(user_id);
CREATE INDEX idx_identities_type_identifier ON identities(type, identifier);
CREATE TRIGGER update_identities_updated_at BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Passwords table
CREATE TABLE passwords (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('pass'),
    user_id VARCHAR(64) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_hash TEXT NOT NULL,
    algorithm VARCHAR(50) DEFAULT 'argon2id',
    previous_hashes JSONB DEFAULT '[]'
);

-- Sessions table
CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('sess'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    client_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    active_organization_id VARCHAR(64)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_user_revoked ON sessions(user_id, revoked) WHERE NOT revoked;

-- MFA factors table
CREATE TABLE mfa_factors (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('mfa'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('totp', 'sms', 'backup_codes')),
    totp_secret TEXT,
    totp_algorithm VARCHAR(10) DEFAULT 'SHA1',
    backup_codes JSONB,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_mfa_factors_user_id ON mfa_factors(user_id);

-- Signup tickets (temporary sign-up state)
CREATE TABLE signup_tickets (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('ticket'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '15 minutes',
    status VARCHAR(50) NOT NULL DEFAULT 'missing_requirements' CHECK (status IN ('missing_requirements', 'awaiting_verification', 'complete')),
    email VARCHAR(255),
    phone VARCHAR(50),
    password_hash TEXT,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    verification_code VARCHAR(10),
    verification_code_expires_at TIMESTAMPTZ,
    verification_attempts INT DEFAULT 0
);

CREATE INDEX idx_signup_tickets_expires_at ON signup_tickets(expires_at);

-- Verification tokens (email/phone verification)
CREATE TABLE verification_tokens (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('vtoken'),
    identity_id VARCHAR(64) NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    token VARCHAR(255) NOT NULL UNIQUE,
    code VARCHAR(10),
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_verification_tokens_identity_id ON verification_tokens(identity_id);
CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens(expires_at);
CREATE INDEX idx_verification_tokens_token ON verification_tokens(token);

-- JWKS keys table
CREATE TABLE jwks_keys (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('key'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kid VARCHAR(255) NOT NULL UNIQUE,
    algorithm VARCHAR(10) NOT NULL DEFAULT 'ES256',
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_jwks_keys_active ON jwks_keys(active) WHERE active = TRUE;

COMMENT ON TABLE users IS 'Core user identity table';
COMMENT ON TABLE identities IS 'Multiple authentication methods per user (email, OAuth, phone)';
COMMENT ON TABLE passwords IS 'Argon2id hashed passwords';
COMMENT ON TABLE sessions IS 'Active user sessions with device tracking';
COMMENT ON TABLE mfa_factors IS 'Multi-factor authentication methods';
COMMENT ON TABLE signup_tickets IS 'Temporary state for multi-step sign-up flow';
COMMENT ON TABLE verification_tokens IS 'Email/phone verification tokens and OTPs';
