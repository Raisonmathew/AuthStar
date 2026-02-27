-- Session Assurance Level and Capability Tracking for EIAA Compliance
-- Tracks the authentication assurance level and verified factors for each session

-- Add assurance_level column to track the Authentication Assurance Level
-- Values: 'aal1' (password only), 'aal2' (+ second factor), 'aal3' (+ hardware key)
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS assurance_level VARCHAR(10) DEFAULT 'aal1';

-- Add verified_capabilities as JSON array of verified authentication factors
-- Example: ["password", "totp"] or ["password", "passkey"]
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS verified_capabilities JSONB DEFAULT '[]'::jsonb;

-- Add is_provisional flag for step-up authentication scenarios
-- A provisional session requires additional authentication before accessing protected resources
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_provisional BOOLEAN DEFAULT FALSE;

-- Create index for efficient AAL-based queries
CREATE INDEX IF NOT EXISTS idx_sessions_assurance_level ON sessions(assurance_level);

-- Create GIN index for capability-based queries
CREATE INDEX IF NOT EXISTS idx_sessions_verified_capabilities ON sessions USING GIN(verified_capabilities);

COMMENT ON COLUMN sessions.assurance_level IS 'Authentication Assurance Level: aal1, aal2, or aal3';
COMMENT ON COLUMN sessions.verified_capabilities IS 'JSON array of verified authentication capabilities (e.g., password, totp, passkey)';
COMMENT ON COLUMN sessions.is_provisional IS 'True if session requires step-up authentication for protected resources';
