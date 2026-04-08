-- Add session token column for server-side cookie validation.
-- The session_token is an opaque value stored in the __session httpOnly cookie,
-- separate from the session_id used in JWTs.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token VARCHAR(128);

-- Index for token lookups during cookie-based authentication
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token) WHERE token IS NOT NULL;
