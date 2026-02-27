-- Add device_id column to sessions table
-- This links a session to a specific device record for risk analysis and audit trails.

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id VARCHAR(255);

-- Create index for faster lookup of sessions by device
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);

COMMENT ON COLUMN sessions.device_id IS 'ID of the device record associated with this session';
