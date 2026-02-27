-- Migration: Add flow_purpose column to hosted_auth_flows
-- EIAA: Internal security semantics (authenticate | enroll_identity)

ALTER TABLE hosted_auth_flows 
ADD COLUMN IF NOT EXISTS flow_purpose VARCHAR(32) NOT NULL DEFAULT 'authenticate';

-- Add index for querying by purpose
CREATE INDEX IF NOT EXISTS idx_hosted_auth_flows_purpose ON hosted_auth_flows(flow_purpose);

COMMENT ON COLUMN hosted_auth_flows.flow_purpose IS 'EIAA internal security semantics: authenticate or enroll_identity';

-- Add login_methods column to organizations
ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS login_methods JSONB DEFAULT '{"email_password": true, "passkey": false, "sso": false, "mfa": {"required": false, "methods": ["totp"]}}';
