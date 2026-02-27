-- User Factors Table Updates for EIAA Compliance
-- Tracks enrolled authentication capabilities per user for step-up auth

-- The table was originally created in 017_risk_engine_tables.sql
-- We need to add all missing columns and constraints for EIAA compliance

-- Add missing columns
ALTER TABLE user_factors ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
ALTER TABLE user_factors ADD COLUMN IF NOT EXISTS factor_data JSONB DEFAULT '{}'::jsonb;
ALTER TABLE user_factors ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT 'pending' NOT NULL;
ALTER TABLE user_factors ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

-- Update existing rows to a default platform tenant to satisfy NOT NULL if any exist
UPDATE user_factors SET tenant_id = 'platform' WHERE tenant_id IS NULL;

-- Make it NOT NULL for future entries
ALTER TABLE user_factors ALTER COLUMN tenant_id SET NOT NULL;

-- Update the primary unique constraint
ALTER TABLE user_factors DROP CONSTRAINT IF EXISTS user_factors_user_id_factor_type_key;
ALTER TABLE user_factors ADD CONSTRAINT user_factors_user_id_type_tenant_key UNIQUE (user_id, factor_type, tenant_id);

-- Indexes for new fields and efficient queries
CREATE INDEX IF NOT EXISTS idx_user_factors_tenant_id ON user_factors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_factors_type_status ON user_factors(factor_type, status);

COMMENT ON TABLE user_factors IS 'Enrolled authentication factors per user for step-up authentication';
COMMENT ON COLUMN user_factors.factor_type IS 'Authentication factor: password, totp, passkey, sms, email, push';
COMMENT ON COLUMN user_factors.status IS 'Factor status: pending, active, disabled';
