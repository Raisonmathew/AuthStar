-- Policy Activation Table
-- Tracks which version of each policy is currently active
-- Separate table allows for atomic activation without modifying policies table

CREATE TABLE IF NOT EXISTS eiaa_policy_activations (
    id VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    policy_id VARCHAR(64) NOT NULL REFERENCES eiaa_policies(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT false,
    activated_by VARCHAR(64), -- User who activated this version
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Only one active version per policy
    CONSTRAINT uk_policy_activation UNIQUE (policy_id)
);

-- Index for fast lookup of active policies
CREATE INDEX IF NOT EXISTS idx_eiaa_policy_activations_active 
    ON eiaa_policy_activations(is_active) WHERE is_active = true;

-- Add missing columns to eiaa_policies if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'eiaa_policies' AND column_name = 'description') THEN
        ALTER TABLE eiaa_policies ADD COLUMN description TEXT;
    END IF;
END $$;

-- Comments for documentation
COMMENT ON TABLE eiaa_policy_activations IS 'Tracks active version of EIAA policies per tenant';
COMMENT ON COLUMN eiaa_policy_activations.policy_id IS 'Reference to the policy version that is active';
COMMENT ON COLUMN eiaa_policy_activations.activated_by IS 'User ID who activated this version';
