-- Create eiaa_policies table
CREATE TABLE IF NOT EXISTS eiaa_policies (
    id VARCHAR(50) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    version INTEGER NOT NULL,
    spec JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT uk_tenant_action_version UNIQUE (tenant_id, action, version)
);

CREATE INDEX IF NOT EXISTS idx_eiaa_policies_tenant ON eiaa_policies(tenant_id);
