-- Custom Domains
-- Migration 019: Custom domain support for hosted pages

CREATE TABLE IF NOT EXISTS custom_domains (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL UNIQUE,
    
    -- Verification
    verification_status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending' | 'verified' | 'failed'
    verification_token VARCHAR(64) NOT NULL,  -- Random token for DNS TXT verification
    verification_method VARCHAR(20) NOT NULL DEFAULT 'dns_txt',  -- 'dns_txt' | 'cname'
    verified_at TIMESTAMPTZ,
    last_verification_attempt TIMESTAMPTZ,
    verification_error TEXT,
    
    -- SSL/TLS
    ssl_status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending' | 'provisioning' | 'active' | 'failed'
    ssl_provider VARCHAR(20),  -- 'letsencrypt' | 'cloudflare' | 'custom'
    ssl_expires_at TIMESTAMPTZ,
    ssl_certificate_id VARCHAR(255),  -- Reference to certificate storage
    
    -- Configuration
    is_primary BOOLEAN NOT NULL DEFAULT false,  -- Primary domain for this org
    is_active BOOLEAN NOT NULL DEFAULT false,   -- Domain is serving traffic
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_custom_domains_org ON custom_domains(organization_id);
CREATE INDEX idx_custom_domains_domain ON custom_domains(domain);
CREATE INDEX idx_custom_domains_verification ON custom_domains(verification_status)
    WHERE verification_status = 'pending';

-- Domain verification records (for tracking DNS lookups)
CREATE TABLE IF NOT EXISTS domain_verification_logs (
    id VARCHAR(255) PRIMARY KEY,
    domain_id VARCHAR(255) NOT NULL REFERENCES custom_domains(id) ON DELETE CASCADE,
    attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    dns_records JSONB,  -- What was found
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_domain_verification_logs_domain ON domain_verification_logs(domain_id);
