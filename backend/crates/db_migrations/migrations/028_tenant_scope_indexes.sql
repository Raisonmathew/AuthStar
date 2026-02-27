-- Tenant Scoping DB Guardrails (G16) — Migration 027
--
-- 1. Fill NULL tenant_id in sessions (from migration 013 which added it nullable)
-- 2. Add NOT NULL constraints where missing
-- 3. Add composite indexes for scoped queries
-- 4. Enable RLS on high-risk tables

-- ═══════════════════════════════════════════════
-- Fix NULL tenant_id values in sessions (set to 'platform' as default)
-- ═══════════════════════════════════════════════
UPDATE sessions SET tenant_id = 'platform' WHERE tenant_id IS NULL;

-- Now safe to set NOT NULL
ALTER TABLE sessions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN user_id SET NOT NULL;

-- ═══════════════════════════════════════════════
-- Add tenant_id to audit_logs if missing
-- ═══════════════════════════════════════════════
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
UPDATE audit_logs SET tenant_id = 'platform' WHERE tenant_id IS NULL;
ALTER TABLE audit_logs ALTER COLUMN tenant_id SET NOT NULL;

-- ═══════════════════════════════════════════════
-- Composite indexes for scoped queries
-- (eiaa_executions, eiaa_policies, sso_connections already NOT NULL)
-- ═══════════════════════════════════════════════

-- Sessions: auth middleware queries by (id, tenant_id)
CREATE INDEX IF NOT EXISTS idx_sessions_id_tenant
    ON sessions(id, tenant_id);

-- Sessions: per-user lookups within a tenant
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user
    ON sessions(tenant_id, user_id);

-- EIAA executions: decision_ref + tenant scoped lookup
CREATE INDEX IF NOT EXISTS idx_executions_decision_tenant
    ON eiaa_executions(decision_ref, tenant_id);

-- Audit logs: per-tenant time-ordered lookup
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_time
    ON audit_logs(tenant_id, created_at DESC);

-- User factors: per-user per-tenant lookup
CREATE INDEX IF NOT EXISTS idx_user_factors_user_tenant
    ON user_factors(user_id, tenant_id);

-- Custom domains: per-org lookup
CREATE INDEX IF NOT EXISTS idx_custom_domains_org
    ON custom_domains(organization_id);

-- ═══════════════════════════════════════════════
-- Row Level Security on high-risk tables
-- ═══════════════════════════════════════════════

ALTER TABLE eiaa_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
