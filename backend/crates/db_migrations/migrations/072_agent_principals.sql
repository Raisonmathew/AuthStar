-- Migration 072: Agent Principals (Sprint A — Non-Human Principal Support)
--
-- Adds the `agent_principals` table for pre-registered AI agent identities.
--
-- For CIMD agents the URL IS the identity — no row is required. Pre-registered
-- enterprise agents (where the tenant admin registers the agent explicitly)
-- store their metadata here. The `principal_source` column records how the
-- agent was identified at token-issuance time.
--
-- Audit chaining: `eiaa_executions` already has a `task_id` and `user_id` column;
-- agent tool-call records reference the issuing `agent_id` via `user_id`
-- (no schema change needed to eiaa_executions for Phase 1).

CREATE TABLE IF NOT EXISTS agent_principals (
    id                 TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id          TEXT        NOT NULL,

    -- Stable external identifier returned to callers in the JWT `agent_id` claim.
    agent_id           TEXT        NOT NULL UNIQUE,

    -- Human-readable name for the agent (used in audit logs and consent screens).
    name               TEXT        NOT NULL,

    -- LLM model identifier, e.g. "claude-3-5-sonnet-20241022".
    -- Nullable — CIMD agents derive model_id from the JWT at issuance time.
    model_id           TEXT,

    -- Space-separated EIAA action strings this agent is allowed to execute.
    -- Empty string = inherit from compiled capsule policy (no further restriction).
    allowed_tools      TEXT        NOT NULL DEFAULT '',

    -- Maximum delegation chain depth permitted for this agent.
    -- Must not exceed MAX_SUBCAPSULE_DEPTH (8) enforced by capsule_runtime.
    max_delegation_depth  SMALLINT NOT NULL DEFAULT 3 CHECK (max_delegation_depth BETWEEN 1 AND 8),

    -- Token TTL in seconds. Default 3600 (1 hour); capped at 86400 (24 hours).
    token_ttl_seconds  INT         NOT NULL DEFAULT 3600 CHECK (token_ttl_seconds BETWEEN 60 AND 86400),

    -- How this agent was registered:
    --   "pre_registered" — admin called POST /api/v1/agents/register
    --   "cimd"           — agent self-described via CIMD URL (future use)
    --   "dcr"            — registered via RFC 7591 Dynamic Client Registration
    principal_source   TEXT        NOT NULL DEFAULT 'pre_registered'
                           CHECK (principal_source IN ('pre_registered', 'cimd', 'dcr')),

    -- Optional CIMD metadata URL for agents that also self-describe.
    cimd_metadata_url  TEXT,

    -- Soft-delete / active flag.
    active             BOOLEAN     NOT NULL DEFAULT TRUE,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-scoped index for fast agent lookup by name / model.
CREATE INDEX IF NOT EXISTS idx_agent_principals_tenant
    ON agent_principals (tenant_id, active);

-- Unique (tenant_id, name) so tenant admins can look agents up by name.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_principals_tenant_name
    ON agent_principals (tenant_id, name)
    WHERE active = TRUE;

-- RLS: agents are tenant-scoped.
ALTER TABLE agent_principals ENABLE ROW LEVEL SECURITY;

-- SELECT / UPDATE / DELETE policy
CREATE POLICY agent_principals_tenant_isolation
    ON agent_principals
    USING (tenant_id = current_setting('app.current_org_id', TRUE));

-- INSERT policy (m-4 fix: without this, INSERT is blocked by RLS when policy is restrictive)
CREATE POLICY agent_principals_tenant_insert
    ON agent_principals
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_org_id', TRUE));

-- updated_at trigger (reuses update_updated_at_column defined in migration 001).
-- Create a compatible alias if the name differs across environments.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_principals_updated_at
    BEFORE UPDATE ON agent_principals
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
