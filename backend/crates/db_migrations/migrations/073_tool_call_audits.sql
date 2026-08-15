-- Migration 073: Tool Call Audits (Sprint B — Tool-Call Authorization Capsules)
--
-- Adds the `tool_call_audits` table.  Every AI agent tool-call authorization
-- decision is recorded here — one row per check, linked to the parent
-- `eiaa_executions` record that authorized the surrounding task.
--
-- Design choices:
--   • Separate table (not a column on eiaa_executions) because one task produces
--     many tool-call records.  Joining is by (tenant_id, task_id).
--   • `allowed` BOOLEAN carries the capsule decision so the query path is fast.
--   • `delegation_depth` is denormalized here to avoid joining agent_principals.
--   • `tool_args_hash` stores SHA-256 of args JSON (hex) — never raw args.
--   • RLS is identical to agent_principals: tenant_id must match session config.

CREATE TABLE IF NOT EXISTS tool_call_audits (
    id                  TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT        NOT NULL,

    -- Agent identity from the JWT claims
    agent_id            TEXT        NOT NULL,
    task_id             TEXT        NOT NULL,

    -- Tool call details
    tool_name           TEXT        NOT NULL,
    -- SHA-256 (hex) of JSON-serialised arguments — never raw args.
    tool_args_hash      TEXT,

    -- EIAA capsule decision
    allowed             BOOLEAN     NOT NULL,
    -- Reason string returned by the capsule (e.g. "tool_not_permitted:send_email").
    denial_reason       TEXT,

    -- Delegation chain depth at time of call (0 = direct human → agent).
    delegation_depth    SMALLINT    NOT NULL DEFAULT 0,

    -- Foreign key to the encompassing EIAA execution record (best-effort,
    -- can be NULL if the execution record was not yet written or was pruned).
    eiaa_execution_id   TEXT,

    -- Principal source from the JWT (pre_registered | cimd | dcr)
    principal_source    TEXT,

    -- Client IP address for risk correlation
    client_ip           TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-scoped index: look up all tool calls for a given task
CREATE INDEX IF NOT EXISTS idx_tool_call_audits_task
    ON tool_call_audits (tenant_id, task_id, created_at DESC);

-- Fast lookup by agent_id across all tasks
CREATE INDEX IF NOT EXISTS idx_tool_call_audits_agent
    ON tool_call_audits (tenant_id, agent_id, created_at DESC);

-- Denial-only index for security dashboards
CREATE INDEX IF NOT EXISTS idx_tool_call_audits_denied
    ON tool_call_audits (tenant_id, created_at DESC)
    WHERE allowed = FALSE;

-- RLS: tool call audit records are tenant-scoped.
ALTER TABLE tool_call_audits ENABLE ROW LEVEL SECURITY;

CREATE POLICY tool_call_audits_tenant_isolation
    ON tool_call_audits
    FOR ALL
    USING (tenant_id = current_setting('app.current_org_id', TRUE));

CREATE POLICY tool_call_audits_tenant_insert
    ON tool_call_audits
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_org_id', TRUE));
