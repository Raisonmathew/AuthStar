-- Migration 078: Agent Delegations (Gap 3-B — Agent Consent Flow)
--
-- Stores human-to-agent delegation grants issued via the consent screen.
-- A delegation grant is the audit-anchored record of a user approving an AI agent
-- to act on their behalf for a specific set of tools, with an expiry TTL.
--
-- Revocation: set revoked = TRUE. The consent handler simultaneously writes
-- `agent_blocklist:{agent_id}` to Redis so EiaaAuthzLayer's inline check denies
-- the revoked agent within 100 ms (before the next DB lookup).

CREATE TABLE IF NOT EXISTS agent_delegations (
    id                  TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT        NOT NULL,

    -- The human user who granted consent.
    user_id             TEXT        NOT NULL,

    -- The agent that received the delegation.
    agent_id            TEXT        NOT NULL,

    -- Ordered list of tools the user consented to, JSON array of strings.
    -- e.g. '["send_email","read_calendar"]'
    allowed_tools       JSONB       NOT NULL DEFAULT '[]',

    -- The EIAA execution record for the "user:consent" capsule decision that
    -- authorised this delegation.  Nullable: populated after the capsule fires.
    consent_decision_ref TEXT,

    -- OAuth flow ID that triggered the consent screen (for correlation).
    oauth_flow_id       TEXT,

    -- Expiry: agent JWT will also carry this as `exp`, but we store it here
    -- so revocation UI can surface TTL and background jobs can purge stale rows.
    expires_at          TIMESTAMPTZ NOT NULL,

    -- Soft-delete / revocation flag.  Setting this TRUE also writes the Redis
    -- blocklist key so revocation propagates within 100 ms.
    revoked             BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    revoked_by          TEXT,       -- user_id of the revoker (self or admin)

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup: list all active delegations for a user (profile/delegations page).
CREATE INDEX IF NOT EXISTS idx_agent_delegations_user
    ON agent_delegations (tenant_id, user_id, revoked, expires_at);

-- Fast lookup: check delegation during agent JWT validation.
CREATE INDEX IF NOT EXISTS idx_agent_delegations_agent
    ON agent_delegations (tenant_id, agent_id, revoked, expires_at);

-- RLS: delegations are tenant-scoped.
ALTER TABLE agent_delegations ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_delegations_tenant_isolation
    ON agent_delegations
    USING (tenant_id = current_setting('app.current_org_id', TRUE));

CREATE POLICY agent_delegations_tenant_insert
    ON agent_delegations
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_org_id', TRUE));

-- updated_at trigger.
CREATE TRIGGER agent_delegations_updated_at
    BEFORE UPDATE ON agent_delegations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
