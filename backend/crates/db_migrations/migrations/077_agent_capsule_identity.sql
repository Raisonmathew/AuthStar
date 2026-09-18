-- Migration 077: Exact identity metadata for agent capsule resolution
--
-- Agent capsules sharing a tenant/action must be resolved by agent identity,
-- not by creation time. Human capsules retain their immutable history.

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS principal_type VARCHAR(32) NOT NULL DEFAULT 'human',
    ADD COLUMN IF NOT EXISTS agent_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS model_id VARCHAR(255);

-- The old global hash uniqueness prevented two agents with identical compiled
-- bytes from retaining separate identity metadata.
DROP INDEX IF EXISTS idx_eiaa_capsules_hash;

-- Legacy agent-prefixed rows do not carry a trustworthy agent identity and
-- must not be eligible for authorization after exact matching is enabled.
DELETE FROM eiaa_capsules
WHERE action LIKE 'agent:%' AND agent_id IS NULL;

-- Keep the newest historical agent row for each identity before adding the
-- identity index. Human capsule history is intentionally preserved.
DELETE FROM eiaa_capsules older
USING eiaa_capsules newer
WHERE older.principal_type = 'agent'
  AND newer.principal_type = 'agent'
  AND older.tenant_id = newer.tenant_id
  AND older.action = newer.action
  AND older.agent_id = newer.agent_id
  AND older.model_id IS NOT DISTINCT FROM newer.model_id
  AND older.created_at < newer.created_at;

CREATE UNIQUE INDEX IF NOT EXISTS idx_eiaa_capsules_agent_identity
    ON eiaa_capsules (tenant_id, action, principal_type, agent_id, model_id)
    WHERE principal_type = 'agent' AND agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_resolution
    ON eiaa_capsules (tenant_id, action, principal_type, agent_id, model_id, created_at DESC);

COMMENT ON COLUMN eiaa_capsules.principal_type IS
    'Capsule principal class: human or agent';
COMMENT ON COLUMN eiaa_capsules.agent_id IS
    'Registered agent identity for agent capsules';
COMMENT ON COLUMN eiaa_capsules.model_id IS
    'Model identity enforced by an agent capsule';
