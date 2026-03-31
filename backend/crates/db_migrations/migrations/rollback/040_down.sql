-- Rollback migration 040: Unified Policy Builder
-- Reverts the unified redesign back to the 039 schema.
-- WARNING: All unified policy builder data (versions, conditions, rule groups) will be lost.

-- Drop eiaa_policies columns added in 040
ALTER TABLE eiaa_policies DROP COLUMN IF EXISTS builder_version_id;
-- Note: builder_config_id and source were added in 039, not dropped here.

-- Drop new tables introduced in 040 (in dependency order)
DROP TABLE IF EXISTS policy_builder_conditions CASCADE;
DROP TABLE IF EXISTS policy_builder_rules CASCADE;
DROP TABLE IF EXISTS policy_builder_rule_groups CASCADE;
DROP TABLE IF EXISTS policy_builder_versions CASCADE;
DROP TABLE IF EXISTS policy_builder_configs CASCADE;
DROP TABLE IF EXISTS policy_templates CASCADE;

-- Recreate the 039-era tables (simplified schema)
-- policy_templates (039 version with slug as non-PK)
CREATE TABLE IF NOT EXISTS policy_templates (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    display_name    VARCHAR(200) NOT NULL,
    description     TEXT         NOT NULL,
    category        VARCHAR(50)  NOT NULL DEFAULT 'authentication',
    applicable_actions TEXT[]    NOT NULL DEFAULT '{}',
    icon            VARCHAR(50),
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    param_schema    JSONB        NOT NULL DEFAULT '{}',
    param_defaults  JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- policy_builder_configs (039 version without versioning)
CREATE TABLE IF NOT EXISTS policy_builder_configs (
    id                  VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           VARCHAR(50)  NOT NULL,
    action_key          VARCHAR(100) NOT NULL,
    display_name        VARCHAR(200),
    description         TEXT,
    state               VARCHAR(20)  NOT NULL DEFAULT 'draft',
    capsule_hash_b64    VARCHAR(200),
    compiled_at         TIMESTAMPTZ,
    compiled_by         VARCHAR(50),
    activated_at        TIMESTAMPTZ,
    activated_by        VARCHAR(50),
    created_by          VARCHAR(50)  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_builder_config_tenant_action UNIQUE (tenant_id, action_key)
);

-- policy_builder_rules (039 version without group_id)
CREATE TABLE IF NOT EXISTS policy_builder_rules (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    config_id       VARCHAR(50)  NOT NULL REFERENCES policy_builder_configs(id) ON DELETE CASCADE,
    template_slug   VARCHAR(100) NOT NULL REFERENCES policy_templates(slug),
    param_values    JSONB        NOT NULL DEFAULT '{}',
    display_name    VARCHAR(200),
    is_enabled      BOOLEAN      NOT NULL DEFAULT true,
    sort_order      INTEGER      NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- policy_builder_audit (039 version without actor_ip/metadata)
CREATE TABLE IF NOT EXISTS policy_builder_audit (
    id              VARCHAR(50)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       VARCHAR(50)  NOT NULL,
    config_id       VARCHAR(50)  NOT NULL,
    action_key      VARCHAR(100) NOT NULL,
    event_type      VARCHAR(50)  NOT NULL,
    actor_id        VARCHAR(50)  NOT NULL,
    actor_email     VARCHAR(200),
    config_snapshot JSONB,
    description     TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Re-enable RLS from 039
ALTER TABLE policy_builder_configs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_builder_rules    ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_builder_audit    ENABLE ROW LEVEL SECURITY;

CREATE POLICY builder_configs_tenant_isolation ON policy_builder_configs
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY builder_rules_tenant_isolation ON policy_builder_rules
    USING (config_id IN (
        SELECT id FROM policy_builder_configs
        WHERE tenant_id = current_setting('app.tenant_id', true)
    ));
CREATE POLICY builder_audit_tenant_isolation ON policy_builder_audit
    USING (tenant_id = current_setting('app.tenant_id', true));
