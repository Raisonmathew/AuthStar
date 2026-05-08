-- P0 Identity and Security Foundation
-- Adds native tenant groups, configurable password policy, and configurable
-- credential lockout policy. These tables hold identity/authentication facts;
-- EIAA remains the authorization decision layer.

CREATE TABLE IF NOT EXISTS groups (
    id              VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('grp'),
    tenant_id       VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_group_id VARCHAR(64) REFERENCES groups(id) ON DELETE SET NULL,
    name            VARCHAR(128) NOT NULL,
    slug            VARCHAR(128) NOT NULL,
    description     TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{1,126}[a-z0-9]$')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_slug_active
    ON groups(tenant_id, slug)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_groups_tenant_parent
    ON groups(tenant_id, parent_group_id)
    WHERE deleted_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_groups_updated_at') THEN
        CREATE TRIGGER update_groups_updated_at
            BEFORE UPDATE ON groups
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'groups'
          AND policyname = 'groups_tenant_isolation'
    ) THEN
        CREATE POLICY groups_tenant_isolation ON groups
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS group_memberships (
    id         VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('gm'),
    tenant_id  VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id   VARCHAR(64) NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_memberships_tenant_user
    ON group_memberships(tenant_id, user_id);

ALTER TABLE group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_memberships FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'group_memberships'
          AND policyname = 'group_memberships_tenant_isolation'
    ) THEN
        CREATE POLICY group_memberships_tenant_isolation ON group_memberships
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS group_role_bindings (
    id         VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('grb'),
    tenant_id  VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id   VARCHAR(64) NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id    VARCHAR(64) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, group_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_group_role_bindings_tenant_role
    ON group_role_bindings(tenant_id, role_id);

ALTER TABLE group_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_role_bindings FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'group_role_bindings'
          AND policyname = 'group_role_bindings_tenant_isolation'
    ) THEN
        CREATE POLICY group_role_bindings_tenant_isolation ON group_role_bindings
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS password_policies (
    id                VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('pwpol'),
    tenant_id         VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    min_length        INTEGER NOT NULL DEFAULT 12 CHECK (min_length BETWEEN 8 AND 256),
    require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_digit     BOOLEAN NOT NULL DEFAULT TRUE,
    require_symbol    BOOLEAN NOT NULL DEFAULT TRUE,
    history_depth     INTEGER NOT NULL DEFAULT 10 CHECK (history_depth BETWEEN 0 AND 50),
    max_age_days      INTEGER CHECK (max_age_days IS NULL OR max_age_days BETWEEN 1 AND 3650),
    force_rotation    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_password_policies_updated_at') THEN
        CREATE TRIGGER update_password_policies_updated_at
            BEFORE UPDATE ON password_policies
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

INSERT INTO password_policies (tenant_id)
SELECT id FROM organizations
ON CONFLICT (tenant_id) DO NOTHING;

ALTER TABLE password_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_policies FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'password_policies'
          AND policyname = 'password_policies_tenant_isolation'
    ) THEN
        CREATE POLICY password_policies_tenant_isolation ON password_policies
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS credential_lockout_policies (
    id                    VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('lockpol'),
    tenant_id             VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    factor_kind           VARCHAR(32) NOT NULL DEFAULT 'password',
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    failure_threshold     INTEGER NOT NULL DEFAULT 5 CHECK (failure_threshold BETWEEN 1 AND 100),
    window_seconds        INTEGER NOT NULL DEFAULT 3600 CHECK (window_seconds BETWEEN 60 AND 86400),
    lock_duration_seconds INTEGER NOT NULL DEFAULT 900 CHECK (lock_duration_seconds BETWEEN 60 AND 2592000),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, factor_kind)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_credential_lockout_policies_updated_at') THEN
        CREATE TRIGGER update_credential_lockout_policies_updated_at
            BEFORE UPDATE ON credential_lockout_policies
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

INSERT INTO credential_lockout_policies (tenant_id, factor_kind)
SELECT id, 'password' FROM organizations
ON CONFLICT (tenant_id, factor_kind) DO NOTHING;

ALTER TABLE credential_lockout_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_lockout_policies FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'credential_lockout_policies'
          AND policyname = 'credential_lockout_policies_tenant_isolation'
    ) THEN
        CREATE POLICY credential_lockout_policies_tenant_isolation ON credential_lockout_policies
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;