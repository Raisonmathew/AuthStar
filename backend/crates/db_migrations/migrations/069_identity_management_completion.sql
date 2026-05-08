-- Identity management completion
-- Adds first-class custom user attributes and explicit impersonation metadata.
-- Authorization remains EIAA-driven; these tables store identity/admin facts only.

CREATE TABLE IF NOT EXISTS user_attributes (
    id           VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('uattr'),
    tenant_id    VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key          VARCHAR(128) NOT NULL,
    value        JSONB NOT NULL DEFAULT 'null'::jsonb,
    display_name VARCHAR(255),
    required     BOOLEAN NOT NULL DEFAULT FALSE,
    mutable      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, key),
    CHECK (key ~ '^[A-Za-z][A-Za-z0-9_.:-]{0,127}$')
);

CREATE INDEX IF NOT EXISTS idx_user_attributes_tenant_user
    ON user_attributes(tenant_id, user_id);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_user_attributes_updated_at') THEN
        CREATE TRIGGER update_user_attributes_updated_at
            BEFORE UPDATE ON user_attributes
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

ALTER TABLE user_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_attributes FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'user_attributes'
          AND policyname = 'user_attributes_tenant_isolation'
    ) THEN
        CREATE POLICY user_attributes_tenant_isolation ON user_attributes
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS impersonated_by VARCHAR(64) REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS impersonation_reason TEXT,
    ADD COLUMN IF NOT EXISTS impersonation_started_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sessions_impersonated_by
    ON sessions(impersonated_by)
    WHERE impersonated_by IS NOT NULL;
