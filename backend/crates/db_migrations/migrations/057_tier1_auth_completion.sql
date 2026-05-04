-- 057_tier1_auth_completion.sql
-- Completes remaining Tier 1 auth foundations:
--   T1.1 required actions
--   T1.2 per-credential brute-force counters
--   T1.5 pluggable auth flow definitions

CREATE TABLE IF NOT EXISTS required_actions (
    id           VARCHAR(64) PRIMARY KEY,
    tenant_id    VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code         VARCHAR(64) NOT NULL,
    state        VARCHAR(16) NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'completed', 'cancelled')),
    priority     INTEGER NOT NULL DEFAULT 100,
    ttl_seconds  INTEGER,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, user_id, code, state)
);

CREATE INDEX IF NOT EXISTS idx_required_actions_user_pending
    ON required_actions(tenant_id, user_id, priority, created_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_required_actions_expires
    ON required_actions(expires_at)
    WHERE state = 'pending' AND expires_at IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_required_actions_updated_at'
    ) THEN
        CREATE TRIGGER update_required_actions_updated_at
            BEFORE UPDATE ON required_actions
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

ALTER TABLE required_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE required_actions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'required_actions'
          AND policyname = 'required_actions_tenant_isolation'
    ) THEN
        CREATE POLICY required_actions_tenant_isolation ON required_actions
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS credential_attempt_counters (
    tenant_id       VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    factor_kind     VARCHAR(32) NOT NULL,
    last_1h         INTEGER NOT NULL DEFAULT 0,
    last_24h        INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, factor_kind)
);

CREATE INDEX IF NOT EXISTS idx_credential_attempt_counters_user
    ON credential_attempt_counters(tenant_id, user_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_credential_attempt_counters_updated_at'
    ) THEN
        CREATE TRIGGER update_credential_attempt_counters_updated_at
            BEFORE UPDATE ON credential_attempt_counters
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

ALTER TABLE credential_attempt_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_attempt_counters FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'credential_attempt_counters'
          AND policyname = 'credential_attempts_tenant_isolation'
    ) THEN
        CREATE POLICY credential_attempts_tenant_isolation ON credential_attempt_counters
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS auth_flows (
    id          VARCHAR(64) PRIMARY KEY,
    tenant_id   VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        VARCHAR(128) NOT NULL,
    flow_key    VARCHAR(64) NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, flow_key)
);

CREATE TABLE IF NOT EXISTS auth_flow_executions (
    id               VARCHAR(64) PRIMARY KEY,
    tenant_id        VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    flow_id          VARCHAR(64) NOT NULL REFERENCES auth_flows(id) ON DELETE CASCADE,
    authenticator_id VARCHAR(64) NOT NULL,
    requirement      VARCHAR(16) NOT NULL DEFAULT 'required'
                     CHECK (requirement IN ('required', 'alternative', 'conditional', 'disabled')),
    sort_order       INTEGER NOT NULL DEFAULT 0,
    config           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (flow_id, authenticator_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_flows_tenant_key
    ON auth_flows(tenant_id, flow_key);
CREATE INDEX IF NOT EXISTS idx_auth_flow_executions_flow
    ON auth_flow_executions(flow_id, sort_order);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_auth_flows_updated_at'
    ) THEN
        CREATE TRIGGER update_auth_flows_updated_at
            BEFORE UPDATE ON auth_flows
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_auth_flow_executions_updated_at'
    ) THEN
        CREATE TRIGGER update_auth_flow_executions_updated_at
            BEFORE UPDATE ON auth_flow_executions
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

ALTER TABLE auth_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_flows FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_flow_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_flow_executions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'auth_flows'
          AND policyname = 'auth_flows_tenant_isolation'
    ) THEN
        CREATE POLICY auth_flows_tenant_isolation ON auth_flows
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'auth_flow_executions'
          AND policyname = 'auth_flow_executions_tenant_isolation'
    ) THEN
        CREATE POLICY auth_flow_executions_tenant_isolation ON auth_flow_executions
            FOR ALL
            USING (tenant_id = current_setting('app.current_org_id', true))
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END $$;
