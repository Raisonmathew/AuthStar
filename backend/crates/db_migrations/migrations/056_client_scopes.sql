-- ============================================================================
-- 056_client_scopes.sql
-- ----------------------------------------------------------------------------
-- T2.8 — Reusable Client Scope objects + per-client mapping.
--
-- Today, `applications.allowed_scopes` is a JSON array directly on the app row.
-- That ships, but it cannot model two things needed for OIDC parity:
--
--   * **Default scopes** — added to a granted token even when the client did
--     not request them (e.g. `openid` for an OIDC client).
--   * **Optional scopes** — only granted when explicitly requested AND
--     mapped (e.g. `email`, `profile`, `offline_access`).
--
-- Strict EIAA invariant: scopes are **hints** that the AS uses to shape the
-- inbound `RuntimeContext.requested_scope`. The capsule still decides
-- authorization. We are storing capability surface, not authority.
--
-- Per-tenant rows; RLS-enforced; uniqueness on (tenant_id, name).
-- ============================================================================

CREATE TABLE IF NOT EXISTS client_scopes (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(64)  NOT NULL,
    name            VARCHAR(128) NOT NULL,
    description     TEXT,
    -- "oauth2" today; reserved for future "saml" et al.
    protocol        VARCHAR(16)  NOT NULL DEFAULT 'oauth2',
    -- Convenience: when true, this scope is auto-attached as a `default`
    -- mapping to every newly created confidential client in the tenant.
    -- The mapping table is still authoritative; this is just a creation hint.
    include_in_new_clients BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_client_scopes_tenant
    ON client_scopes (tenant_id);

-- Mapping: which scopes does a given client surface, and as what kind.
--   * default  — added to granted scope set even if not requested.
--   * optional — granted only when the client explicitly requests it.
CREATE TABLE IF NOT EXISTS client_scope_mappings (
    client_id    VARCHAR(255) NOT NULL,
    tenant_id    VARCHAR(64)  NOT NULL,
    scope_name   VARCHAR(128) NOT NULL,
    kind         VARCHAR(16)  NOT NULL CHECK (kind IN ('default','optional')),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, scope_name)
);

CREATE INDEX IF NOT EXISTS idx_client_scope_mappings_tenant
    ON client_scope_mappings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_scope_mappings_client
    ON client_scope_mappings (client_id);

-- Trigger keeps updated_at fresh on client_scopes (mappings are append/delete only).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'update_client_scopes_updated_at'
    ) THEN
        CREATE TRIGGER update_client_scopes_updated_at
            BEFORE UPDATE ON client_scopes
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- ─── Row-Level Security (mirrors migration 053) ─────────────────────────────
ALTER TABLE client_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_scopes FORCE ROW LEVEL SECURITY;
ALTER TABLE client_scope_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_scope_mappings FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'current_schema'::name AND tablename = 'client_scopes'
          AND policyname = 'client_scopes_tenant_isolation'
    ) THEN
        CREATE POLICY client_scopes_tenant_isolation ON client_scopes
            USING (tenant_id = current_setting('app.current_org_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true)::text);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'current_schema'::name AND tablename = 'client_scope_mappings'
          AND policyname = 'client_scope_mappings_tenant_isolation'
    ) THEN
        CREATE POLICY client_scope_mappings_tenant_isolation ON client_scope_mappings
            USING (tenant_id = current_setting('app.current_org_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_org_id', true)::text);
    END IF;
END $$;

COMMENT ON TABLE client_scopes IS
    'T2.8 — reusable per-tenant OAuth scope definitions. Mapped to clients via client_scope_mappings.';
COMMENT ON TABLE client_scope_mappings IS
    'T2.8 — kind=default scopes are always granted; kind=optional scopes are granted only when requested.';
