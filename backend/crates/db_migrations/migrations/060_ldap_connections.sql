CREATE TABLE IF NOT EXISTS ldap_connections (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    host VARCHAR(512) NOT NULL,
    port INTEGER NOT NULL DEFAULT 389,
    use_ssl BOOLEAN NOT NULL DEFAULT FALSE,
    bind_dn VARCHAR(512) NOT NULL DEFAULT '',
    bind_password_enc TEXT NOT NULL DEFAULT '',
    base_dn VARCHAR(512) NOT NULL DEFAULT '',
    user_search_filter VARCHAR(512) NOT NULL DEFAULT '(objectClass=person)',
    attr_map_email VARCHAR(128) NOT NULL DEFAULT 'mail',
    attr_map_name VARCHAR(128) NOT NULL DEFAULT 'cn',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ,
    sync_status VARCHAR(32) NOT NULL DEFAULT 'idle' CHECK (sync_status IN ('idle', 'syncing', 'error')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ldap_connections_tenant_id ON ldap_connections(tenant_id);
