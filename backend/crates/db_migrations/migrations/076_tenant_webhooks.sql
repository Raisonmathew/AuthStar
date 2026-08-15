-- Migration 076: Tenant Webhook Endpoints
--
-- Stores HTTPS endpoints that receive real-time agent events from
-- AgentWebhookService. Matches the WebhookEndpoint struct in
-- services/agent_webhook_service.rs.
--
-- Event filtering: event_type column holds 'agent' (the only current type).
-- Future event types (e.g. 'user', 'oauth') can be added without schema changes.
--
-- The `secret` column holds the HMAC-SHA256 signing key. It is stored
-- in plaintext (same as Stripe/GitHub webhook secrets) — the secret is
-- what the *tenant* configures; it is not an AuthStar-held credential.

CREATE TABLE IF NOT EXISTS tenant_webhooks (
    id              TEXT        NOT NULL DEFAULT 'whk_' || replace(gen_random_uuid()::text, '-', ''),
    tenant_id       TEXT        NOT NULL,
    url             TEXT        NOT NULL,
    secret          TEXT        NOT NULL,
    event_type      TEXT        NOT NULL DEFAULT 'agent',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    description     TEXT,
    -- Delivery tracking (updated by AgentWebhookService on each delivery attempt)
    last_delivery_at            TIMESTAMPTZ,
    last_delivery_status        INTEGER,       -- HTTP response status code, NULL if never delivered
    last_delivery_success       BOOLEAN,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenant_webhooks_pkey       PRIMARY KEY (id),
    CONSTRAINT tenant_webhooks_url_https  CHECK (url LIKE 'https://%')
);

-- Tenant-scoped index for the AgentWebhookService load_endpoints query
CREATE INDEX IF NOT EXISTS idx_tenant_webhooks_tenant_event
    ON tenant_webhooks (tenant_id, event_type)
    WHERE active = TRUE;

-- RLS: each tenant can only see and modify their own webhooks
ALTER TABLE tenant_webhooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_webhooks_isolation ON tenant_webhooks
    USING (tenant_id = current_setting('app.current_org_id', TRUE))
    WITH CHECK (tenant_id = current_setting('app.current_org_id', TRUE));
