-- Migration 081: Webhook Dead-Letter Queue
--
-- Gap: AgentWebhookService retries deliveries in-memory (3 attempts with
-- exponential back-off) but permanently loses events on process restart or
-- when max retries are exhausted.  This migration adds a persistent DLQ so
-- dead-lettered events survive restarts and operators can re-drive them.
--
-- Schema design
-- ─────────────
-- • dead-lettered events are written here after the 3rd delivery attempt fails
-- • `retry_count` tracks how many times the event has been manually re-driven
-- • `next_retry_at` enables a scheduled redelivery sweep (cron/worker job)
-- • `resolved_at` is set when a re-drive succeeds, keeping full history
-- • RLS enforces tenant isolation
-- • the `state` check constraint prevents invalid state transitions

CREATE TABLE IF NOT EXISTS webhook_dlq (
    id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       TEXT        NOT NULL,

    -- The target webhook endpoint at the time of the failed delivery.
    webhook_id      TEXT        NOT NULL,
    url             TEXT        NOT NULL,

    -- Event metadata
    event_type      TEXT        NOT NULL,    -- e.g. 'agent.action.denied'
    decision_ref    TEXT        NOT NULL,
    payload_json    JSONB       NOT NULL,

    -- Delivery failure details
    last_error      TEXT,                   -- HTTP status or transport error message
    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Re-drive tracking
    retry_count     INTEGER     NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,            -- NULL = not scheduled for redelivery
    resolved_at     TIMESTAMPTZ,            -- NULL = still pending
    resolved_by     TEXT,                   -- user_id of the operator who resolved it

    state           TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'retrying', 'resolved', 'abandoned')),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup: pending items for a tenant (operator console + redelivery sweep).
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_pending
    ON webhook_dlq (tenant_id, state, next_retry_at)
    WHERE state IN ('pending', 'retrying');

-- Fast lookup: by webhook_id for per-endpoint failure analysis.
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_webhook
    ON webhook_dlq (webhook_id, state, created_at DESC);

-- RLS: DLQ entries are tenant-scoped.
ALTER TABLE webhook_dlq ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_dlq_tenant_isolation
    ON webhook_dlq
    USING (tenant_id = current_setting('app.current_org_id', TRUE));

CREATE POLICY webhook_dlq_tenant_insert
    ON webhook_dlq
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_org_id', TRUE));

-- updated_at trigger.
CREATE TRIGGER webhook_dlq_updated_at
    BEFORE UPDATE ON webhook_dlq
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
