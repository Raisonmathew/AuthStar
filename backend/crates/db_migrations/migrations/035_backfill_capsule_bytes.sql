-- Migration 035: Backfill wasm_bytes and ast_bytes for pre-031 capsules
--
-- RENAMED from 032_backfill_capsule_bytes.sql to resolve migration prefix collision.
-- The original file shared the '032_' prefix with 032_session_decision_ref.sql (now 036),
-- causing non-deterministic execution order in sqlx migrate.
--
-- Execution order dependency:
--   031_eiaa_storage_columns.sql  → adds wasm_bytes, ast_bytes columns to eiaa_capsules
--   033_reconcile_eiaa_schema.sql → reconciles schema, adds lowering_version column
--   035_backfill_capsule_bytes.sql → adds backfill tracking (depends on 031+033 columns)
--
-- CAVEAT-EIAA-1 FIX: Migration 031 added wasm_bytes and ast_bytes columns to
-- eiaa_capsules, but existing rows compiled before that migration have NULL bytes.
-- The DB fallback path in load_capsule_from_db() requires these bytes to reconstruct
-- a fully executable CapsuleSigned.
--
-- ARCHITECTURE NOTE:
-- WASM compilation cannot be done in SQL — it requires the capsule_compiler Rust crate.
-- This migration provides:
--   1. A diagnostic view to identify capsules needing backfill
--   2. A helper function to mark capsules as "backfill pending" for the Rust backfill job
--   3. A backfill_status column to track progress
--   4. An index for the backfill job to efficiently find pending capsules
--
-- The actual byte population is done by the `backfill-capsules` binary (see
-- backend/crates/api_server/src/bin/backfill_capsules.rs) which:
--   1. Queries capsules WHERE wasm_bytes IS NULL
--   2. Looks up the policy AST from eiaa_policies (same tenant_id + action)
--   3. Recompiles using capsule_compiler::compile()
--   4. UPDATEs eiaa_capsules SET wasm_bytes = $1, ast_bytes = $2 WHERE id = $3
--
-- This migration is safe to run before the backfill job — the DB fallback path
-- already handles NULL bytes gracefully (returns None → fail_closed).

-- ============================================================
-- Step 1: Add backfill tracking column
-- ============================================================

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS backfill_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (backfill_status IN ('pending', 'complete', 'failed', 'not_needed'));

-- Mark rows that already have bytes as not needing backfill
UPDATE eiaa_capsules
SET backfill_status = 'not_needed'
WHERE wasm_bytes IS NOT NULL AND ast_bytes IS NOT NULL;

-- Mark rows that have bytes from migration 031 column addition as complete
-- (these were compiled after 031 ran and already have bytes)
UPDATE eiaa_capsules
SET backfill_status = 'complete'
WHERE wasm_bytes IS NOT NULL AND ast_bytes IS NOT NULL
  AND backfill_status = 'pending';

COMMENT ON COLUMN eiaa_capsules.backfill_status IS
    'Tracks wasm_bytes/ast_bytes backfill status: pending=needs backfill, complete=bytes present, failed=backfill failed, not_needed=compiled after migration 031';

-- ============================================================
-- Step 2: Index for efficient backfill job queries
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_backfill_pending
    ON eiaa_capsules(tenant_id, action, created_at DESC)
    WHERE backfill_status = 'pending';

-- ============================================================
-- Step 3: Diagnostic view — capsules needing backfill
-- ============================================================

CREATE OR REPLACE VIEW eiaa_capsules_backfill_needed AS
SELECT
    id,
    tenant_id,
    action,
    capsule_hash_b64,
    created_at,
    backfill_status,
    CASE
        WHEN wasm_bytes IS NULL AND ast_bytes IS NULL THEN 'both_missing'
        WHEN wasm_bytes IS NULL THEN 'wasm_missing'
        WHEN ast_bytes IS NULL THEN 'ast_missing'
        ELSE 'complete'
    END AS bytes_status
FROM eiaa_capsules
WHERE wasm_bytes IS NULL OR ast_bytes IS NULL
ORDER BY tenant_id, action, created_at DESC;

COMMENT ON VIEW eiaa_capsules_backfill_needed IS
    'Capsules that need wasm_bytes/ast_bytes backfill. Run the backfill-capsules binary to populate.';

-- ============================================================
-- Step 4: Helper function for the backfill job
-- ============================================================

-- Returns the next batch of capsules needing backfill, with their policy AST.
-- The backfill job calls this to get work items.
CREATE OR REPLACE FUNCTION get_capsules_for_backfill(batch_size INT DEFAULT 100)
RETURNS TABLE (
    capsule_id      TEXT,
    tenant_id       TEXT,
    action          TEXT,
    capsule_hash_b64 TEXT,
    compiler_kid    TEXT,
    compiler_sig_b64 TEXT,
    meta            JSONB,
    policy_spec     JSONB  -- AST from eiaa_policies (most recent version)
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.id::TEXT,
        c.tenant_id::TEXT,
        c.action::TEXT,
        c.capsule_hash_b64::TEXT,
        c.compiler_kid::TEXT,
        c.compiler_sig_b64::TEXT,
        c.meta,
        p.spec AS policy_spec
    FROM eiaa_capsules c
    LEFT JOIN LATERAL (
        SELECT spec
        FROM eiaa_policies ep
        WHERE ep.tenant_id = c.tenant_id
          AND ep.action = c.action
        ORDER BY ep.version DESC
        LIMIT 1
    ) p ON true
    WHERE c.wasm_bytes IS NULL OR c.ast_bytes IS NULL
    ORDER BY c.created_at ASC
    LIMIT batch_size;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_capsules_for_backfill IS
    'Returns capsules needing wasm_bytes/ast_bytes backfill with their policy AST. Used by the backfill-capsules binary.';

-- ============================================================
-- Step 5: Function to mark backfill complete (called by Rust job)
-- ============================================================

CREATE OR REPLACE FUNCTION mark_capsule_backfill_complete(
    p_capsule_id TEXT,
    p_wasm_bytes BYTEA,
    p_ast_bytes  BYTEA
) RETURNS VOID AS $$
BEGIN
    UPDATE eiaa_capsules
    SET wasm_bytes      = p_wasm_bytes,
        ast_bytes       = p_ast_bytes,
        backfill_status = 'complete'
    WHERE id = p_capsule_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Capsule % not found', p_capsule_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION mark_capsule_backfill_complete IS
    'Called by the backfill-capsules binary after successfully recompiling a capsule.';

-- ============================================================
-- Step 6: Function to mark backfill failed (called by Rust job)
-- ============================================================

CREATE OR REPLACE FUNCTION mark_capsule_backfill_failed(
    p_capsule_id TEXT,
    p_reason     TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE eiaa_capsules
    SET backfill_status = 'failed'
    WHERE id = p_capsule_id;

    -- Log to a dedicated table for operational visibility
    INSERT INTO eiaa_capsule_backfill_errors (capsule_id, reason, failed_at)
    VALUES (p_capsule_id, p_reason, NOW())
    ON CONFLICT (capsule_id) DO UPDATE
        SET reason    = EXCLUDED.reason,
            failed_at = EXCLUDED.failed_at;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- Step 7: Error tracking table for failed backfills
-- ============================================================

CREATE TABLE IF NOT EXISTS eiaa_capsule_backfill_errors (
    capsule_id  TEXT PRIMARY KEY REFERENCES eiaa_capsules(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL,
    failed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE eiaa_capsule_backfill_errors IS
    'Tracks capsules that failed wasm_bytes/ast_bytes backfill. Investigate and re-run backfill job.';

-- ============================================================
-- Step 8: Summary function for operational monitoring
-- ============================================================

CREATE OR REPLACE FUNCTION capsule_backfill_summary()
RETURNS TABLE (
    status      TEXT,
    count       BIGINT,
    oldest      TIMESTAMPTZ,
    newest      TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        backfill_status::TEXT AS status,
        COUNT(*)              AS count,
        MIN(created_at)       AS oldest,
        MAX(created_at)       AS newest
    FROM eiaa_capsules
    GROUP BY backfill_status
    ORDER BY backfill_status;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION capsule_backfill_summary IS
    'Returns a summary of capsule backfill status. Run SELECT * FROM capsule_backfill_summary() to check progress.';

-- Made with Bob