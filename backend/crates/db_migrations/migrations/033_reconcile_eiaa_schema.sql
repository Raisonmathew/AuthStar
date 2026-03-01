-- Migration 033: Reconcile EIAA Schema
--
-- RENAMED from 031_reconcile_eiaa_schema.sql to resolve migration prefix collision.
-- The original file shared the '031_' prefix with 031_eiaa_storage_columns.sql and
-- 031_flow_expiry_10min.sql, causing non-deterministic execution order in sqlx migrate.
--
-- Execution order dependency:
--   031_eiaa_storage_columns.sql  → adds input_context, wasm_bytes, ast_bytes columns
--   033_reconcile_eiaa_schema.sql → reconciles schema conflicts between migrations 006 and 011
--   034_flow_expiry_10min.sql     → unrelated flow expiry hardening
--   035_backfill_capsule_bytes.sql → backfill job scaffolding (depends on 031 columns)
--   036_session_decision_ref.sql  → session EIAA decision reference (depends on 033 schema)
--
-- HIGH-EIAA-5 FIX: Reconcile eiaa_executions schema conflict between migrations 006 and 011.
--   Migration 006 created eiaa_executions with a minimal schema (no decision_ref, no tenant_id,
--   no input_digest, no attestation_hash_b64, no user_id).
--   Migration 011 dropped and recreated the table with the full production schema.
--   This migration ensures the production schema is in place idempotently, and adds any
--   columns that may be missing if 011 ran before 006 or vice versa.
--
-- MEDIUM-EIAA-7 FIX: Add wasm_bytes and ast_bytes columns to eiaa_capsules.
--   The DB fallback path in eiaa_authz.rs (CRITICAL-EIAA-3) requires these columns to
--   reconstruct a fully executable CapsuleSigned from the database. Without them, the
--   fallback returns None and the request fails with a clear error rather than executing
--   with empty WASM bytes (which would produce an incorrect decision).
--
-- MEDIUM-EIAA-8 FIX: Add expires_at column to eiaa_replay_nonces for TTL-based cleanup.
--   The table was created in migration 006 but never used. This migration adds the
--   expires_at column so the runtime service can insert nonces with a TTL and a
--   background job can purge expired entries.

-- ============================================================
-- HIGH-EIAA-5: Reconcile eiaa_executions
-- ============================================================

-- Add missing columns to eiaa_executions if they don't exist.
-- These were added in migration 011 but may be absent if the table was created by 006
-- and 011 failed to run (e.g., due to the DROP TABLE CASCADE on a table with FK refs).

ALTER TABLE eiaa_executions
    ADD COLUMN IF NOT EXISTS decision_ref VARCHAR(64),
    ADD COLUMN IF NOT EXISTS capsule_version TEXT,
    ADD COLUMN IF NOT EXISTS action TEXT,
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS input_digest TEXT,
    ADD COLUMN IF NOT EXISTS input_context TEXT,
    ADD COLUMN IF NOT EXISTS attestation_signature_b64 TEXT,
    ADD COLUMN IF NOT EXISTS attestation_timestamp TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attestation_hash_b64 TEXT,
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(64);

-- Backfill decision_ref for any rows that were inserted before 011 ran.
-- Use a deterministic value derived from the row id so it is stable across re-runs.
UPDATE eiaa_executions
SET decision_ref = 'dec_' || replace(id, '-', '')
WHERE decision_ref IS NULL;

-- Now enforce NOT NULL + UNIQUE on decision_ref (safe after backfill).
ALTER TABLE eiaa_executions
    ALTER COLUMN decision_ref SET NOT NULL;

-- Add unique constraint only if it doesn't already exist.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'eiaa_executions_decision_ref_key'
          AND conrelid = 'eiaa_executions'::regclass
    ) THEN
        ALTER TABLE eiaa_executions ADD CONSTRAINT eiaa_executions_decision_ref_key UNIQUE (decision_ref);
    END IF;
END $$;

-- Backfill capsule_version for legacy rows.
UPDATE eiaa_executions SET capsule_version = '1.0' WHERE capsule_version IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN capsule_version SET NOT NULL;
ALTER TABLE eiaa_executions ALTER COLUMN capsule_version SET DEFAULT '1.0';

-- Backfill action for legacy rows (unknown action for pre-011 rows).
UPDATE eiaa_executions SET action = 'unknown' WHERE action IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN action SET NOT NULL;

-- Backfill tenant_id for legacy rows.
UPDATE eiaa_executions SET tenant_id = 'unknown' WHERE tenant_id IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN tenant_id SET NOT NULL;

-- Backfill input_digest for legacy rows.
UPDATE eiaa_executions SET input_digest = '' WHERE input_digest IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN input_digest SET NOT NULL;

-- Backfill attestation_signature_b64 for legacy rows.
UPDATE eiaa_executions SET attestation_signature_b64 = '' WHERE attestation_signature_b64 IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN attestation_signature_b64 SET NOT NULL;

-- Backfill attestation_timestamp for legacy rows.
UPDATE eiaa_executions SET attestation_timestamp = created_at WHERE attestation_timestamp IS NULL;
ALTER TABLE eiaa_executions ALTER COLUMN attestation_timestamp SET NOT NULL;

-- Ensure all indexes from migration 011 exist.
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_decision_ref ON eiaa_executions(decision_ref);
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_tenant_action ON eiaa_executions(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_created_at ON eiaa_executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_user_id ON eiaa_executions(user_id) WHERE user_id IS NOT NULL;

-- Comments
COMMENT ON TABLE eiaa_executions IS 'Cryptographic audit trail for all EIAA execution decisions';
COMMENT ON COLUMN eiaa_executions.decision_ref IS 'Unique reference linking to the attested decision';
COMMENT ON COLUMN eiaa_executions.capsule_hash_b64 IS 'Hash of the compiled WASM capsule that made the decision';
COMMENT ON COLUMN eiaa_executions.attestation_signature_b64 IS 'Ed25519 signature proving decision authenticity';
COMMENT ON COLUMN eiaa_executions.input_context IS 'Full JSON context used as capsule input (for re-execution verification)';
COMMENT ON COLUMN eiaa_executions.input_digest IS 'SHA-256 of input_context for fast tamper detection';

-- ============================================================
-- MEDIUM-EIAA-7: Add wasm_bytes and ast_bytes to eiaa_capsules
-- ============================================================

-- These columns store the compiled WASM and AST bytes for the capsule.
-- Required by the DB fallback path (CRITICAL-EIAA-3) to reconstruct a fully
-- executable CapsuleSigned when the Redis cache misses.
--
-- Both columns are nullable: existing rows compiled before this migration
-- will have NULL bytes and will trigger the "pending MEDIUM-EIAA-7 migration"
-- warning in load_capsule_from_db(). New capsules compiled after this migration
-- will have the bytes populated by the capsule compiler service.

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS wasm_bytes BYTEA,
    ADD COLUMN IF NOT EXISTS ast_bytes BYTEA;

-- Also add the missing columns referenced in load_capsule_from_db():
--   capsule_hash_b64 is already present (migration 006).
--   compiler_kid is already present (migration 006).
--   compiler_sig_b64 is already present (migration 006).
-- Add the lowering_version column used to reconstruct CapsuleSigned.
ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS lowering_version TEXT NOT NULL DEFAULT 'ei-aa-lower-wasm-v1';

COMMENT ON COLUMN eiaa_capsules.wasm_bytes IS 'Compiled WASM bytes for the capsule (required for DB fallback execution)';
COMMENT ON COLUMN eiaa_capsules.ast_bytes IS 'Serialized AST bytes for the capsule (required for re-execution verification)';
COMMENT ON COLUMN eiaa_capsules.lowering_version IS 'Lowering version string (e.g. ei-aa-lower-wasm-v1)';

-- ============================================================
-- MEDIUM-EIAA-8: Add expires_at to eiaa_replay_nonces
-- ============================================================

-- The eiaa_replay_nonces table was created in migration 006 but never used.
-- Add expires_at so the runtime service can insert nonces with a TTL and
-- a background job (or pg_cron) can purge expired entries.
--
-- Also add tenant_id and action for scoped nonce lookup (prevents cross-tenant
-- nonce collisions in multi-tenant deployments).

ALTER TABLE eiaa_replay_nonces
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS action VARCHAR(128);

-- Index for fast expiry-based cleanup.
CREATE INDEX IF NOT EXISTS idx_eiaa_replay_nonces_expires_at ON eiaa_replay_nonces(expires_at);
-- Index for tenant-scoped nonce lookup.
CREATE INDEX IF NOT EXISTS idx_eiaa_replay_nonces_tenant ON eiaa_replay_nonces(tenant_id) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE eiaa_replay_nonces IS 'Persistent nonce store for EIAA capsule execution replay protection';
COMMENT ON COLUMN eiaa_replay_nonces.nonce_b64 IS 'Base64url-encoded nonce (primary key, globally unique)';
COMMENT ON COLUMN eiaa_replay_nonces.expires_at IS 'Nonce expiry time — entries past this time are safe to purge';
COMMENT ON COLUMN eiaa_replay_nonces.tenant_id IS 'Tenant that generated this nonce (for scoped cleanup)';
COMMENT ON COLUMN eiaa_replay_nonces.action IS 'Action that generated this nonce (for audit)';

-- ============================================================
-- signup_tickets: Add decision_ref column (MEDIUM-EIAA-9)
-- ============================================================

-- The signup_tickets table needs a decision_ref column to link the signup
-- ticket to the EIAA execution that authorized the signup flow.
-- This is populated by verification_service.rs after the signup capsule executes.

ALTER TABLE signup_tickets
    ADD COLUMN IF NOT EXISTS decision_ref VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_signup_tickets_decision_ref ON signup_tickets(decision_ref) WHERE decision_ref IS NOT NULL;

COMMENT ON COLUMN signup_tickets.decision_ref IS 'EIAA execution decision_ref that authorized this signup (MEDIUM-EIAA-9)';

-- Made with Bob