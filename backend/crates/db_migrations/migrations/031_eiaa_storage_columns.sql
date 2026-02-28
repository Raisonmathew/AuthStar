-- Migration 031: EIAA Storage Columns
--
-- HIGH-EIAA-5: Add `input_context` to `eiaa_executions` for cryptographic re-execution.
--   The re-execution service (reexecution_service.rs) needs the full serialized
--   AuthorizationContext JSON to replay a capsule execution and verify the decision
--   was not tampered with. Previously only `input_digest` (SHA-256 hash) was stored,
--   making replay impossible.
--
-- MEDIUM-EIAA-7: Add `wasm_bytes` and `ast_bytes` to `eiaa_capsules`.
--   The capsule cache-miss DB fallback (eiaa_authz.rs::load_capsule_from_db) and
--   the re-execution service both need the compiled WASM bytes to execute the capsule.
--   Without these columns, every cache miss results in a hard authorization failure.
--
-- Design notes:
--   - `input_context` is TEXT (not JSONB) to preserve exact byte-for-byte serialization
--     order, which is critical for SHA-256 digest verification. JSONB would re-serialize
--     and potentially reorder keys, breaking the digest check.
--   - `wasm_bytes` is BYTEA. Capsules are typically 4–64 KB. The column is nullable
--     to allow gradual backfill of existing capsule records.
--   - `ast_bytes` is BYTEA. Stores the serialized AST (MessagePack) for policy
--     re-compilation audits. Also nullable for backward compatibility.
--   - Both new capsule columns are added with IF NOT EXISTS guards for idempotency.

-- ─── eiaa_executions: add input_context ──────────────────────────────────────

ALTER TABLE eiaa_executions
    ADD COLUMN IF NOT EXISTS input_context TEXT;

COMMENT ON COLUMN eiaa_executions.input_context IS
    'Full serialized AuthorizationContext JSON used as input to the capsule execution. '
    'Stored verbatim (not as JSONB) to preserve exact byte order for SHA-256 digest '
    'verification during re-execution. NULL for records created before migration 031.';

-- Index for re-execution queries that filter by tenant + action + time range
-- (the re-execution service loads records by decision_ref, but this helps bulk audits)
CREATE INDEX IF NOT EXISTS idx_eiaa_executions_tenant_created
    ON eiaa_executions(tenant_id, created_at DESC);

-- ─── eiaa_capsules: add wasm_bytes and ast_bytes ──────────────────────────────

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS wasm_bytes BYTEA;

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS ast_bytes BYTEA;

COMMENT ON COLUMN eiaa_capsules.wasm_bytes IS
    'Compiled WASM binary for this capsule. Required for cache-miss execution fallback '
    'and cryptographic re-execution verification. NULL for capsules compiled before '
    'migration 031 (these must be recompiled to populate this column).';

COMMENT ON COLUMN eiaa_capsules.ast_bytes IS
    'MessagePack-serialized AST of the policy at compile time. Used for policy '
    're-compilation audits and diff analysis. NULL for pre-031 capsules.';

-- Partial index: quickly find capsules that still need WASM backfill
CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_missing_wasm
    ON eiaa_capsules(tenant_id, created_at DESC)
    WHERE wasm_bytes IS NULL;

-- ─── eiaa_capsules: add tenant_id index if missing ───────────────────────────
-- Migration 006 only created (tenant_id, action) index. Add tenant-only index
-- for the load_capsule_from_db() fallback which queries by (tenant_id, action)
-- but also needs efficient tenant-scoped listing.
CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_tenant_id
    ON eiaa_capsules(tenant_id);

-- ─── eiaa_executions: ensure capsule_id FK is indexed ────────────────────────
-- Migration 011 added capsule_hash_b64 but not a direct FK to eiaa_capsules.id.
-- Add capsule_id column (nullable, for records where capsule is known by ID).
ALTER TABLE eiaa_executions
    ADD COLUMN IF NOT EXISTS capsule_id VARCHAR(64)
    REFERENCES eiaa_capsules(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_eiaa_executions_capsule_id
    ON eiaa_executions(capsule_id)
    WHERE capsule_id IS NOT NULL;

COMMENT ON COLUMN eiaa_executions.capsule_id IS
    'Direct FK to eiaa_capsules.id. Populated when the capsule is known at execution '
    'time. NULL for executions where only the hash was available (pre-031 records).';

-- Made with Bob