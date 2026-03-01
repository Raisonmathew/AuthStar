-- Rollback migration 033: Reconcile EIAA schema
-- Removes columns and constraints added by 033_reconcile_eiaa_schema.sql
-- WARNING: This will drop data in wasm_bytes and ast_bytes columns.

-- Drop wasm_bytes and ast_bytes from eiaa_capsules if added by 033
ALTER TABLE eiaa_capsules
    DROP COLUMN IF EXISTS wasm_bytes,
    DROP COLUMN IF EXISTS ast_bytes;

-- Drop eiaa_replay_nonces table if created by 033
DROP TABLE IF EXISTS eiaa_replay_nonces;

-- Note: Schema reconciliation changes (idempotent column additions, index
-- additions) are not fully reversible without knowing the exact prior state.
-- This rollback removes the additions made by 033 only.