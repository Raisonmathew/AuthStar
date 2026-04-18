-- Migration 049: Unify session AAL on a single SMALLINT column.
--
-- Background:
--   Migration 017/023/026 added `sessions.assurance_level VARCHAR` and code
--   wrote string values like "aal1"/"aal2" into it.
--   Migration 036 added `sessions.aal_level SMALLINT` and the EIAA middleware
--   (eiaa_authz.rs) reads from it, but no code wrote to it. Result: AAL
--   enforcement was effectively dead code (always read 0).
--
-- This migration:
--   1. Backfills `aal_level` from `assurance_level` where `aal_level = 0`
--      and `assurance_level` looks like "aal1"/"aal2"/"aal3" (case-insensitive).
--   2. Drops the dependent index `idx_sessions_assurance_level`.
--   3. Drops the redundant `assurance_level` VARCHAR column.
--
-- All Rust call sites are updated in the same change set to write
-- `aal_level SMALLINT` (0/1/2/3) directly. The `Aal` helper enum in
-- `shared_types::auth::aal` provides safe conversions.

BEGIN;

-- 1. Backfill aal_level from assurance_level for sessions that have a string
--    AAL but a default-zero numeric AAL. Idempotent: only updates rows where
--    aal_level is still 0 and assurance_level encodes a higher level.
UPDATE sessions
SET aal_level = CASE LOWER(assurance_level)
        WHEN 'aal0' THEN 0
        WHEN 'aal1' THEN 1
        WHEN 'aal2' THEN 2
        WHEN 'aal3' THEN 3
        ELSE aal_level
    END
WHERE assurance_level IS NOT NULL
  AND aal_level = 0
  AND LOWER(assurance_level) IN ('aal1', 'aal2', 'aal3');

-- 2. Drop the legacy index that depends on the column.
DROP INDEX IF EXISTS idx_sessions_assurance_level;

-- 3. Drop the legacy column. All writers/readers now use aal_level SMALLINT.
ALTER TABLE sessions DROP COLUMN IF EXISTS assurance_level;

COMMIT;
