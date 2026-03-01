-- MIGRATION SUPERSEDED — DO NOT USE
--
-- This file (032_backfill_capsule_bytes.sql) has been RENAMED to
-- 035_backfill_capsule_bytes.sql to resolve a migration prefix collision.
--
-- The original '032_' prefix was shared with:
--   032_session_decision_ref.sql (now 036_session_decision_ref.sql)
--
-- If your migration runner has already applied this file under the name
-- '032_backfill_capsule_bytes', the new 035_backfill_capsule_bytes.sql is
-- fully idempotent (all DDL uses IF NOT EXISTS / CREATE OR REPLACE guards)
-- and safe to apply on top of an already-migrated database.
--
-- ACTION REQUIRED:
--   1. Delete this file from your migration directory.
--   2. Ensure 035_backfill_capsule_bytes.sql is applied instead.
--   3. If using sqlx migrate, run: sqlx migrate run
--
-- This stub is intentionally a no-op so it does not break existing
-- migration runners that have already recorded this filename in their
-- schema_migrations table.

-- no-op: see 035_backfill_capsule_bytes.sql
SELECT 1;

-- Made with Bob
