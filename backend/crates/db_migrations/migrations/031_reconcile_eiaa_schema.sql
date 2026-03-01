-- MIGRATION SUPERSEDED — DO NOT USE
--
-- This file (031_reconcile_eiaa_schema.sql) has been RENAMED to
-- 033_reconcile_eiaa_schema.sql to resolve a migration prefix collision.
--
-- The original '031_' prefix was shared with:
--   031_eiaa_storage_columns.sql  (canonical 031)
--   031_flow_expiry_10min.sql     (now 034_flow_expiry_10min.sql)
--
-- If your migration runner has already applied this file under the name
-- '031_reconcile_eiaa_schema', the new 033_reconcile_eiaa_schema.sql is
-- fully idempotent (all DDL uses IF NOT EXISTS / DO NOTHING guards) and
-- safe to apply on top of an already-migrated database.
--
-- ACTION REQUIRED:
--   1. Delete this file from your migration directory.
--   2. Ensure 033_reconcile_eiaa_schema.sql is applied instead.
--   3. If using sqlx migrate, run: sqlx migrate run
--
-- This stub is intentionally a no-op so it does not break existing
-- migration runners that have already recorded this filename in their
-- schema_migrations table.

-- no-op: see 033_reconcile_eiaa_schema.sql
SELECT 1;

-- Made with Bob
