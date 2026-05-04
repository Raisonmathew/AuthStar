-- Rollback for 053_unified_credentials.sql
-- Safe to drop: Phase 1 means no application reads or writes to this table.
DROP TRIGGER IF EXISTS update_credentials_updated_at ON credentials;
DROP TABLE IF EXISTS credentials;
