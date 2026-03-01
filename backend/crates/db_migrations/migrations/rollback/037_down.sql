-- Rollback migration 037: API Keys
-- Drops the api_keys table and all associated indexes, policies, and RLS.
-- WARNING: All API key data will be permanently lost.

DROP TABLE IF EXISTS api_keys;