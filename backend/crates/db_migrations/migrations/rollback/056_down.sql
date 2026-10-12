-- 056_down.sql — Rollback client_scopes (T2.8)
DROP TABLE IF EXISTS client_scope_mappings CASCADE;
DROP TABLE IF EXISTS client_scopes CASCADE;
