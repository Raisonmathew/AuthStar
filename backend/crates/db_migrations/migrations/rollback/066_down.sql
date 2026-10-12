-- 066_down.sql — Rollback read_timeout_secs and memberof_attr on ldap_connections
ALTER TABLE ldap_connections
    DROP COLUMN IF EXISTS read_timeout_secs,
    DROP COLUMN IF EXISTS memberof_attr;
