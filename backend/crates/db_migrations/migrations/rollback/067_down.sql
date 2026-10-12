-- 067_down.sql — Rollback LDAP failover_hosts and search_scope columns
ALTER TABLE ldap_connections
    DROP COLUMN IF EXISTS failover_hosts,
    DROP COLUMN IF EXISTS search_scope;
