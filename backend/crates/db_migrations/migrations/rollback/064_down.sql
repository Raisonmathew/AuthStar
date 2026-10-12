-- 064_down.sql — Rollback complete LDAP federation schema additions
DROP TABLE IF EXISTS ldap_group_members CASCADE;
DROP TABLE IF EXISTS ldap_groups CASCADE;

ALTER TABLE ldap_connections
    DROP COLUMN IF EXISTS use_starttls,
    DROP COLUMN IF EXISTS group_base_dn,
    DROP COLUMN IF EXISTS group_search_filter,
    DROP COLUMN IF EXISTS sync_groups;
