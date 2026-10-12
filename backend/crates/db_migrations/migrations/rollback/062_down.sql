-- 062_down.sql — Rollback LDAP Keycloak-parity enhancements
-- Drops ldap_sync_runs, ldap_federated_users, ldap_mappers added in 062.
-- Removes Keycloak-parity columns added to ldap_connections.
DROP TABLE IF EXISTS ldap_mappers CASCADE;
DROP TABLE IF EXISTS ldap_federated_users CASCADE;
DROP TABLE IF EXISTS ldap_sync_runs CASCADE;

-- Remove columns added to ldap_connections by 062
ALTER TABLE ldap_connections
    DROP COLUMN IF EXISTS sync_interval_secs,
    DROP COLUMN IF EXISTS sync_enabled,
    DROP COLUMN IF EXISTS user_object_class,
    DROP COLUMN IF EXISTS group_object_class,
    DROP COLUMN IF EXISTS username_ldap_attribute,
    DROP COLUMN IF EXISTS rdn_ldap_attribute,
    DROP COLUMN IF EXISTS uuid_ldap_attribute,
    DROP COLUMN IF EXISTS user_ldap_filter,
    DROP COLUMN IF EXISTS group_name_ldap_attribute,
    DROP COLUMN IF EXISTS group_member_ldap_attribute;
