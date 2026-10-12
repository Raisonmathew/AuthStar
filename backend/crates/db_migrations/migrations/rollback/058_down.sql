-- 058_down.sql — Rollback SCIM 2.0 provisioning tables
DROP TABLE IF EXISTS scim_group_members CASCADE;
DROP TABLE IF EXISTS scim_groups CASCADE;
DROP TABLE IF EXISTS scim_users CASCADE;
DROP TABLE IF EXISTS scim_tokens CASCADE;
