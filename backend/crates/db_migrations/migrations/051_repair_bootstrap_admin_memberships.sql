-- Repair migration: reconcile bootstrap admin memberships on environments
-- that were initialized before the current bootstrap role expectations.

-- Ensure prerequisite rows exist so FK constraints are not violated on fresh DBs.
-- The api_server bootstrap.rs performs the same upserts at startup; these are
-- minimal no-op stubs that let the migration run on a clean schema.

INSERT INTO organizations (id, slug, name)
VALUES
  ('system',  'admin',   'IDaaS Provider'),
  ('default', 'default', 'Default Organization')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, first_name, last_name, organization_id)
VALUES ('user_admin', 'System', 'Admin', 'system')
ON CONFLICT (id) DO NOTHING;

INSERT INTO memberships (id, organization_id, user_id, role, permissions, created_at, updated_at)
VALUES ('membership_admin_system', 'system', 'user_admin', 'owner', '{}'::jsonb, NOW(), NOW())
ON CONFLICT (organization_id, user_id) DO UPDATE
SET role = 'owner',
    updated_at = NOW();

INSERT INTO memberships (id, organization_id, user_id, role, permissions, created_at, updated_at)
VALUES ('membership_admin_default', 'default', 'user_admin', 'admin', '{}'::jsonb, NOW(), NOW())
ON CONFLICT (organization_id, user_id) DO UPDATE
SET role = 'admin',
    updated_at = NOW();