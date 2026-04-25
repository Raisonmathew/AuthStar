-- Repair migration: reconcile bootstrap admin memberships on environments
-- that were initialized before the current bootstrap role expectations.

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