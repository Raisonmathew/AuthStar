-- Remove check constraint on role column in memberships table to allow custom roles
-- Reverting to standard naming convention due to issues with DO block in migration runner
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_role_check;
