-- Migration 038: Fix API Keys RLS for Cross-Tenant Auth Lookup
--
-- FUNC-6 FIX: Migration 037 enabled FORCE ROW LEVEL SECURITY on api_keys with a
-- single policy requiring app.current_tenant_id to be set. This breaks the
-- authenticate_api_key() function in api_key_auth middleware, which must perform
-- a cross-tenant prefix lookup BEFORE the tenant is known (the tenant is derived
-- FROM the key, not the other way around).
--
-- Root cause: The auth lookup path (middleware) is a system-level operation that
-- must find a key by prefix across all tenants. The management CRUD paths (list,
-- create, revoke) are correctly tenant-scoped via JWT claims.
--
-- Fix: Replace the single restrictive policy with two policies:
--   1. api_keys_tenant_isolation — for management operations (tenant-scoped reads/writes)
--   2. api_keys_auth_lookup      — for the auth middleware (cross-tenant prefix reads only)
--
-- The auth lookup policy allows SELECT when app.current_tenant_id is NOT set
-- (i.e. the request is coming from the auth middleware before tenant context is
-- established). All INSERT/UPDATE/DELETE operations still require tenant context.

-- Drop the existing policy from migration 037
DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;

-- Policy 1: Tenant-scoped management operations (list, create, revoke)
-- Applies to all operations when app.current_tenant_id IS set.
-- This is the normal path for authenticated management API calls.
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
    );

-- Policy 2: Cross-tenant auth lookup (SELECT only, no tenant context required)
-- Applies to SELECT operations when app.current_tenant_id is NOT set.
-- This is the path used by api_key_auth_middleware to look up a key by prefix
-- before the tenant is known. The middleware then verifies the key hash and
-- extracts the tenant_id from the matched row.
--
-- Security: This policy only allows SELECT (read). INSERT/UPDATE/DELETE always
-- require tenant context via Policy 1. An unauthenticated caller can only read
-- key metadata (prefix, hash, scopes) — they cannot create or modify keys.
-- The key_hash is an Argon2id hash; reading it does not expose the plaintext key.
CREATE POLICY api_keys_auth_lookup ON api_keys
    FOR SELECT
    USING (
        current_setting('app.current_tenant_id', true) IS NULL
        OR current_setting('app.current_tenant_id', true) = ''
    );

-- Verify both policies exist
-- (informational comment — psql \d api_keys will show them)