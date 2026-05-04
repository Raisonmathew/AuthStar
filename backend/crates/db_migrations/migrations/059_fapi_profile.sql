-- T4.4 — FAPI 2.0 profile column on applications
--
-- Stores which FAPI profile (if any) an OAuth 2.0 client opts into.
-- NULL means standard OAuth 2.0/OIDC (no FAPI hardening).
-- 'fapi2' means FAPI 2.0 Security Profile: PAR required, PKCE required,
-- DPoP required, max access-token lifetime 300 s, s_hash in ID token.
--
-- The column is intentionally TEXT rather than an enum so that future
-- profile variants (fapi2-message-signing, etc.) can be added without
-- a schema migration.

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS fapi_profile TEXT NULL;
