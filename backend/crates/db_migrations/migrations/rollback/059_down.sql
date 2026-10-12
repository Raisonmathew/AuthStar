-- 059_down.sql — Rollback FAPI 2.0 profile column on applications
ALTER TABLE applications DROP COLUMN IF EXISTS fapi_profile;
