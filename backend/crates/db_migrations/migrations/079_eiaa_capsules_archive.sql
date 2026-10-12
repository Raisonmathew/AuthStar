-- Migration 079: Capsule Version Archive (Gap 2-A — Compliance Tier)
--
-- SOC 2 evidence requires knowing the exact capsule policy active at any point
-- in time.  The existing `eiaa_capsules` table uses ON CONFLICT … DO UPDATE which
-- overwrites rows — there is no way to reconstruct the capsule that was active
-- on a given date.
--
-- This migration adds `archived_at` (nullable = still active) so the activation
-- path can soft-archive the previous row instead of overwriting it.  The compliance
-- export query can then reconstruct the exact capsule at any timestamp using:
--
--   WHERE tenant_id = $1
--     AND action    = $2
--     AND (archived_at IS NULL OR archived_at > $target_ts)
--     AND created_at <= $target_ts
--   ORDER BY created_at DESC LIMIT 1

ALTER TABLE eiaa_capsules
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

-- Index for the time-travel query used by the compliance export endpoint.
CREATE INDEX IF NOT EXISTS idx_eiaa_capsules_compliance_timetravel
    ON eiaa_capsules (tenant_id, action, principal_type, created_at DESC, archived_at);

COMMENT ON COLUMN eiaa_capsules.archived_at IS
    'NULL = currently active.  Set to NOW() when a newer activation replaces this row.  '
    'Never deleted — required for SOC 2 compliance evidence.';
