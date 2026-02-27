-- Add branding_config column to organizations table
-- This column stores JSON branding configuration for hosted login pages

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS branding_config JSONB DEFAULT NULL;

-- Add index for faster queries when filtering by branding
CREATE INDEX IF NOT EXISTS idx_organizations_branding ON organizations USING GIN (branding_config) WHERE branding_config IS NOT NULL;
