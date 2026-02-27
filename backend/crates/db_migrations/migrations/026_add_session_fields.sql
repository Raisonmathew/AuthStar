-- Add EIAA session fields
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS assurance_level VARCHAR(50) DEFAULT 'aal1';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS verified_capabilities JSONB DEFAULT '["password"]'::jsonb;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_provisional BOOLEAN DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
