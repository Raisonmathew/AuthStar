-- EIAA Risk Engine: Geo Velocity Tables
-- Migration 018: User geo history for velocity detection

-- User Geo History (for geo velocity detection)
-- Tracks last N login locations per user for impossible travel detection
CREATE TABLE IF NOT EXISTS user_geo_history (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    country_code VARCHAR(2),
    city VARCHAR(100),
    latitude DECIMAL(9,6),
    longitude DECIMAL(9,6),
    device_id VARCHAR(255),  -- Optional reference to device_records
    auth_method VARCHAR(50),  -- 'password' | 'totp' | 'passkey' | etc
    success BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_user_geo_history_user ON user_geo_history(user_id);
CREATE INDEX idx_user_geo_history_org ON user_geo_history(org_id);
CREATE INDEX idx_user_geo_history_recent ON user_geo_history(user_id, created_at DESC);
CREATE INDEX idx_user_geo_history_country ON user_geo_history(user_id, country_code);

-- User Geo Baseline (computed baseline for each user)
-- Updated periodically from user_geo_history
CREATE TABLE IF NOT EXISTS user_geo_baselines (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    primary_country VARCHAR(2),           -- Most common country
    primary_city VARCHAR(100),            -- Most common city
    common_countries JSONB NOT NULL DEFAULT '[]'::jsonb,  -- Top N countries
    common_ips JSONB NOT NULL DEFAULT '[]'::jsonb,        -- Top N IPs
    avg_latitude DECIMAL(9,6),
    avg_longitude DECIMAL(9,6),
    max_observed_distance_km DECIMAL(10,2),  -- Maximum distance between logins
    login_count INTEGER NOT NULL DEFAULT 0,
    last_computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_geo_baselines_org ON user_geo_baselines(org_id);

-- Function to calculate distance between two points (Haversine formula)
-- Returns distance in kilometers
CREATE OR REPLACE FUNCTION haversine_distance(
    lat1 DECIMAL, lon1 DECIMAL,
    lat2 DECIMAL, lon2 DECIMAL
) RETURNS DECIMAL AS $$
DECLARE
    R CONSTANT DECIMAL := 6371; -- Earth radius in km
    dlat DECIMAL;
    dlon DECIMAL;
    a DECIMAL;
    c DECIMAL;
BEGIN
    dlat := RADIANS(lat2 - lat1);
    dlon := RADIANS(lon2 - lon1);
    a := SIN(dlat/2) * SIN(dlat/2) + 
         COS(RADIANS(lat1)) * COS(RADIANS(lat2)) * 
         SIN(dlon/2) * SIN(dlon/2);
    c := 2 * ATAN2(SQRT(a), SQRT(1-a));
    RETURN R * c;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
