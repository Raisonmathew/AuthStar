//! User Location Service
//!
//! Tracks user login locations for geo velocity detection.
//! Computes user baselines and detects impossible travel.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Location record for a single login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip_address: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// User's computed geo baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGeoBaseline {
    pub user_id: String,
    pub primary_country: Option<String>,
    pub primary_city: Option<String>,
    pub common_countries: Vec<String>,
    pub avg_latitude: Option<f64>,
    pub avg_longitude: Option<f64>,
    pub max_observed_distance_km: Option<f64>,
    pub login_count: i32,
}

/// Geo velocity analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoVelocityResult {
    pub velocity_km_h: Option<f64>,
    pub distance_km: Option<f64>,
    pub time_hours: Option<f64>,
    pub is_impossible_travel: bool,
    pub country_changed: bool,
    pub is_new_country: bool,
}

/// User location tracking service
#[derive(Clone)]
pub struct UserLocationService {
    db: PgPool,
}

impl UserLocationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Record a login location
    pub async fn record_login(
        &self,
        user_id: &str,
        org_id: &str,
        location: &GeoLocation,
        device_id: Option<&str>,
        auth_method: &str,
        success: bool,
    ) -> anyhow::Result<()> {
        let id = shared_types::id_generator::generate_id("geo");

        sqlx::query(
            r#"
            INSERT INTO user_geo_history (
                id, user_id, org_id, ip_address, country_code, city,
                latitude, longitude, device_id, auth_method, success
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(org_id)
        .bind(&location.ip_address)
        .bind(&location.country_code)
        .bind(&location.city)
        .bind(location.latitude)
        .bind(location.longitude)
        .bind(device_id)
        .bind(auth_method)
        .bind(success)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Get the last N login locations for a user
    pub async fn get_recent_logins(
        &self,
        user_id: &str,
        limit: i32,
    ) -> anyhow::Result<Vec<(GeoLocation, DateTime<Utc>)>> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                Option<f64>,
                Option<f64>,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT ip_address, country_code, city, 
                   latitude::FLOAT8, longitude::FLOAT8, 
                   created_at
            FROM user_geo_history
            WHERE user_id = $1 AND success = true
            ORDER BY created_at DESC
            LIMIT $2
        "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(ip, country, city, lat, lon, ts)| {
                (
                    GeoLocation {
                        ip_address: ip,
                        country_code: country,
                        city,
                        latitude: lat,
                        longitude: lon,
                    },
                    ts,
                )
            })
            .collect())
    }

    /// Analyze geo velocity between current and last login
    pub async fn analyze_velocity(
        &self,
        user_id: &str,
        current: &GeoLocation,
    ) -> anyhow::Result<GeoVelocityResult> {
        // Get last successful login
        let recent = self.get_recent_logins(user_id, 1).await?;

        if recent.is_empty() {
            // First login - no velocity
            return Ok(GeoVelocityResult {
                velocity_km_h: None,
                distance_km: None,
                time_hours: None,
                is_impossible_travel: false,
                country_changed: false,
                is_new_country: true,
            });
        }

        let (last_loc, last_time) = &recent[0];
        let now = Utc::now();

        // Check country change
        let country_changed = match (&current.country_code, &last_loc.country_code) {
            (Some(c1), Some(c2)) => c1 != c2,
            _ => false,
        };

        // Check if new country for this user
        let is_new_country = if let Some(ref cc) = current.country_code {
            !self.has_visited_country(user_id, cc).await.unwrap_or(true)
        } else {
            false
        };

        // Calculate velocity if we have coordinates
        match (
            current.latitude,
            current.longitude,
            last_loc.latitude,
            last_loc.longitude,
        ) {
            (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) => {
                let distance_km = haversine_distance(lat1, lon1, lat2, lon2);
                let duration = now.signed_duration_since(*last_time);
                let time_hours = duration.num_seconds() as f64 / 3600.0;

                // Handle edge case of very short time
                let velocity_km_h = if time_hours > 0.01 {
                    Some(distance_km / time_hours)
                } else {
                    None
                };

                // Impossible travel: > 1000 km/h (supersonic)
                let is_impossible_travel = velocity_km_h.map(|v| v > 1000.0).unwrap_or(false);

                Ok(GeoVelocityResult {
                    velocity_km_h,
                    distance_km: Some(distance_km),
                    time_hours: Some(time_hours),
                    is_impossible_travel,
                    country_changed,
                    is_new_country,
                })
            }
            _ => {
                // No coordinates - can only check country
                Ok(GeoVelocityResult {
                    velocity_km_h: None,
                    distance_km: None,
                    time_hours: None,
                    is_impossible_travel: false,
                    country_changed,
                    is_new_country,
                })
            }
        }
    }

    /// Check if user has visited a country before
    async fn has_visited_country(&self, user_id: &str, country: &str) -> anyhow::Result<bool> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM user_geo_history
            WHERE user_id = $1 AND country_code = $2 AND success = true
        "#,
        )
        .bind(user_id)
        .bind(country)
        .fetch_one(&self.db)
        .await?;

        Ok(count > 0)
    }

    /// Get user's geo baseline
    pub async fn get_baseline(&self, user_id: &str) -> anyhow::Result<Option<UserGeoBaseline>> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                serde_json::Value,
                Option<f64>,
                Option<f64>,
                Option<f64>,
                i32,
            ),
        >(
            r#"
            SELECT user_id, primary_country, primary_city, common_countries,
                   avg_latitude::FLOAT8, avg_longitude::FLOAT8, 
                   max_observed_distance_km::FLOAT8, login_count
            FROM user_geo_baselines
            WHERE user_id = $1
        "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(row.map(
            |(uid, pc, pcity, cc, lat, lon, dist, count)| UserGeoBaseline {
                user_id: uid,
                primary_country: pc,
                primary_city: pcity,
                common_countries: serde_json::from_value(cc).unwrap_or_default(),
                avg_latitude: lat,
                avg_longitude: lon,
                max_observed_distance_km: dist,
                login_count: count,
            },
        ))
    }
}

/// Haversine distance between two coordinates (in km)
pub(crate) fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    R * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_distance() {
        // New York to London: ~5570 km
        let dist = haversine_distance(40.7128, -74.0060, 51.5074, -0.1278);
        assert!(dist > 5500.0 && dist < 5700.0, "Distance: {dist}");

        // Same point
        let dist2 = haversine_distance(0.0, 0.0, 0.0, 0.0);
        assert!(dist2 < 0.001);
    }
}
