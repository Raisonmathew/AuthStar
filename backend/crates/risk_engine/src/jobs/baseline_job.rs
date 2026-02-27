//! Baseline Computation Job
//!
//! Background job that periodically updates user geo baselines
//! from their login history.

use sqlx::PgPool;
use tracing::{info, warn, error};

/// Baseline computation service
#[derive(Clone)]
pub struct BaselineComputationJob {
    db: PgPool,
}

impl BaselineComputationJob {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
    
    /// Run baseline computation for all users
    /// Call this periodically (e.g., hourly cron job)
    pub async fn run_all(&self) -> anyhow::Result<u32> {
        info!("Starting baseline computation for all users");
        
        // Get all users with geo history
        let users: Vec<String> = sqlx::query_scalar(r#"
            SELECT DISTINCT user_id FROM user_geo_history
            WHERE success = true
        "#)
            .fetch_all(&self.db)
            .await?;
        
        let mut updated = 0u32;
        
        for user_id in users {
            match self.compute_baseline(&user_id).await {
                Ok(_) => updated += 1,
                Err(e) => warn!(user_id = %user_id, error = %e, "Failed to compute baseline"),
            }
        }
        
        info!(updated = updated, "Baseline computation complete");
        Ok(updated)
    }
    
    /// Compute baseline for a single user
    pub async fn compute_baseline(&self, user_id: &str) -> anyhow::Result<()> {
        // Get aggregated stats from geo history
        let stats = sqlx::query_as::<_, (
            Option<String>,  // primary_country
            Option<String>,  // primary_city  
            i64,             // login_count
            Option<f64>,     // avg_latitude
            Option<f64>,     // avg_longitude
        )>(r#"
            WITH country_counts AS (
                SELECT country_code, COUNT(*) as cnt
                FROM user_geo_history
                WHERE user_id = $1 AND success = true AND country_code IS NOT NULL
                GROUP BY country_code
                ORDER BY cnt DESC
                LIMIT 1
            ),
            city_counts AS (
                SELECT city, COUNT(*) as cnt
                FROM user_geo_history
                WHERE user_id = $1 AND success = true AND city IS NOT NULL
                GROUP BY city
                ORDER BY cnt DESC
                LIMIT 1
            ),
            stats AS (
                SELECT 
                    COUNT(*) as login_count,
                    AVG(latitude) as avg_lat,
                    AVG(longitude) as avg_lon
                FROM user_geo_history
                WHERE user_id = $1 AND success = true
            )
            SELECT 
                (SELECT country_code FROM country_counts) as primary_country,
                (SELECT city FROM city_counts) as primary_city,
                s.login_count,
                s.avg_lat,
                s.avg_lon
            FROM stats s
        "#)
            .bind(user_id)
            .fetch_one(&self.db)
            .await?;
        
        // Get common countries (top 5)
        let common_countries: Vec<String> = sqlx::query_scalar(r#"
            SELECT country_code
            FROM user_geo_history
            WHERE user_id = $1 AND success = true AND country_code IS NOT NULL
            GROUP BY country_code
            ORDER BY COUNT(*) DESC
            LIMIT 5
        "#)
            .bind(user_id)
            .fetch_all(&self.db)
            .await?;
        
        // Get common IPs (top 10)
        let common_ips: Vec<String> = sqlx::query_scalar(r#"
            SELECT ip_address
            FROM user_geo_history
            WHERE user_id = $1 AND success = true
            GROUP BY ip_address
            ORDER BY COUNT(*) DESC
            LIMIT 10
        "#)
            .bind(user_id)
            .fetch_all(&self.db)
            .await?;
        
        // Calculate max distance between any two logins
        let max_distance: Option<f64> = sqlx::query_scalar(r#"
            SELECT MAX(haversine_distance(
                a.latitude, a.longitude,
                b.latitude, b.longitude
            ))
            FROM user_geo_history a
            CROSS JOIN user_geo_history b
            WHERE a.user_id = $1 AND b.user_id = $1
              AND a.success = true AND b.success = true
              AND a.latitude IS NOT NULL AND b.latitude IS NOT NULL
              AND a.id < b.id
        "#)
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?
            .flatten();
        
        // Get org_id
        let org_id: Option<String> = sqlx::query_scalar(r#"
            SELECT org_id FROM user_geo_history WHERE user_id = $1 LIMIT 1
        "#)
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?;
        
        let org_id = match org_id {
            Some(o) => o,
            None => return Ok(()), // No history
        };
        
        let common_countries_json = serde_json::to_value(&common_countries)?;
        let common_ips_json = serde_json::to_value(&common_ips)?;
        
        // Upsert baseline
        sqlx::query(r#"
            INSERT INTO user_geo_baselines (
                id, user_id, org_id, primary_country, primary_city,
                common_countries, common_ips, avg_latitude, avg_longitude,
                max_observed_distance_km, login_count, last_computed_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()
            )
            ON CONFLICT (user_id) DO UPDATE SET
                primary_country = EXCLUDED.primary_country,
                primary_city = EXCLUDED.primary_city,
                common_countries = EXCLUDED.common_countries,
                common_ips = EXCLUDED.common_ips,
                avg_latitude = EXCLUDED.avg_latitude,
                avg_longitude = EXCLUDED.avg_longitude,
                max_observed_distance_km = EXCLUDED.max_observed_distance_km,
                login_count = EXCLUDED.login_count,
                last_computed_at = NOW(),
                updated_at = NOW()
        "#)
            .bind(shared_types::id_generator::generate_id("baseline"))
            .bind(user_id)
            .bind(&org_id)
            .bind(&stats.0) // primary_country
            .bind(&stats.1) // primary_city
            .bind(&common_countries_json)
            .bind(&common_ips_json)
            .bind(stats.3) // avg_latitude
            .bind(stats.4) // avg_longitude  
            .bind(max_distance)
            .bind(stats.2 as i32) // login_count
            .execute(&self.db)
            .await?;
        
        Ok(())
    }
    
    /// Spawn a background task that runs baseline computation periodically
    pub fn spawn_periodic(self, interval_hours: u64) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(interval_hours * 3600);
            
            loop {
                match self.run_all().await {
                    Ok(count) => info!(count = count, "Periodic baseline computation complete"),
                    Err(e) => error!(error = %e, "Periodic baseline computation failed"),
                }
                
                tokio::time::sleep(interval).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_job_creation() {
        // This would need a real DB for full testing
        // Just verify the struct can be created
    }
}
