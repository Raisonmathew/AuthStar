use risk_engine::signals::{NetworkInput, SignalCollector, IpLocateClient};
use shared_types::GeoVelocity;
use sqlx::{Pool, Postgres};
use chrono::{Utc, Duration};
use std::net::IpAddr;
use std::str::FromStr;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

// Helper to seed location
async fn seed_location(
    pool: &Pool<Postgres>,
    user_id: &str,
    ip: &str,
    country: &str,
    lat: f64,
    lon: f64,
    timestamp: chrono::DateTime<Utc>,
) {
    let id = shared_types::generate_id("geo");
    sqlx::query(r#"
        INSERT INTO user_geo_history (
            id, user_id, org_id, ip_address, country_code, city,
            latitude, longitude, device_id, auth_method, success, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    "#)
    .bind(id)
    .bind(user_id)
    .bind("org_test")
    .bind(ip)
    .bind(country)
    .bind("SeedCity")
    .bind(lat)
    .bind(lon)
    .bind("dev_1")
    .bind("password")
    .bind(true)
    .bind(timestamp)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn test_impossible_travel_detection(pool: Pool<Postgres>) {
    // 0. Run Migrations
    sqlx::migrate!("../db_migrations/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // 1. Start Mock Server
    let mock_server = MockServer::start().await;

    // 2. Setup User & Org (Satisfy FKs)
    let user_id = "user_travel_test";
    
    // Insert User
    sqlx::query("INSERT INTO users (id, first_name) VALUES ($1, 'TestUser')")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("Failed to seed user");

    // Insert Org
    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, 'TestOrg', 'test-org')")
        .bind("org_test")
        .execute(&pool)
        .await
        .expect("Failed to seed org");

    // 3. Setup User History: NYC Login 10 minutes ago
    seed_location(
        &pool, 
        user_id, 
        "1.1.1.1", 
        "US", 
        40.7128, -74.0060, // New York
        Utc::now() - Duration::minutes(10)
    ).await;

    // Verify seed success
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_geo_history WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "Seeding failed");

    // 4. Mock IP Response for London (Current Request)
    // Distance NYC -> London is ~5500km
    Mock::given(method("GET"))
        .and(path("/8.8.8.8")) // London IP
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ip": "8.8.8.8",
            "country": "United Kingdom",
            "country_code": "GB",
            "city": "London",
            "latitude": 51.5074,
            "longitude": -0.1278,
            "asn": 12345,
            "org": "Google",
            "is_datacenter": false
        })))
        .mount(&mock_server)
        .await;

    // 4. Configure Client
    let client = IpLocateClient::new(Some("test_key".into()), true)
        .with_base_url(mock_server.uri());
    
    // 5. Run Collector
    let collector = SignalCollector::with_iplocate(pool.clone(), client);
    
    let input = NetworkInput {
        remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
        x_forwarded_for: None,
        user_agent: "Mozilla/5.0".into(),
        accept_language: Some("en-US".into()),
        timestamp: Utc::now(),
    };

    let signals = collector.collect(&input, None, Some(user_id)).await;

    // 6. Assertions
    assert_eq!(signals.network.country, Some("GB".to_string()));
    assert!(signals.network.country_changed, "Country change should be detected");
    
    // NYC to London (~5500km) in 10 mins is > 30,000 km/h -> Impossible
    assert_eq!(signals.network.geo_velocity, GeoVelocity::Impossible, 
        "Travel detection failed. Got: {:?}", signals.network.geo_velocity);
}
