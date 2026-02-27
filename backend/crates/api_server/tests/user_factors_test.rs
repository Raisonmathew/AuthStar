use api_server::services::UserFactorService;
use sqlx::postgres::PgPoolOptions;
use std::env;
use totp_rs::{Algorithm, TOTP, Secret};
use uuid::Uuid;

#[tokio::test]
async fn test_user_factor_flow() -> anyhow::Result<()> {
    // Setup
    dotenvy::from_filename(".env").ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
        
    let service = UserFactorService::new(pool.clone());
    
    // Create dummy user and tenant to rely on
    // In a real test we'd insert into users/organizations first, 
    // or rely on existing ones. Since we have existing users (based on migration history), let's use a random ID
    // expecting FK constraints might fail if user doesn't exist.
    // Let's first ensure we have a valid user.
    
    let user_id = format!("user_{}", Uuid::new_v4().to_string().replace("-", ""));
    let tenant_id = format!("tenant_{}", Uuid::new_v4().to_string().replace("-", ""));
    
    // Create org/user logic omitted for brevity, checking if FKs are enforced in migration 024.
    // Migration 024: user_id REFERS users(id). So we MUST insert a user.
    
    // Insert dummy user
    // Insert dummy user
    sqlx::query(r#"
        INSERT INTO users (id, first_name, last_name)
        VALUES ($1, 'Test', 'User')
        ON CONFLICT DO NOTHING
    "#)
    .bind(&user_id)
    .execute(&pool).await?;

    // Enrollment
    println!("Initiating enrollment...");
    let (factor_id, secret_str) = service.initiate_enrollment(&user_id, &tenant_id, "totp").await?;
    println!("Factor ID: {}", factor_id);
    println!("Secret: {}", secret_str);
    
    // Verify with wrong code
    println!("Verifying with wrong code...");
    let result = service.verify_enrollment(&user_id, &tenant_id, &factor_id, "000000").await;
    assert!(result.is_ok()); // Should return Ok(false) or similar? 
    // Wait, verify_enrollment returns Result<bool>.
    assert!(!result.unwrap());
    
    // Generate valid code
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid base32 secret"))?;
        
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        "IDaaS".to_string(),
    ).unwrap();
    let code = totp.generate_current().unwrap();
    
    // Verify with valid code (enrollment)
    println!("Verifying with valid code: {}", code);
    let valid = service.verify_enrollment(&user_id, &tenant_id, &factor_id, &code).await?;
    assert!(valid, "Factor verification failed with valid code");
    
    // --- Step-Up Test ---
    println!("Testing step-up verification...");
    
    // Create provisional session
    let session_id = format!("sess_{}", Uuid::new_v4().to_string().replace("-", ""));
    let decision_ref = "dec_test";
    
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, assurance_level, verified_capabilities, is_provisional)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3, 'end_user', $4, 'aal1', '["password"]'::jsonb, true)
        "#
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&tenant_id)
    .bind(&decision_ref)
    .execute(&pool).await?;

    // Verify factor for session step-up
    // Generate new code (might be same if time hasn't changed, but let's regen)
    let code_stepup = totp.generate_current().unwrap();
    
    let stepup_valid = service.verify_factor_for_session(&user_id, &tenant_id, &session_id, &factor_id, &code_stepup).await?;
    assert!(stepup_valid, "Step-up verification failed");
    
    // Check session updated
    #[derive(sqlx::FromRow)]
    struct SessionRow {
        assurance_level: Option<String>,
        is_provisional: Option<bool>,
        verified_capabilities: Option<serde_json::Value>,
    }

    let session = sqlx::query_as::<_, SessionRow>(
        "SELECT assurance_level, is_provisional, verified_capabilities FROM sessions WHERE id = $1"
    )
    .bind(&session_id)
    .fetch_one(&pool).await?;
    
    assert_eq!(session.assurance_level.as_deref(), Some("aal2"));
    assert_eq!(session.is_provisional, Some(false));
    
    // verified_capabilities should contain "totp"
    // It's returned as serde_json::Value
    let capabilities_val = session.verified_capabilities.expect("Capabilities missing");
    let capabilities = capabilities_val.as_array().expect("Capabilities not an array");
    let has_totp = capabilities.iter().any(|v| v.as_str() == Some("totp"));
    assert!(has_totp, "verified_capabilities missing 'totp'");

    // List factors
    println!("Listing factors...");
    let factors = service.list_factors(&user_id, &tenant_id).await?;
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].status, "active");
    
    // Delete factor
    println!("Deleting factor...");
    service.delete_factor(&user_id, &tenant_id, &factor_id).await?;
    
    let factors_after = service.list_factors(&user_id, &tenant_id).await?;
    assert_eq!(factors_after.len(), 0);
    
    // Cleanup
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(&user_id).execute(&pool).await?; // Create cleanup
    sqlx::query("DELETE FROM users WHERE id = $1").bind(&user_id).execute(&pool).await?;
    
    Ok(())
}
