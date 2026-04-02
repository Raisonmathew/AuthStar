use api_server::services::UserFactorService;
use sqlx::PgPool;
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_user_factor_flow(pool: PgPool) -> anyhow::Result<()> {
    let service = UserFactorService::new(pool.clone());

    let org_id = format!("org_{}", Uuid::new_v4().simple());
    let user_id = format!("user_{}", Uuid::new_v4().simple());

    // Seed organization (user_factors.org_id is NOT NULL FK → organizations)
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ($1, 'Factor Test Org', 'factor-test', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&org_id)
    .execute(&pool)
    .await?;

    // Insert user in that org
    sqlx::query(
        "INSERT INTO users (id, first_name, last_name, organization_id)
         VALUES ($1, 'Test', 'User', $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(&user_id)
    .bind(&org_id)
    .execute(&pool)
    .await?;

    // Enrollment — tenant_id must match the org we seeded
    let (factor_id, secret_str) =
        service.initiate_enrollment(&user_id, &org_id, "totp").await?;

    // Verify with wrong code
    let wrong = service
        .verify_enrollment(&user_id, &org_id, &factor_id, "000000")
        .await;
    assert!(wrong.is_ok());
    assert!(!wrong.unwrap());

    // Generate valid code
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid base32 secret"))?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, "IDaaS".to_string())
        .unwrap();
    let code = totp.generate_current().unwrap();

    let valid = service
        .verify_enrollment(&user_id, &org_id, &factor_id, &code)
        .await?;
    assert!(valid, "Factor verification failed with valid code");

    // --- Step-Up Test ---
    let session_id = format!("sess_{}", Uuid::new_v4().simple());
    let decision_ref = "dec_test";

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, assurance_level, verified_capabilities, is_provisional)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3, 'end_user', $4, 'aal1', '["password"]'::jsonb, true)
        "#,
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&org_id)
    .bind(decision_ref)
    .execute(&pool)
    .await?;

    let code_stepup = totp.generate_current().unwrap();
    let stepup_valid = service
        .verify_factor_for_session(&user_id, &org_id, &session_id, &factor_id, &code_stepup)
        .await?;
    assert!(stepup_valid, "Step-up verification failed");

    // Check session updated
    #[derive(sqlx::FromRow)]
    struct SessionRow {
        assurance_level: Option<String>,
        is_provisional: Option<bool>,
        verified_capabilities: Option<serde_json::Value>,
    }

    let session = sqlx::query_as::<_, SessionRow>(
        "SELECT assurance_level, is_provisional, verified_capabilities FROM sessions WHERE id = $1",
    )
    .bind(&session_id)
    .fetch_one(&pool)
    .await?;

    assert_eq!(session.assurance_level.as_deref(), Some("aal2"));
    assert_eq!(session.is_provisional, Some(false));

    let caps = session.verified_capabilities.expect("Capabilities missing");
    let arr = caps.as_array().expect("Capabilities not an array");
    assert!(arr.iter().any(|v| v.as_str() == Some("totp")), "missing 'totp'");

    // List factors
    let factors = service.list_factors(&user_id, &org_id).await?;
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].status, "active");

    // Delete factor
    service.delete_factor(&user_id, &org_id, &factor_id).await?;
    let factors_after = service.list_factors(&user_id, &org_id).await?;
    assert_eq!(factors_after.len(), 0);

    Ok(())
}
