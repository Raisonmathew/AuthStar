#![allow(dead_code)]
//! Hardening Test Suite — Phase 6
//!
//! Tests covering all hardening changes from Phases 1-5:
//! - Session revocation enforcement (Phase 1)
//! - Multi-tenant email isolation (Phase 2)
//! - Bootstrap password safety (Phase 5)
//!
//! Uses `#[sqlx::test]` with automatic migration provisioning.

use sqlx::PgPool;

mod common;
use common::seed::*;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PHASE 1: Session Revocation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Revoked sessions must not appear in active session queries.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoked_session_excluded_from_active_query(pool: PgPool) {
    let org_id = "org_revoke_1";
    let user_id = "usr_revoke_1";
    seed_org(&pool, org_id, "revoke-test-1").await;
    seed_user(&pool, user_id, org_id).await;

    // Create an active session
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_active', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW())"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("insert active session");

    // Create a revoked session
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at, revoked, revoked_at)
         VALUES ('sess_revoked', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW(), TRUE, NOW())"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("insert revoked session");

    // Query with the same pattern used in middleware/auth.rs
    let active_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE"
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count active sessions");

    assert_eq!(
        active_count.0, 1,
        "Only non-revoked session should be counted"
    );
}

/// Verify the revoke action sets both revoked=TRUE and revoked_at, and clamps expires_at.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_sets_correct_flags(pool: PgPool) {
    let org_id = "org_revoke_2";
    let user_id = "usr_revoke_2";
    seed_org(&pool, org_id, "revoke-test-2").await;
    seed_user(&pool, user_id, org_id).await;

    // Create a far-future session
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_to_revoke', $1, $2, $2, NOW() + INTERVAL '7 days', NOW())"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("insert session");

    // Execute the revoke pattern from routes/auth.rs (logout)
    sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
         WHERE id = $1 AND user_id = $2"
    )
    .bind("sess_to_revoke")
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("revoke session");

    // Verify the session state
    let row: (
        bool,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as(
        "SELECT revoked, revoked_at, expires_at FROM sessions WHERE id = 'sess_to_revoke'",
    )
    .fetch_one(&pool)
    .await
    .expect("fetch revoked session");

    assert!(row.0, "revoked must be TRUE");
    assert!(row.1.is_some(), "revoked_at must be set");
    // expires_at should now be <= NOW() (clamped by LEAST)
    assert!(
        row.2 <= chrono::Utc::now(),
        "expires_at should be clamped to <= NOW()"
    );
}

/// Invalidate-other-sessions only affects non-revoked sessions and excludes the current session.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_invalidate_other_sessions_scope(pool: PgPool) {
    let org_id = "org_revoke_3";
    let user_id = "usr_revoke_3";
    seed_org(&pool, org_id, "revoke-test-3").await;
    seed_user(&pool, user_id, org_id).await;

    // Create current session (should be preserved)
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_current', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW())"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    // Create other active sessions (should be revoked)
    for i in 1..=3 {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
             VALUES ($1, $2, $3, $3, NOW() + INTERVAL '1 hour', NOW())"
        )
        .bind(format!("sess_other_{i}"))
        .bind(user_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Revoke all other sessions (pattern from user_service.rs)
    let result = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
         WHERE user_id = $1 AND id != $2 AND expires_at > NOW() AND revoked = FALSE RETURNING id"
    )
    .bind(user_id)
    .bind("sess_current")
    .fetch_all(&pool)
    .await
    .expect("invalidate others");

    assert_eq!(result.len(), 3, "Should revoke exactly 3 other sessions");

    // Verify current session is still active
    let active: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(active.0, 1, "Only current session should remain active");
}

/// Double-revoke should be idempotent (second revoke affects 0 rows).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_double_revoke_is_idempotent(pool: PgPool) {
    let org_id = "org_revoke_4";
    let user_id = "usr_revoke_4";
    seed_org(&pool, org_id, "revoke-test-4").await;
    seed_user(&pool, user_id, org_id).await;

    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_dbl', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW())"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    // First revoke
    let r1 = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
         WHERE id = 'sess_dbl' AND tenant_id = $1 AND revoked = FALSE"
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(r1.rows_affected(), 1);

    // Second revoke — should match 0 rows (already revoked)
    let r2 = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
         WHERE id = 'sess_dbl' AND tenant_id = $1 AND revoked = FALSE"
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(r2.rows_affected(), 0, "Double revoke should be no-op");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PHASE 2: Multi-Tenant Email Isolation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Email lookup scoped by org_id returns correct user per tenant.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_email_lookup_scoped_by_org(pool: PgPool) {
    let email = "shared@example.com";

    // Tenant A
    seed_org(&pool, "org_iso_a", "iso-a").await;
    seed_user(&pool, "usr_iso_a", "org_iso_a").await;
    seed_identity(&pool, "ident_iso_a", "usr_iso_a", email, "org_iso_a").await;

    // Tenant B
    seed_org(&pool, "org_iso_b", "iso-b").await;
    seed_user(&pool, "usr_iso_b", "org_iso_b").await;
    seed_identity(&pool, "ident_iso_b", "usr_iso_b", email, "org_iso_b").await;

    // Scoped lookup returns tenant A's user
    let user_a: (String,) = sqlx::query_as(
        "SELECT u.id FROM users u JOIN identities i ON u.id = i.user_id
         WHERE i.type = 'email' AND i.identifier = $1 AND i.organization_id = $2",
    )
    .bind(email)
    .bind("org_iso_a")
    .fetch_one(&pool)
    .await
    .expect("find user in tenant A");
    assert_eq!(user_a.0, "usr_iso_a");

    // Scoped lookup returns tenant B's user
    let user_b: (String,) = sqlx::query_as(
        "SELECT u.id FROM users u JOIN identities i ON u.id = i.user_id
         WHERE i.type = 'email' AND i.identifier = $1 AND i.organization_id = $2",
    )
    .bind(email)
    .bind("org_iso_b")
    .fetch_one(&pool)
    .await
    .expect("find user in tenant B");
    assert_eq!(user_b.0, "usr_iso_b");
}

/// Signup ticket with organization_id scopes email check correctly.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_signup_ticket_org_scoped(pool: PgPool) {
    seed_org(&pool, "org_tkt_a", "tkt-a").await;
    seed_org(&pool, "org_tkt_b", "tkt-b").await;

    // Insert signup ticket for tenant A
    sqlx::query(
        "INSERT INTO signup_tickets (id, email, password_hash, organization_id, status, created_at, expires_at)
         VALUES ('tkt_a', 'signup@example.com', 'hash_a', 'org_tkt_a', 'missing_requirements', NOW(), NOW() + INTERVAL '1 hour')"
    )
    .execute(&pool)
    .await
    .expect("insert ticket A");

    // Same email in tenant B should succeed
    let result = sqlx::query(
        "INSERT INTO signup_tickets (id, email, password_hash, organization_id, status, created_at, expires_at)
         VALUES ('tkt_b', 'signup@example.com', 'hash_b', 'org_tkt_b', 'missing_requirements', NOW(), NOW() + INTERVAL '1 hour')"
    )
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "Same email in different org should be allowed for tickets"
    );
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PHASE 5: Bootstrap Safety
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Without IDAAS_BOOTSTRAP_PASSWORD in dev mode, bootstrap generates a random password.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_bootstrap_no_password_without_env(pool: PgPool) {
    // Remove the env var and ensure we're NOT in production mode
    std::env::remove_var("IDAAS_BOOTSTRAP_PASSWORD");
    std::env::remove_var("APP_ENV");

    api_server::bootstrap::seed_system_org(&pool)
        .await
        .expect("bootstrap should succeed without password env");

    // Verify admin user exists
    let user_exists: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE id = 'user_admin')")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(user_exists.0, "Admin user should exist");

    let password_exists: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM passwords WHERE user_id = 'user_admin')")
            .fetch_one(&pool)
            .await
            .unwrap();
    // In dev mode (no APP_ENV=production), bootstrap generates a random password
    assert!(
        password_exists.0,
        "Admin password should exist (random-generated in dev mode)"
    );
}

/// Bootstrap must repair stale admin memberships back to the expected roles.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_bootstrap_repairs_admin_memberships(pool: PgPool) {
    std::env::remove_var("IDAAS_BOOTSTRAP_PASSWORD");
    std::env::remove_var("APP_ENV");

    api_server::bootstrap::seed_system_org(&pool)
        .await
        .expect("initial bootstrap should succeed");

    sqlx::query(
        "UPDATE memberships
         SET role = 'member'
         WHERE user_id = 'user_admin' AND organization_id IN ('system', 'default')",
    )
    .execute(&pool)
    .await
    .expect("downgrade stale memberships");

    api_server::bootstrap::seed_system_org(&pool)
        .await
        .expect("bootstrap should reconcile stale memberships");

    let memberships: Vec<(String, String)> = sqlx::query_as(
        "SELECT organization_id, role
         FROM memberships
         WHERE user_id = 'user_admin' AND organization_id IN ('default', 'system')
         ORDER BY organization_id",
    )
    .fetch_all(&pool)
    .await
    .expect("fetch bootstrap memberships");

    assert_eq!(
        memberships,
        vec![
            ("default".to_string(), "admin".to_string()),
            ("system".to_string(), "owner".to_string()),
        ],
        "Bootstrap should restore provider admin memberships"
    );
}

/// With IDAAS_BOOTSTRAP_PASSWORD set, bootstrap creates a verifiable password.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_bootstrap_creates_password_with_env(pool: PgPool) {
    let test_pw = "SecureBootstrap123!";
    std::env::set_var("IDAAS_BOOTSTRAP_PASSWORD", test_pw);

    api_server::bootstrap::seed_system_org(&pool)
        .await
        .expect("bootstrap should succeed");

    // Verify password exists and is verifiable
    let hash: (String,) =
        sqlx::query_as("SELECT password_hash FROM passwords WHERE user_id = 'user_admin'")
            .fetch_one(&pool)
            .await
            .expect("Admin password should exist");

    assert!(
        auth_core::verify_password(test_pw, &hash.0).is_ok(),
        "Password should verify against the env-var value"
    );
}

/// Bootstrap rejects passwords shorter than 8 chars.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_bootstrap_rejects_short_password(pool: PgPool) {
    std::env::set_var("IDAAS_BOOTSTRAP_PASSWORD", "short");

    api_server::bootstrap::seed_system_org(&pool)
        .await
        .expect("bootstrap should still succeed (skips short password)");

    // Password should NOT be set
    let password_exists: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM passwords WHERE user_id = 'user_admin')")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!password_exists.0, "Short password should be skipped");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CONCURRENCY & STRESS TESTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 20 concurrent revocations targeting the same sessions must not cause panics or
/// data corruption. Result: all sessions except current should be revoked.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_concurrent_session_revocation_is_safe(pool: PgPool) {
    let org_id = "org_conc_1";
    let user_id = "usr_conc_1";
    seed_org(&pool, org_id, "conc-test-1").await;
    seed_user(&pool, user_id, org_id).await;

    // Create 20 sessions
    for i in 0..20 {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
             VALUES ($1, $2, $3, $3, NOW() + INTERVAL '1 hour', NOW())"
        )
        .bind(format!("sess_conc_{i}"))
        .bind(user_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let current_session = "sess_conc_0";

    // Fire 20 concurrent invalidation requests
    let mut handles = Vec::new();
    for _ in 0..20 {
        let pool_clone = pool.clone();
        let user = user_id.to_string();
        let current = current_session.to_string();
        handles.push(tokio::spawn(async move {
            sqlx::query_scalar::<_, i64>(
                "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
                 WHERE user_id = $1 AND id != $2 AND expires_at > NOW() AND revoked = FALSE
                 RETURNING 1"
            )
            .bind(&user)
            .bind(&current)
            .fetch_all(&pool_clone)
            .await
        }));
    }

    let mut total_revoked: i64 = 0;
    for handle in handles {
        let result = handle.await.expect("Task should not panic");
        let rows = result.expect("Query should not error");
        total_revoked += rows.len() as i64;
    }
    assert_eq!(
        total_revoked, 19,
        "Exactly 19 sessions should be revoked across all concurrent tasks"
    );

    // Current session must still be active
    let current_active: (bool,) = sqlx::query_as("SELECT NOT revoked FROM sessions WHERE id = $1")
        .bind(current_session)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(current_active.0, "Current session must remain active");
}

/// Concurrent user creation with the same email in the same org should reject duplicates.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_concurrent_duplicate_email_same_org_safe(pool: PgPool) {
    seed_org(&pool, "org_conc_dup", "conc-dup").await;

    // Pre-seed one user
    seed_user(&pool, "usr_conc_dup_1", "org_conc_dup").await;
    seed_identity(
        &pool,
        "ident_conc_dup_1",
        "usr_conc_dup_1",
        "race@example.com",
        "org_conc_dup",
    )
    .await;

    // Try to insert a second identity with the same email+org concurrently 10 times.
    // The UNIQUE(organization_id, type, identifier) constraint should reject all of them.
    let mut handles = Vec::new();
    for i in 0..10 {
        let pool_clone = pool.clone();
        handles.push(tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO identities (id, user_id, organization_id, type, identifier, verified, created_at, updated_at)
                 VALUES ($1, $2, 'org_conc_dup', 'email', 'race@example.com', false, NOW(), NOW())"
            )
            .bind(format!("ident_conc_dup_dup_{i}"))
            .bind(format!("usr_conc_dup_{}", i + 10))
            .execute(&pool_clone)
            .await
        }));
    }

    let mut success_count: usize = 0;
    for handle in handles {
        let result = handle.await.expect("Task should not panic");
        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(success_count, 0, "No duplicate inserts should succeed");
}

/// Cross-tenant session access must be prevented: session for org A cannot be
/// queried using org B's tenant_id.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_cross_tenant_session_isolation(pool: PgPool) {
    seed_org(&pool, "org_iso_x", "iso-x").await;
    seed_org(&pool, "org_iso_y", "iso-y").await;
    seed_user(&pool, "usr_iso_x", "org_iso_x").await;
    seed_user(&pool, "usr_iso_y", "org_iso_y").await;

    // Create sessions in org X and org Y
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_x', 'usr_iso_x', 'org_iso_x', 'org_iso_x', NOW() + INTERVAL '1 hour', NOW())"
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_y', 'usr_iso_y', 'org_iso_y', 'org_iso_y', NOW() + INTERVAL '1 hour', NOW())"
    )
    .execute(&pool)
    .await
    .unwrap();

    // Cross-tenant query: org_iso_y tries to access org_iso_x's session
    let cross_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE id = 'sess_x' AND tenant_id = 'org_iso_y' AND expires_at > NOW() AND revoked = FALSE"
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        cross_tenant.is_none(),
        "org_iso_y should NOT see org_iso_x's session"
    );

    // Same-tenant query: org_iso_x can access its own session
    let same_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE id = 'sess_x' AND tenant_id = 'org_iso_x' AND expires_at > NOW() AND revoked = FALSE"
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(
        same_tenant.is_some(),
        "org_iso_x should see its own session"
    );
}

/// Password history prevents reuse when passwords are changed in rapid succession.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_password_history_table_operations(pool: PgPool) {
    seed_org(&pool, "org_hist", "hist-test").await;
    seed_user(&pool, "usr_hist", "org_hist").await;
    seed_password(&pool, "usr_hist", "InitialPassword123!").await;

    // Insert password history entries
    for i in 0..3 {
        let hash = auth_core::hash_password(&format!("OldPassword{i}!")).unwrap();
        sqlx::query(
            "INSERT INTO password_history (id, user_id, password_hash, created_at)
             VALUES ($1, 'usr_hist', $2, NOW() - ($3 || ' hours')::INTERVAL)",
        )
        .bind(format!("hist_{i}"))
        .bind(&hash)
        .bind(format!("{}", i + 1))
        .execute(&pool)
        .await
        .unwrap();
    }

    // Verify we can query the last N passwords in order
    let history: Vec<(String,)> = sqlx::query_as(
        "SELECT password_hash FROM password_history WHERE user_id = 'usr_hist' ORDER BY created_at DESC LIMIT 10"
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(history.len(), 3, "Should have 3 password history entries");

    // Verify each hash is valid
    for (hash,) in &history {
        assert!(hash.starts_with("$argon2"), "Hash should be Argon2: {hash}");
    }
}

/// Session expiry edge case: expired session excluded even if not revoked.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_expired_session_excluded_even_if_not_revoked(pool: PgPool) {
    let org_id = "org_exp";
    let user_id = "usr_exp";
    seed_org(&pool, org_id, "exp-test").await;
    seed_user(&pool, user_id, org_id).await;

    // Create an expired but NOT revoked session
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at, revoked)
         VALUES ('sess_expired', $1, $2, $2, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '2 hours', FALSE)"
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    // Active session query (same as middleware) should not include it
    let active: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE"
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        active.0, 0,
        "Expired session should not appear in active queries"
    );
}
