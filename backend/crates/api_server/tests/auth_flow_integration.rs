//! F-4: Auth Flow Integration Tests
//!
//! These tests exercise the full auth flow stack against a real PostgreSQL
//! instance (provided by sqlx::test's automatic test database provisioning).
//!
//! Each test gets an isolated database with all migrations applied.
//! Tests are independent and can run in parallel.
//!
//! ## Running
//! ```bash
//! # Requires DATABASE_URL pointing to a PostgreSQL instance
//! export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/authstar_test
//! cargo test -p api_server --test auth_flow_integration
//! ```
//!
//! ## CI
//! The GitHub Actions workflow starts a PostgreSQL service container and sets
//! DATABASE_URL before running these tests.

use sqlx::PgPool;

// ─── Flow Context Tests ───────────────────────────────────────────────────────

/// Test that a flow context can be stored and loaded back correctly.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_flow_context_store_and_load(pool: PgPool) {
    

    // Insert a test organization first (required FK)
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_test_001', 'Test Org', 'test-org', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert test org");

    // Insert a hosted_auth_flow row
    let flow_id = "flow_test_001";
    sqlx::query(
        r#"
        INSERT INTO hosted_auth_flows (
            id, org_id, flow_type, status, execution_state, expires_at, created_at, updated_at
        ) VALUES (
            $1, 'org_test_001', 'login', 'pending',
            '{"flow_id": "flow_test_001", "org_id": "org_test_001"}'::jsonb,
            NOW() + INTERVAL '10 minutes',
            NOW(), NOW()
        )
        "#
    )
    .bind(flow_id)
    .execute(&pool)
    .await
    .expect("Failed to insert flow");

    // Verify the flow can be loaded and is not expired
    let row = sqlx::query!(
        r#"
        SELECT flow_id,
               expires_at > NOW() AS "is_active!"
        FROM hosted_auth_flows
        WHERE flow_id = $1
        "#,
        flow_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to load flow");

    assert_eq!(row.flow_id, flow_id);
    assert!(row.is_active, "Flow should not be expired");
}

/// Test that an expired flow is correctly identified.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_expired_flow_detection(pool: PgPool) {
    // Insert test org
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_test_002', 'Test Org 2', 'test-org-2', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert test org");

    // Insert an already-expired flow
    let flow_id = "flow_expired_001";
    sqlx::query(
        r#"
        INSERT INTO hosted_auth_flows (
            id, org_id, flow_type, status, execution_state, expires_at, created_at, updated_at
        ) VALUES (
            $1, 'org_test_002', 'login', 'pending',
            '{}'::jsonb,
            NOW() - INTERVAL '1 minute',  -- already expired
            NOW() - INTERVAL '11 minutes',
            NOW() - INTERVAL '11 minutes'
        )
        "#
    )
    .bind(flow_id)
    .execute(&pool)
    .await
    .expect("Failed to insert expired flow");

    // Query should show it as expired
    let row = sqlx::query!(
        r#"
        SELECT flow_id,
               expires_at > NOW() AS "is_active!"
        FROM hosted_auth_flows
        WHERE flow_id = $1
        "#,
        flow_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to load flow");

    assert!(!row.is_active, "Flow should be expired");
}

// ─── Stripe Webhook Idempotency Tests ────────────────────────────────────────

/// Test that duplicate Stripe webhook events are rejected by the unique constraint.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_stripe_webhook_idempotency(pool: PgPool) {
    let event_id = "evt_test_idempotency_001";

    // First insert should succeed
    let result1 = sqlx::query(
        r#"
        INSERT INTO stripe_webhook_events (event_id, event_type, received_at)
        VALUES ($1, 'checkout.session.completed', NOW())
        ON CONFLICT (event_id) DO NOTHING
        "#
    )
    .bind(event_id)
    .execute(&pool)
    .await
    .expect("First insert failed");

    assert_eq!(result1.rows_affected(), 1, "First insert should affect 1 row");

    // Second insert (duplicate) should be silently ignored
    let result2 = sqlx::query(
        r#"
        INSERT INTO stripe_webhook_events (event_id, event_type, received_at)
        VALUES ($1, 'checkout.session.completed', NOW())
        ON CONFLICT (event_id) DO NOTHING
        "#
    )
    .bind(event_id)
    .execute(&pool)
    .await
    .expect("Second insert failed");

    assert_eq!(result2.rows_affected(), 0, "Duplicate insert should affect 0 rows");

    // Verify only one row exists
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM stripe_webhook_events WHERE event_id = $1"
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("Count query failed");

    assert_eq!(count, 1, "Should have exactly 1 row");
}

/// Test that webhook events can be marked as processed.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_stripe_webhook_status_update(pool: PgPool) {
    let event_id = "evt_test_status_001";

    // Insert pending event
    sqlx::query(
        "INSERT INTO stripe_webhook_events (event_id, event_type, received_at, status)
         VALUES ($1, 'invoice.paid', NOW(), 'pending')"
    )
    .bind(event_id)
    .execute(&pool)
    .await
    .expect("Insert failed");

    // Mark as processed
    sqlx::query(
        "UPDATE stripe_webhook_events SET status = 'processed', processed_at = NOW() WHERE event_id = $1"
    )
    .bind(event_id)
    .execute(&pool)
    .await
    .expect("Update failed");

    // Verify status
    let status: String = sqlx::query_scalar(
        "SELECT status FROM stripe_webhook_events WHERE event_id = $1"
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .expect("Query failed");

    assert_eq!(status, "processed");
}

// ─── Account Lockout Tests ────────────────────────────────────────────────────

/// Test that failed_login_attempts increments correctly.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_account_lockout_fields(pool: PgPool) {
    // Insert test org
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_lockout_test', 'Lockout Test Org', 'lockout-test', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert org");

    // Insert test user
    let user_id = "user_lockout_test_001";
    sqlx::query(
        r#"
        INSERT INTO users (id, organization_id, email, created_at, updated_at)
        VALUES ($1, 'org_lockout_test', 'lockout@example.com', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
        "#
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("Failed to insert user");

    // Simulate 3 failed login attempts
    for _ in 0..3 {
        sqlx::query(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1"
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("Failed to increment attempts");
    }

    // Verify count
    let attempts: i32 = sqlx::query_scalar(
        "SELECT failed_login_attempts FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("Query failed");

    assert_eq!(attempts, 3);

    // Lock the account
    sqlx::query(
        "UPDATE users SET locked = true, locked_at = NOW() WHERE id = $1"
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("Failed to lock account");

    // Verify locked
    let locked: bool = sqlx::query_scalar(
        "SELECT locked FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("Query failed");

    assert!(locked, "Account should be locked");
}

// ─── Multi-Tenancy Tests ──────────────────────────────────────────────────────

/// Test that two tenants can have users with the same email (per-tenant uniqueness).
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_per_tenant_email_uniqueness(pool: PgPool) {
    // Insert two organizations
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_tenant_a', 'Tenant A', 'tenant-a', NOW(), NOW()),
                ('org_tenant_b', 'Tenant B', 'tenant-b', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert orgs");

    // Insert user in tenant A
    sqlx::query(
        "INSERT INTO users (id, organization_id, email, created_at, updated_at)
         VALUES ('user_a_001', 'org_tenant_a', 'shared@example.com', NOW(), NOW())"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert user in tenant A");

    // Insert same email in tenant B — should succeed (per-tenant uniqueness)
    let result = sqlx::query(
        "INSERT INTO users (id, organization_id, email, created_at, updated_at)
         VALUES ('user_b_001', 'org_tenant_b', 'shared@example.com', NOW(), NOW())"
    )
    .execute(&pool)
    .await;

    assert!(result.is_ok(), "Same email in different tenant should be allowed");
}

/// Test that duplicate email within the same tenant is rejected.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_duplicate_email_same_tenant_rejected(pool: PgPool) {
    // Insert organization
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_dup_test', 'Dup Test Org', 'dup-test', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert org");

    // Insert first user
    sqlx::query(
        "INSERT INTO users (id, organization_id, email, created_at, updated_at)
         VALUES ('user_dup_001', 'org_dup_test', 'dup@example.com', NOW(), NOW())"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert first user");

    // Insert duplicate email in same tenant — should fail
    let result = sqlx::query(
        "INSERT INTO users (id, organization_id, email, created_at, updated_at)
         VALUES ('user_dup_002', 'org_dup_test', 'dup@example.com', NOW(), NOW())"
    )
    .execute(&pool)
    .await;

    assert!(result.is_err(), "Duplicate email in same tenant should be rejected");
}

// ─── Password History Tests ───────────────────────────────────────────────────

/// Test that password_history table exists and accepts entries.
#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_password_history_table_exists(pool: PgPool) {
    // Insert test org and user
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_pw_hist', 'PW Hist Org', 'pw-hist', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert org");

    sqlx::query(
        "INSERT INTO users (id, organization_id, email, created_at, updated_at)
         VALUES ('user_pw_hist_001', 'org_pw_hist', 'pwhist@example.com', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .expect("Failed to insert user");

    // Insert a password history entry
    let result = sqlx::query(
        "INSERT INTO password_history (user_id, password_hash, created_at)
         VALUES ('user_pw_hist_001', '$argon2id$v=19$m=65536,t=3,p=4$test_hash', NOW())"
    )
    .execute(&pool)
    .await;

    assert!(result.is_ok(), "Password history insert should succeed");

    // Verify it was stored
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM password_history WHERE user_id = $1"
    )
    .bind("user_pw_hist_001")
    .fetch_one(&pool)
    .await
    .expect("Count query failed");

    assert_eq!(count, 1);
}

// Made with Bob
