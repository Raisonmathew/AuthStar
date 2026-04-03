//! Phase 6 — Session Revocation Tests
//!
//! Verifies session revocation behaviour: single-session revoke, bulk invalidation,
//! and queries excluding revoked sessions.
//! The CORE revocation tests already live in hardening_tests.rs. This file adds
//! deeper coverage: tenant-scoped revocation, concurrent revoke, and edge cases.

mod common;

use sqlx::PgPool;

/// Seeds a session directly in the DB.
async fn seed_session(
    pool: &PgPool,
    session_id: &str,
    user_id: &str,
    org_id: &str,
    revoked: bool,
) {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, revoked, revoked_at, expires_at)
         VALUES ($1, $2, $3, $4, CASE WHEN $4 THEN NOW() ELSE NULL END, NOW() + INTERVAL '1 hour')
         ON CONFLICT (id) DO NOTHING"
    )
    .bind(session_id)
    .bind(user_id)
    .bind(org_id)
    .bind(revoked)
    .execute(pool)
    .await
    .expect("seed_session");
}

// ─────────────────────────────────────────────────────────────────────────────
// T1: Single Session Revocation
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_session_sets_flags(pool: PgPool) {
    common::seed::seed_org(&pool, "org_sr1", "sr1").await;
    common::seed::seed_user(&pool, "user_sr1", "org_sr1").await;
    seed_session(&pool, "sess_sr_active", "user_sr1", "org_sr1", false).await;

    // Revoke
    sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                expires_at = LEAST(expires_at, NOW())
         WHERE id = $1"
    )
    .bind("sess_sr_active")
    .execute(&pool)
    .await
    .unwrap();

    // Verify
    let (revoked, revoked_at_set): (bool, bool) = sqlx::query_as(
        "SELECT revoked, (revoked_at IS NOT NULL) FROM sessions WHERE id = $1"
    )
    .bind("sess_sr_active")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(revoked, "revoked flag should be true");
    assert!(revoked_at_set, "revoked_at should be set");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_session_expires_immediately(pool: PgPool) {
    common::seed::seed_org(&pool, "org_sr2", "sr2").await;
    common::seed::seed_user(&pool, "user_sr2", "org_sr2").await;
    seed_session(&pool, "sess_sr_expire", "user_sr2", "org_sr2", false).await;

    sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                expires_at = LEAST(expires_at, NOW())
         WHERE id = $1"
    )
    .bind("sess_sr_expire")
    .execute(&pool)
    .await
    .unwrap();

    let (expired,): (bool,) = sqlx::query_as(
        "SELECT expires_at <= NOW() FROM sessions WHERE id = $1"
    )
    .bind("sess_sr_expire")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(expired, "expires_at should be <= NOW after revocation");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_double_revoke_is_idempotent(pool: PgPool) {
    common::seed::seed_org(&pool, "org_sr3", "sr3").await;
    common::seed::seed_user(&pool, "user_sr3", "org_sr3").await;
    seed_session(&pool, "sess_sr_double", "user_sr3", "org_sr3", false).await;

    let revoke_sql = "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                      expires_at = LEAST(expires_at, NOW()) WHERE id = $1";

    sqlx::query(revoke_sql).bind("sess_sr_double").execute(&pool).await.unwrap();
    // Second revoke should not error
    sqlx::query(revoke_sql).bind("sess_sr_double").execute(&pool).await.unwrap();

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE id = $1 AND revoked = TRUE"
    )
    .bind("sess_sr_double")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count.0, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// T2: Bulk Invalidation (invalidate_other_sessions)
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_invalidate_other_sessions_keeps_current(pool: PgPool) {
    common::seed::seed_org(&pool, "org_bulk", "bulk").await;
    common::seed::seed_user(&pool, "user_bulk", "org_bulk").await;
    seed_session(&pool, "sess_keep", "user_bulk", "org_bulk", false).await;
    seed_session(&pool, "sess_kill_1", "user_bulk", "org_bulk", false).await;
    seed_session(&pool, "sess_kill_2", "user_bulk", "org_bulk", false).await;

    // Invalidate all except sess_keep
    sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                expires_at = LEAST(expires_at, NOW())
         WHERE user_id = $1 AND id != $2 AND revoked = FALSE"
    )
    .bind("user_bulk")
    .bind("sess_keep")
    .execute(&pool)
    .await
    .unwrap();

    // Check kept session is alive
    let (kept_revoked,): (bool,) = sqlx::query_as(
        "SELECT revoked FROM sessions WHERE id = 'sess_keep'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!kept_revoked, "current session should NOT be revoked");

    // Check others are revoked
    let (revoked_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = 'user_bulk' AND revoked = TRUE"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked_count, 2, "two other sessions should be revoked");
}

// ─────────────────────────────────────────────────────────────────────────────
// T3: Active Session Query Excludes Revoked
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_active_sessions_excludes_revoked_and_expired(pool: PgPool) {
    common::seed::seed_org(&pool, "org_active", "active").await;
    common::seed::seed_user(&pool, "user_active", "org_active").await;

    // Active session
    seed_session(&pool, "sess_good", "user_active", "org_active", false).await;
    // Revoked session
    seed_session(&pool, "sess_revoked", "user_active", "org_active", true).await;
    // Expired session (force expires_at to past)
    seed_session(&pool, "sess_expired", "user_active", "org_active", false).await;
    sqlx::query("UPDATE sessions SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = 'sess_expired'")
        .execute(&pool)
        .await
        .unwrap();

    let active: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE user_id = $1 AND revoked = FALSE AND expires_at > NOW()"
    )
    .bind("user_active")
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(active.len(), 1, "only one active session");
    assert_eq!(active[0].0, "sess_good");
}

// ─────────────────────────────────────────────────────────────────────────────
// T4: Tenant-Scoped Revocation
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_scoped_to_tenant(pool: PgPool) {
    common::seed::seed_org(&pool, "org_t1", "t1").await;
    common::seed::seed_org(&pool, "org_t2", "t2").await;
    common::seed::seed_user(&pool, "user_t", "org_t1").await;

    seed_session(&pool, "sess_t1", "user_t", "org_t1", false).await;
    seed_session(&pool, "sess_t2", "user_t", "org_t2", false).await;

    // Revoke only org_t1 sessions
    sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                expires_at = LEAST(expires_at, NOW())
         WHERE user_id = $1 AND active_organization_id = $2 AND revoked = FALSE"
    )
    .bind("user_t")
    .bind("org_t1")
    .execute(&pool)
    .await
    .unwrap();

    let (t1_revoked,): (bool,) = sqlx::query_as(
        "SELECT revoked FROM sessions WHERE id = 'sess_t1'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(t1_revoked, "org_t1 session should be revoked");

    let (t2_revoked,): (bool,) = sqlx::query_as(
        "SELECT revoked FROM sessions WHERE id = 'sess_t2'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!t2_revoked, "org_t2 session should NOT be revoked");
}

// ─────────────────────────────────────────────────────────────────────────────
// T1.9: Revoke non-existent session → 0 rows affected (404 equivalent)
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_nonexistent_session_zero_rows(pool: PgPool) {
    common::seed::seed_org(&pool, "org_ne", "ne").await;

    // Attempt to revoke a session ID that doesn't exist
    let result = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(),
                expires_at = LEAST(expires_at, NOW())
         WHERE id = $1 AND active_organization_id = $2 AND revoked = FALSE"
    )
    .bind("sess_does_not_exist")
    .bind("org_ne")
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        result.rows_affected(), 0,
        "Revoking non-existent session should affect 0 rows"
    );
}
