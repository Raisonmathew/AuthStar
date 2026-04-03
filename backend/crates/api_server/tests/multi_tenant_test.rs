//! Phase 6 — Multi-Tenant Email Isolation Tests
//!
//! Verifies that email identity lookups, user creation, and session management
//! are properly scoped by organization_id (Phase 2 hardening).

mod common;

use sqlx::PgPool;

// ─────────────────────────────────────────────────────────────────────────────
// T2.1: Same email in different orgs → different users
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_same_email_different_orgs_creates_distinct_users(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_a", "mt-alpha").await;
    common::seed::seed_org(&pool, "org_mt_b", "mt-beta").await;

    let email = "alice@example.com";

    // Create user + identity in org A
    common::seed::seed_user(&pool, "user_mt_a1", "org_mt_a").await;
    common::seed::seed_identity(&pool, "id_mt_a1", "user_mt_a1", email, "org_mt_a").await;

    // Create user + identity in org B with the SAME email
    common::seed::seed_user(&pool, "user_mt_b1", "org_mt_b").await;
    common::seed::seed_identity(&pool, "id_mt_b1", "user_mt_b1", email, "org_mt_b").await;

    // Both identities should exist
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identities WHERE identifier = $1 AND type = 'email'"
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count.0, 2, "Same email should exist in both orgs");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.2: Org-scoped email lookup returns only the correct user
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_org_scoped_email_lookup(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_c", "mt-charlie").await;
    common::seed::seed_org(&pool, "org_mt_d", "mt-delta").await;

    let email = "bob@example.com";

    common::seed::seed_user(&pool, "user_mt_c1", "org_mt_c").await;
    common::seed::seed_identity(&pool, "id_mt_c1", "user_mt_c1", email, "org_mt_c").await;

    common::seed::seed_user(&pool, "user_mt_d1", "org_mt_d").await;
    common::seed::seed_identity(&pool, "id_mt_d1", "user_mt_d1", email, "org_mt_d").await;

    // Query scoped to org_mt_c should return only that user
    let row: (String,) = sqlx::query_as(
        "SELECT i.user_id FROM identities i
         WHERE i.identifier = $1 AND i.type = 'email' AND i.organization_id = $2"
    )
    .bind(email)
    .bind("org_mt_c")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, "user_mt_c1", "Scoped lookup should return correct org's user");

    // Query scoped to org_mt_d should return the other user
    let row2: (String,) = sqlx::query_as(
        "SELECT i.user_id FROM identities i
         WHERE i.identifier = $1 AND i.type = 'email' AND i.organization_id = $2"
    )
    .bind(email)
    .bind("org_mt_d")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row2.0, "user_mt_d1");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.3: Duplicate email within same org is rejected
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_duplicate_email_in_same_org_rejected(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_e", "mt-echo").await;

    let email = "charlie@example.com";

    common::seed::seed_user(&pool, "user_mt_e1", "org_mt_e").await;
    common::seed::seed_identity(&pool, "id_mt_e1", "user_mt_e1", email, "org_mt_e").await;

    common::seed::seed_user(&pool, "user_mt_e2", "org_mt_e").await;

    // Attempting to insert a second identity with the same email + org should fail
    // (relies on the unique constraint on identities: type + identifier + organization_id)
    let result = sqlx::query(
        "INSERT INTO identities (id, user_id, type, identifier, verified, organization_id)
         VALUES ($1, $2, 'email', $3, true, $4)"
    )
    .bind("id_mt_e2_dup")
    .bind("user_mt_e2")
    .bind(email)
    .bind("org_mt_e")
    .execute(&pool)
    .await;

    assert!(result.is_err(), "Duplicate email in same org should be rejected by DB constraint");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.4: Session scoped to org cannot access another org's data
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_sessions_scoped_to_org(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_f", "mt-foxtrot").await;
    common::seed::seed_org(&pool, "org_mt_g", "mt-golf").await;
    common::seed::seed_user(&pool, "user_mt_f1", "org_mt_f").await;
    common::seed::seed_user(&pool, "user_mt_g1", "org_mt_g").await;

    // Create sessions in different orgs
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_mt_f1', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW())"
    )
    .bind("user_mt_f1")
    .bind("org_mt_f")
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at, last_active_at)
         VALUES ('sess_mt_g1', $1, $2, $2, NOW() + INTERVAL '1 hour', NOW())"
    )
    .bind("user_mt_g1")
    .bind("org_mt_g")
    .execute(&pool)
    .await
    .unwrap();

    // Query sessions for org_mt_f only
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions
         WHERE active_organization_id = $1 AND revoked = FALSE AND expires_at > NOW()"
    )
    .bind("org_mt_f")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count.0, 1, "Only sessions for org_mt_f should be returned");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.5: Identity organization_id is NOT NULL for org-scoped users
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_identity_org_id_set_for_org_user(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_h", "mt-hotel").await;
    common::seed::seed_user(&pool, "user_mt_h1", "org_mt_h").await;
    common::seed::seed_identity(&pool, "id_mt_h1", "user_mt_h1", "hotel@example.com", "org_mt_h").await;

    let (org_id,): (Option<String>,) = sqlx::query_as(
        "SELECT organization_id FROM identities WHERE id = $1"
    )
    .bind("id_mt_h1")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(org_id.as_deref(), Some("org_mt_h"), "Identity org_id must match");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.6: Unscoped query returns all orgs (backwards compat for admin)
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_unscoped_email_lookup_returns_all(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_i", "mt-india").await;
    common::seed::seed_org(&pool, "org_mt_j", "mt-juliet").await;

    let email = "global@example.com";

    common::seed::seed_user(&pool, "user_mt_i1", "org_mt_i").await;
    common::seed::seed_identity(&pool, "id_mt_i1", "user_mt_i1", email, "org_mt_i").await;

    common::seed::seed_user(&pool, "user_mt_j1", "org_mt_j").await;
    common::seed::seed_identity(&pool, "id_mt_j1", "user_mt_j1", email, "org_mt_j").await;

    // Unscoped lookup returns both
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identities WHERE identifier = $1 AND type = 'email'"
    )
    .bind(email)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count.0, 2, "Unscoped query should return users from all orgs");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.7: Membership is org-scoped
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_membership_scoped_to_org(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_k", "mt-kilo").await;
    common::seed::seed_org(&pool, "org_mt_l", "mt-lima").await;
    common::seed::seed_user(&pool, "user_mt_k1", "org_mt_k").await;
    common::seed::seed_membership(&pool, "mem_mt_k1", "user_mt_k1", "org_mt_k", "admin").await;
    common::seed::seed_membership(&pool, "mem_mt_l1", "user_mt_k1", "org_mt_l", "member").await;

    // Query memberships for org_mt_k
    let (role,): (String,) = sqlx::query_as(
        "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2"
    )
    .bind("user_mt_k1")
    .bind("org_mt_k")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(role, "admin", "Should get admin role in org_mt_k");

    // Query memberships for org_mt_l
    let (role2,): (String,) = sqlx::query_as(
        "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2"
    )
    .bind("user_mt_k1")
    .bind("org_mt_l")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(role2, "member", "Should get member role in org_mt_l");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.8: Signup ticket org_id propagates to user
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_signup_ticket_org_id_propagates(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_m", "mt-mike").await;

    // Insert a signup ticket with organization_id
    sqlx::query(
        "INSERT INTO signup_tickets (id, organization_id, email, status, created_at, updated_at)
         VALUES ('ticket_mt_m1', $1, 'mike@example.com', 'awaiting_verification', NOW(), NOW())"
    )
    .bind("org_mt_m")
    .execute(&pool)
    .await
    .unwrap();

    // Verify the ticket has the org_id
    let (org_id,): (Option<String>,) = sqlx::query_as(
        "SELECT organization_id FROM signup_tickets WHERE id = $1"
    )
    .bind("ticket_mt_m1")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(org_id.as_deref(), Some("org_mt_m"), "Signup ticket should carry org_id");
}

// ─────────────────────────────────────────────────────────────────────────────
// T2.9: Global email lookup returns only one user (fetch_optional semantics)
// When the same email exists in multiple orgs, the global lookup returns
// the first match (non-deterministic). This test verifies that it does NOT
// error/panic — the ambiguity is handled by routing to org-scoped lookups.
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_global_email_lookup_with_multiple_orgs_returns_one(pool: PgPool) {
    common::seed::seed_org(&pool, "org_mt_n", "mt-november").await;
    common::seed::seed_org(&pool, "org_mt_o", "mt-oscar").await;

    let email = "ambiguous@example.com";

    common::seed::seed_user(&pool, "user_mt_n1", "org_mt_n").await;
    common::seed::seed_identity(&pool, "id_mt_n1", "user_mt_n1", email, "org_mt_n").await;

    common::seed::seed_user(&pool, "user_mt_o1", "org_mt_o").await;
    common::seed::seed_identity(&pool, "id_mt_o1", "user_mt_o1", email, "org_mt_o").await;

    // Global lookup (no org scope) — uses fetch_optional, returns first match
    // This simulates what get_user_by_email() does: it should NOT panic
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT u.id FROM users u
         INNER JOIN identities i ON i.user_id = u.id
         WHERE i.type = 'email' AND i.identifier = $1 AND i.verified = true
           AND u.deleted_at IS NULL"
    )
    .bind(email)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(result.is_some(), "Global lookup should return a result (one of the two)");

    // Verify the result is one of the two valid users
    let user_id = result.unwrap().0;
    assert!(
        user_id == "user_mt_n1" || user_id == "user_mt_o1",
        "Should return one of the two users, got: {user_id}"
    );
}
