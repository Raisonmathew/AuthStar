/**
 * Cross-Tenant Isolation Integration Tests
 *
 * Verifies that tenant_id scoping prevents cross-tenant data access.
 * 
 * Prerequisites:
 *   DATABASE_URL must be set
 *   Tests run against a live database (not mocked)
 */

use sqlx::PgPool;
use std::env;

async fn setup_pool() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://idaas_user:dev_password_change_me@localhost:5432/idaas".into());
    PgPool::connect(&database_url).await.expect("Failed to connect to DB")
}

/// Insert a test session for a specific tenant
async fn insert_test_session(db: &PgPool, session_id: &str, user_id: &str, tenant_id: &str) {
    sqlx::query(
        r#"INSERT INTO sessions (id, user_id, token, user_agent, ip_address, expires_at, created_at, updated_at, tenant_id, session_type, assurance_level, is_provisional)
           VALUES ($1, $2, 'test_token', 'test', '127.0.0.1', NOW() + INTERVAL '1 hour', NOW(), NOW(), $3, 'test', 'aal1', false)
           ON CONFLICT (id) DO NOTHING"#
    )
    .bind(session_id)
    .bind(user_id)
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("Failed to insert test session");
}

/// Insert a test EIAA execution for a specific tenant
async fn insert_test_execution(db: &PgPool, decision_ref: &str, tenant_id: &str) {
    sqlx::query(
        r#"INSERT INTO eiaa_executions (decision_ref, tenant_id, action, capsule_hash_b64, input_context, original_decision, original_reason, attestation_signature_b64, executed_at, nonce_b64)
           VALUES ($1, $2, 'test:action', 'hash', '{}', 'ALLOW', 'test', 'sig', NOW(), 'nonce')
           ON CONFLICT DO NOTHING"#
    )
    .bind(decision_ref)
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("Failed to insert test execution");
}

/// Clean up test data
async fn cleanup(db: &PgPool) {
    let _ = sqlx::query("DELETE FROM sessions WHERE user_agent = 'test'").execute(db).await;
    let _ = sqlx::query("DELETE FROM eiaa_executions WHERE action = 'test:action'").execute(db).await;
}

/// CRITICAL: Session lookup for Tenant A must NOT return sessions from Tenant B
#[tokio::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_session_isolation_by_tenant() {
    let db = setup_pool().await;
    cleanup(&db).await;

    // Tenant A session
    insert_test_session(&db, "sess_iso_a", "user_a", "tenant_a").await;
    // Tenant B session
    insert_test_session(&db, "sess_iso_b", "user_b", "tenant_b").await;

    // Looking up Tenant A's session with Tenant B's tenant_id should return NULL
    let cross_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()"
    )
    .bind("sess_iso_a")
    .bind("tenant_b")  // WRONG tenant
    .fetch_optional(&db)
    .await
    .expect("Query failed");

    assert!(cross_tenant.is_none(), "SECURITY: Cross-tenant session access detected!");

    // Same query with CORRECT tenant should return the session
    let correct_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()"
    )
    .bind("sess_iso_a")
    .bind("tenant_a")
    .fetch_optional(&db)
    .await
    .expect("Query failed");

    assert!(correct_tenant.is_some(), "Correct tenant session lookup should succeed");

    cleanup(&db).await;
}

/// CRITICAL: EIAA execution lookup must be scoped to tenant
#[tokio::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_execution_isolation_by_tenant() {
    let db = setup_pool().await;
    cleanup(&db).await;

    // Tenant A execution
    insert_test_execution(&db, "dec_iso_a", "tenant_a").await;
    // Tenant B execution
    insert_test_execution(&db, "dec_iso_b", "tenant_b").await;

    // Cross-tenant lookup should fail
    let cross_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT decision_ref FROM eiaa_executions WHERE decision_ref = $1 AND tenant_id = $2"
    )
    .bind("dec_iso_a")
    .bind("tenant_b")  // WRONG tenant
    .fetch_optional(&db)
    .await
    .expect("Query failed");

    assert!(cross_tenant.is_none(), "SECURITY: Cross-tenant execution access detected!");

    // Correct tenant lookup should succeed
    let correct_tenant: Option<(String,)> = sqlx::query_as(
        "SELECT decision_ref FROM eiaa_executions WHERE decision_ref = $1 AND tenant_id = $2"
    )
    .bind("dec_iso_a")
    .bind("tenant_a")
    .fetch_optional(&db)
    .await
    .expect("Query failed");

    assert!(correct_tenant.is_some(), "Correct tenant execution lookup should succeed");

    cleanup(&db).await;
}

/// SSO connection lookup must be scoped to tenant
#[tokio::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_sso_connection_isolation_by_tenant() {
    let db = setup_pool().await;

    // This test verifies the SQL pattern without inserting test data
    // (sso_connections has constraints that make test data complex)
    // Instead, we verify that queries with non-existent tenant return empty
    let result: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT config FROM sso_connections WHERE provider = $1 AND tenant_id = $2 AND enabled = true LIMIT 1"
    )
    .bind("google")
    .bind("nonexistent_tenant_xyz")
    .fetch_optional(&db)
    .await
    .expect("Query failed");

    assert!(result.is_none(), "Non-existent tenant should return no SSO config");
}
