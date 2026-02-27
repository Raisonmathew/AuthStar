//! Common test utilities for API integration tests

use api_server::{router::create_router, state::AppState, config::Config};
use axum::Router;
use sqlx::PgPool;

/// Setup test application with JWT token
pub async fn setup_test_app() -> (Router, String) {
    // Load test config
    dotenvy::from_filename(".env.test").ok();
    let config = Config::from_env().expect("Failed to load test config");

    // Create test database pool
    let db = PgPool::connect(&config.database.url)
        .await
        .expect("Failed to connect to test database");

    // Create app state
    let state = AppState::new_with_pool(config.clone(), db)
        .await
        .expect("Failed to create app state");

    // Create router
    let app = create_router(state.clone());

    // Generate test JWT
    let jwt = generate_test_jwt(&state);

    (app, jwt)
}

/// Generate a test JWT token
fn generate_test_jwt(state: &AppState) -> String {
    state.jwt_service.generate_token(
        "usr_test123",      // user_id
        "sess_test456",     // session_id
        "org_test789",      // tenant_id
        "end_user",         // session_type
    ).expect("Failed to create test JWT")
}

/// Cleanup test data
#[allow(dead_code)]
pub async fn cleanup_test_data(db: &PgPool, tenant_id: &str) {
    sqlx::query("DELETE FROM eiaa_policy_activations WHERE policy_id IN (SELECT id FROM eiaa_policies WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(db)
        .await
        .ok();
    
    sqlx::query("DELETE FROM eiaa_policies WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(db)
        .await
        .ok();
}
