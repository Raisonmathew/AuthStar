//! OAuth 2.0 Authorization Server Integration Tests
//!
//! Tests the full OAuth AS stack against a real PostgreSQL + Redis instance.
//! Each test gets an isolated database with all migrations applied via `#[sqlx::test]`.
//!
//! ## Running
//! ```bash
//! export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/idaas_test
//! cargo test -p api_server --test oauth2_integration
//! ```

mod common;

use base64::Engine;
use common::harness::TestHarness;
use common::seed;
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

// ─── Seed Helpers ──────────────────────────────────────────────────────────────

/// Insert a session row for a user.
async fn seed_session(pool: &PgPool, session_id: &str, user_id: &str, org_id: &str) {
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, active_organization_id)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await
    .expect("seed_session");
}

/// Insert an application (OAuth client) with a known secret.
/// Returns (client_id, raw_secret).
async fn seed_oauth_client(
    pool: &PgPool,
    app_id: &str,
    tenant_id: &str,
    name: &str,
    app_type: &str,
    client_id: &str,
    raw_secret: &str,
    redirect_uris: &[&str],
    allowed_flows: &[&str],
    is_first_party: bool,
) {
    let secret_hash = hex::encode(Sha256::digest(raw_secret.as_bytes()));
    let uris_json: Vec<Value> = redirect_uris
        .iter()
        .map(|u| Value::String(u.to_string()))
        .collect();
    let flows_json: Vec<Value> = allowed_flows
        .iter()
        .map(|f| Value::String(f.to_string()))
        .collect();

    sqlx::query(
        r#"
        INSERT INTO applications (id, tenant_id, name, type, client_id, client_secret_hash,
            redirect_uris, allowed_flows, is_first_party, allowed_scopes,
            token_lifetime_secs, refresh_token_lifetime_secs)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
            '["openid", "profile", "email"]'::jsonb, 300, 86400)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(app_id)
    .bind(tenant_id)
    .bind(name)
    .bind(app_type)
    .bind(client_id)
    .bind(&secret_hash)
    .bind(serde_json::Value::Array(uris_json))
    .bind(serde_json::Value::Array(flows_json))
    .bind(is_first_party)
    .execute(pool)
    .await
    .expect("seed_oauth_client");
}

/// Seed a public OAuth client (no secret, e.g., SPA/mobile).
async fn seed_public_oauth_client(
    pool: &PgPool,
    app_id: &str,
    tenant_id: &str,
    name: &str,
    client_id: &str,
    redirect_uris: &[&str],
) {
    let uris_json: Vec<Value> = redirect_uris
        .iter()
        .map(|u| Value::String(u.to_string()))
        .collect();

    sqlx::query(
        r#"
        INSERT INTO applications (id, tenant_id, name, type, client_id, client_secret_hash,
            redirect_uris, allowed_flows, is_first_party, allowed_scopes,
            token_lifetime_secs, refresh_token_lifetime_secs, public_config)
        VALUES ($1, $2, $3, 'mobile', $4, NULL,
            $5, '["authorization_code"]'::jsonb, false,
            '["openid", "profile", "email"]'::jsonb, 300, 86400,
            '{"enforce_pkce": true}'::jsonb)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(app_id)
    .bind(tenant_id)
    .bind(name)
    .bind(client_id)
    .bind(serde_json::Value::Array(uris_json))
    .execute(pool)
    .await
    .expect("seed_public_oauth_client");
}

/// Common setup: org, user, identity, password, session, and OAuth client.
async fn setup_oauth_fixtures(pool: &PgPool) {
    seed::seed_org(pool, "org_oauth_test", "oauth-test").await;
    seed::seed_user(pool, "user_oauth_1", "org_oauth_test").await;
    seed::seed_identity(
        pool,
        "id_oauth_1",
        "user_oauth_1",
        "oauth@test.com",
        "org_oauth_test",
    )
    .await;
    seed::seed_password(pool, "user_oauth_1", "TestPassword123!").await;
    seed::seed_membership(
        pool,
        "mem_oauth_1",
        "user_oauth_1",
        "org_oauth_test",
        "member",
    )
    .await;
    seed_session(pool, "sess_oauth_1", "user_oauth_1", "org_oauth_test").await;
    seed_oauth_client(
        pool,
        "app_oauth_test",
        "org_oauth_test",
        "Test OAuth App",
        "web",
        "client_test_001",
        "super_secret_value_123",
        &["https://example.com/callback", "https://example.com/cb2"],
        &["authorization_code", "refresh_token", "client_credentials"],
        false,
    )
    .await;
}

// ═══════════════════════════════════════════════════════════════════════════════
// OIDC Discovery
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_openid_configuration_returns_valid_document(pool: PgPool) {
    let h = TestHarness::spawn(pool).await;

    let res = h
        .client
        .get(format!("{}/.well-known/openid-configuration", h.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    // Verify required OIDC Discovery fields
    assert!(body["issuer"].is_string(), "Missing issuer");
    assert!(body["authorization_endpoint"]
        .as_str()
        .unwrap()
        .contains("/oauth/authorize"));
    assert!(body["token_endpoint"]
        .as_str()
        .unwrap()
        .contains("/oauth/token"));
    assert!(body["userinfo_endpoint"]
        .as_str()
        .unwrap()
        .contains("/oauth/userinfo"));
    assert!(body["jwks_uri"]
        .as_str()
        .unwrap()
        .contains("/.well-known/jwks.json"));
    assert!(body["revocation_endpoint"]
        .as_str()
        .unwrap()
        .contains("/oauth/revoke"));
    assert!(body["introspection_endpoint"]
        .as_str()
        .unwrap()
        .contains("/oauth/introspect"));

    // Verify supported values
    let response_types = body["response_types_supported"].as_array().unwrap();
    assert!(response_types.iter().any(|v| v == "code"));

    let grant_types = body["grant_types_supported"].as_array().unwrap();
    assert!(grant_types.iter().any(|v| v == "authorization_code"));
    assert!(grant_types.iter().any(|v| v == "refresh_token"));
    assert!(grant_types.iter().any(|v| v == "client_credentials"));

    assert_eq!(body["code_challenge_methods_supported"][0], "S256");
    assert!(body["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "openid"));
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_jwks_returns_ec_key(pool: PgPool) {
    let h = TestHarness::spawn(pool).await;

    let res = h
        .client
        .get(format!("{}/.well-known/jwks.json", h.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    let keys = body["keys"].as_array().unwrap();
    assert!(!keys.is_empty(), "JWKS should have at least one key");

    let key = &keys[0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert_eq!(key["alg"], "ES256");
    assert_eq!(key["use"], "sig");
    assert!(key["kid"].is_string(), "Missing kid");
    assert!(key["x"].is_string(), "Missing x coordinate");
    assert!(key["y"].is_string(), "Missing y coordinate");

    // Validate x and y are 32 bytes (43 base64url chars)
    let x = key["x"].as_str().unwrap();
    let y = key["y"].as_str().unwrap();
    assert_eq!(
        x.len(),
        43,
        "x coordinate should be 43 base64url chars (32 bytes)"
    );
    assert_eq!(
        y.len(),
        43,
        "y coordinate should be 43 base64url chars (32 bytes)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Authorization Endpoint (/oauth/authorize)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorize_redirects_to_login_with_flow_id(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .get(format!("{}/oauth/authorize", h.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "client_test_001"),
            ("redirect_uri", "https://example.com/callback"),
            ("scope", "openid profile"),
            ("state", "random_state_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    // Should redirect to login (302 or follow to login URL)
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("/u/") && final_url.contains("oauth_flow_id="),
        "Should redirect to login page with oauth_flow_id, got: {final_url}"
    );
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorize_rejects_missing_client_id(pool: PgPool) {
    let h = TestHarness::spawn(pool).await;

    let res = h
        .client
        .get(format!("{}/oauth/authorize", h.base_url))
        .query(&[
            ("response_type", "code"),
            ("redirect_uri", "https://example.com/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorize_rejects_invalid_redirect_uri(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .get(format!("{}/oauth/authorize", h.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "client_test_001"),
            ("redirect_uri", "https://evil.com/steal"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    // Must NOT redirect — return error directly (RFC §3.1.2.4)
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"]
        .as_str()
        .unwrap()
        .contains("redirect_uri"));
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorize_rejects_unsupported_response_type(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .get(format!("{}/oauth/authorize", h.base_url))
        .query(&[
            ("response_type", "token"),
            ("client_id", "client_test_001"),
            ("redirect_uri", "https://example.com/callback"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Endpoint (/oauth/token)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_token_rejects_missing_grant_type(pool: PgPool) {
    let h = TestHarness::spawn(pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[("client_id", "client_test_001")])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_token_rejects_unsupported_grant_type(pool: PgPool) {
    let h = TestHarness::spawn(pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[("grant_type", "password")])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_client_credentials_grant(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("scope", "openid"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let cache_control = res
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_string());
    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string(), "Missing access_token");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert!(
        body["refresh_token"].is_null(),
        "client_credentials must NOT issue refresh token"
    );
    assert!(body["scope"].as_str().unwrap().contains("openid"));

    // Cache-Control: no-store per RFC 6749 §5.1
    assert_eq!(cache_control.as_deref(), Some("no-store"));
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_client_credentials_wrong_secret(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client_test_001"),
            ("client_secret", "wrong_secret"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorization_code_grant_full_flow(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Step 1: Start authorization — stores context in Redis
    let oauth_service = &h.state.oauth_as_service;
    let ctx = api_server::services::oauth_as_service::AuthorizationContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid profile".into(),
        state: Some("test_state_xyz".into()),
        code_challenge: None,
        code_challenge_method: None,
        tenant_id: "org_oauth_test".into(),
        nonce: None,
    };
    let flow_id = oauth_service.start_authorization(ctx).await.unwrap();

    // Step 2: Simulate consent grant — create authorization code
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid profile".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: None,
        code_challenge_method: None,
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: Some("dec_oauth_test".into()),
        nonce: None,
    };
    let code = oauth_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    // Consume the auth context (as grant_consent would)
    oauth_service
        .consume_authorization_context(&flow_id)
        .await
        .unwrap();

    // Step 3: Exchange code for tokens at /token
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert!(
        body["refresh_token"].is_string(),
        "Should issue refresh token"
    );
    assert_eq!(body["scope"], "openid profile");

    // Step 4: Code is single-use — reusing should fail
    let res2 = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);
    let body2: Value = res2.json().await.unwrap();
    assert_eq!(body2["error"], "invalid_grant");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_authorization_code_grant_with_pkce(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Generate PKCE values
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = {
        let digest = sha2::Sha256::digest(code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    };

    // Create authorization code with PKCE challenge
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".into()),
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    // Exchange with correct code_verifier
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("code_verifier", code_verifier),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string());
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_pkce_wrong_verifier_rejected(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let correct_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = {
        let digest = sha2::Sha256::digest(correct_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    };

    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".into()),
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    // Exchange with WRONG code_verifier
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("code_verifier", "totally_wrong_verifier_value"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"].as_str().unwrap().contains("PKCE"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Refresh Token Rotation
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_refresh_token_rotation(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Issue initial token set via authorization code
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid profile".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: None,
        code_challenge_method: None,
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    let first_tokens: Value = res.json().await.unwrap();
    let first_rt = first_tokens["refresh_token"].as_str().unwrap();

    // Refresh — should get new tokens + rotated refresh token
    let res2 = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", first_rt),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::OK);
    let second_tokens: Value = res2.json().await.unwrap();
    assert!(second_tokens["access_token"].is_string());
    let second_rt = second_tokens["refresh_token"].as_str().unwrap();
    assert_ne!(first_rt, second_rt, "Refresh token should be rotated");

    // Old refresh token should be rejected (one-time use)
    let res3 = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", first_rt),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res3.status(), StatusCode::BAD_REQUEST);
    let body3: Value = res3.json().await.unwrap();
    assert_eq!(body3["error"], "invalid_grant");

    // Reuse detection: the new token should also be revoked (family revocation)
    let res4 = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", second_rt),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(
        res4.status(),
        StatusCode::BAD_REQUEST,
        "Family should be revoked after reuse"
    );
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_refresh_token_scope_narrowing(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Start with "openid profile email" scope
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_test_001".into(),
        redirect_uri: "https://example.com/callback".into(),
        scope: "openid profile email".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: None,
        code_challenge_method: None,
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.com/callback"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    let tokens: Value = res.json().await.unwrap();
    let rt = tokens["refresh_token"].as_str().unwrap();

    // Refresh with narrowed scope (only openid)
    let res2 = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("scope", "openid"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::OK);
    let body2: Value = res2.json().await.unwrap();
    assert_eq!(
        body2["scope"], "openid",
        "Scope should be narrowed to openid only"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Revocation (RFC 7009)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_revoke_returns_200_always(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Revoke a non-existent token — should still return 200 per RFC 7009
    let res = h
        .client
        .post(format!("{}/oauth/revoke", h.base_url))
        .form(&[
            ("token", "ort_nonexistent_token"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_revoke_requires_client_auth(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/revoke", h.base_url))
        .form(&[
            ("token", "ort_some_token"),
            ("client_id", "client_test_001"),
            ("client_secret", "wrong_secret"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token Introspection (RFC 7662)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_introspect_invalid_token_returns_inactive(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let res = h
        .client
        .post(format!("{}/oauth/introspect", h.base_url))
        .form(&[
            ("token", "invalid_jwt_here"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], false);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_introspect_valid_oauth_token(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    // Issue a token via client_credentials
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("scope", "openid"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    let tokens: Value = res.json().await.unwrap();
    let access_token = tokens["access_token"].as_str().unwrap();

    // Introspect it
    let res2 = h
        .client
        .post(format!("{}/oauth/introspect", h.base_url))
        .form(&[
            ("token", access_token),
            ("client_id", "client_test_001"),
            ("client_secret", "super_secret_value_123"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res2.status(), StatusCode::OK);
    let body: Value = res2.json().await.unwrap();
    assert_eq!(body["active"], true);
    assert_eq!(body["client_id"], "client_test_001");
    assert!(body["scope"].as_str().unwrap().contains("openid"));
    assert_eq!(body["token_type"], "Bearer");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public Client (PKCE-only, no secret)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_public_client_requires_pkce(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;
    seed_public_oauth_client(
        &pool,
        "app_public_test",
        "org_oauth_test",
        "Public SPA",
        "client_public_001",
        &["https://spa.example.com/callback"],
    )
    .await;

    // Public client without code_challenge → should fail at /authorize
    let res = h
        .client
        .get(format!("{}/oauth/authorize", h.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", "client_public_001"),
            ("redirect_uri", "https://spa.example.com/callback"),
            ("scope", "openid"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    // Should redirect with error (PKCE required for mobile apps)
    let final_url = res.url().to_string();
    assert!(
        final_url.contains("error=invalid_request") || res.status() == StatusCode::BAD_REQUEST,
        "Should reject public client without PKCE, got: {final_url}"
    );
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_public_client_with_pkce_succeeds(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;
    seed_public_oauth_client(
        &pool,
        "app_public_test2",
        "org_oauth_test",
        "Public SPA 2",
        "client_public_002",
        &["https://spa.example.com/callback"],
    )
    .await;

    let code_verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let challenge = {
        let digest = sha2::Sha256::digest(code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    };

    // Create auth code directly with PKCE
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_public_002".into(),
        redirect_uri: "https://spa.example.com/callback".into(),
        scope: "openid".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".into()),
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    // Exchange with code_verifier — NO client_secret (public client)
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://spa.example.com/callback"),
            ("client_id", "client_public_002"),
            ("code_verifier", code_verifier),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].is_string());
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_public_client_without_pkce_at_token_rejected(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;
    seed_public_oauth_client(
        &pool,
        "app_public_test3",
        "org_oauth_test",
        "Public SPA 3",
        "client_public_003",
        &["https://spa.example.com/callback"],
    )
    .await;

    // Create auth code WITHOUT PKCE (shouldn't happen via /authorize, but test the defense)
    let code_ctx = api_server::services::oauth_as_service::AuthorizationCodeContext {
        client_id: "client_public_003".into(),
        redirect_uri: "https://spa.example.com/callback".into(),
        scope: "openid".into(),
        user_id: "user_oauth_1".into(),
        session_id: "sess_oauth_1".into(),
        tenant_id: "org_oauth_test".into(),
        code_challenge: None, // No PKCE
        code_challenge_method: None,
        created_at: chrono::Utc::now().timestamp(),
        decision_ref: None,
        nonce: None,
    };
    let code = h
        .state
        .oauth_as_service
        .create_authorization_code(code_ctx)
        .await
        .unwrap();

    // Public client without secret AND without PKCE → must be rejected
    let res = h
        .client
        .post(format!("{}/oauth/token", h.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://spa.example.com/callback"),
            ("client_id", "client_public_003"),
            ("tenant_id", "org_oauth_test"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"].as_str().unwrap().contains("PKCE"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Consent Service (Unit-style tests via direct service calls)
// ═══════════════════════════════════════════════════════════════════════════════

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_consent_grant_and_check(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let svc = &h.state.oauth_as_service;

    // No consent yet
    let has_consent = svc
        .check_consent(
            "user_oauth_1",
            "client_test_001",
            "org_oauth_test",
            "openid profile",
        )
        .await
        .unwrap();
    assert!(!has_consent, "Should have no consent yet");

    // Grant consent
    svc.grant_consent(
        "user_oauth_1",
        "client_test_001",
        "org_oauth_test",
        "openid profile email",
        None,
    )
    .await
    .unwrap();

    // Check — subset should pass
    let has_consent = svc
        .check_consent(
            "user_oauth_1",
            "client_test_001",
            "org_oauth_test",
            "openid profile",
        )
        .await
        .unwrap();
    assert!(has_consent, "Subset of consented scopes should pass");

    // Check — superset should fail
    let has_consent = svc
        .check_consent(
            "user_oauth_1",
            "client_test_001",
            "org_oauth_test",
            "openid profile offline_access",
        )
        .await
        .unwrap();
    assert!(!has_consent, "Superset of consented scopes should fail");

    // Re-consent with narrower scope (upsert)
    svc.grant_consent(
        "user_oauth_1",
        "client_test_001",
        "org_oauth_test",
        "openid",
        None,
    )
    .await
    .unwrap();
    let has_consent = svc
        .check_consent(
            "user_oauth_1",
            "client_test_001",
            "org_oauth_test",
            "openid profile",
        )
        .await
        .unwrap();
    assert!(
        !has_consent,
        "Re-consent with narrower scope should not cover old scopes"
    );
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL and Redis"]
async fn test_consent_revocation_revokes_tokens(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    setup_oauth_fixtures(&pool).await;

    let svc = &h.state.oauth_as_service;

    // Grant consent and create a refresh token
    svc.grant_consent(
        "user_oauth_1",
        "client_test_001",
        "org_oauth_test",
        "openid",
        None,
    )
    .await
    .unwrap();
    let raw_token = svc
        .create_refresh_token(
            "client_test_001",
            "user_oauth_1",
            "sess_oauth_1",
            "org_oauth_test",
            "openid",
            86400,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // Verify token works
    let rt = svc.consume_refresh_token(&raw_token).await.unwrap();
    assert!(rt.is_some(), "Token should be valid before revocation");

    // Create another token (the consumed one is already revoked by rotation)
    let raw_token2 = svc
        .create_refresh_token(
            "client_test_001",
            "user_oauth_1",
            "sess_oauth_1",
            "org_oauth_test",
            "openid",
            86400,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // Revoke consent — should revoke all tokens for this client+user
    svc.revoke_consent("user_oauth_1", "client_test_001", "org_oauth_test")
        .await
        .unwrap();

    // Token should be invalid
    let rt2 = svc.consume_refresh_token(&raw_token2).await.unwrap();
    assert!(
        rt2.is_none(),
        "Token should be revoked after consent revocation"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PKCE Unit Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_pkce_validation_correct_verifier() {
    use api_server::services::oauth_as_service::OAuthAsService;

    // RFC 7636 Appendix B example
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    assert!(OAuthAsService::validate_pkce(verifier, challenge));
}

#[test]
fn test_pkce_validation_wrong_verifier() {
    use api_server::services::oauth_as_service::OAuthAsService;

    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert!(!OAuthAsService::validate_pkce("wrong_verifier", challenge));
}

#[test]
fn test_pkce_validation_empty_strings() {
    use api_server::services::oauth_as_service::OAuthAsService;
    assert!(!OAuthAsService::validate_pkce("", ""));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Redirect URI Validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_redirect_uri_exact_match() {
    use api_server::services::oauth_as_service::OAuthAsService;

    let app = org_manager::Application {
        id: "test".into(),
        tenant_id: "org".into(),
        name: "Test".into(),
        r#type: "web".into(),
        client_id: "cid".into(),
        client_secret_hash: None,
        redirect_uris: serde_json::json!(["https://example.com/callback"]),
        allowed_flows: serde_json::json!(["authorization_code"]),
        public_config: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        allowed_scopes: serde_json::json!(["openid"]),
        is_first_party: false,
        token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 86400,
    };

    assert!(OAuthAsService::validate_redirect_uri(
        &app,
        "https://example.com/callback"
    ));
    assert!(!OAuthAsService::validate_redirect_uri(
        &app,
        "https://example.com/callback/"
    ));
    assert!(!OAuthAsService::validate_redirect_uri(
        &app,
        "https://evil.com/callback"
    ));
    assert!(!OAuthAsService::validate_redirect_uri(&app, ""));
}

#[test]
fn test_scope_resolution() {
    use api_server::services::oauth_as_service::OAuthAsService;

    let app = org_manager::Application {
        id: "test".into(),
        tenant_id: "org".into(),
        name: "Test".into(),
        r#type: "web".into(),
        client_id: "cid".into(),
        client_secret_hash: None,
        redirect_uris: serde_json::json!([]),
        allowed_flows: serde_json::json!([]),
        public_config: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        allowed_scopes: serde_json::json!(["openid", "profile", "email"]),
        is_first_party: false,
        token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 86400,
    };

    // Request valid scopes
    let resolved = OAuthAsService::resolve_scopes(&app, "openid profile");
    let parts: Vec<&str> = resolved.split_whitespace().collect();
    assert!(parts.contains(&"openid"));
    assert!(parts.contains(&"profile"));

    // Request invalid scope — filtered out
    let resolved = OAuthAsService::resolve_scopes(&app, "openid admin");
    assert!(resolved.contains("openid"));
    assert!(!resolved.contains("admin"));

    // Empty request — defaults to all allowed
    let resolved = OAuthAsService::resolve_scopes(&app, "");
    assert!(!resolved.is_empty());
}
