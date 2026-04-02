mod common;

use api_server::router::create_router;
use axum::{body::Body, http::{Request, StatusCode}};
use common::harness::create_test_state;
use common::seed::{seed_org, seed_org_with_config};
use sqlx::PgPool;
use tower::ServiceExt;

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Manifest returns 200 for a known organisation and contains expected fields.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_manifest_returns_200_for_valid_org(pool: PgPool) {
    seed_org_with_config(
        &pool,
        "org_manifest_1",
        "manifest-test-1",
        serde_json::json!({
            "primary_color": "#FF5733",
            "background_color": "#FFFFFF",
            "text_color": "#111111",
            "font_family": "Roboto",
            "logo_url": "https://example.com/logo.png"
        }),
        serde_json::json!({
            "fields": { "email": true, "password": true, "phone": false, "custom_fields": [] },
            "oauth": {
                "google": { "enabled": true, "client_id": "gid", "client_secret": "gsecret" },
                "github": { "enabled": false, "client_id": null, "client_secret": null },
                "microsoft": { "enabled": false, "client_id": null, "client_secret": null }
            },
            "custom_css": "",
            "redirect_urls": []
        }),
    )
    .await;

    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/manifest?org_id=org_manifest_1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body["org_id"], "org_manifest_1");
    assert_eq!(body["branding"]["primary_color"], "#FF5733");
    assert_eq!(body["branding"]["logo_url"], "https://example.com/logo.png");
    // Sign-up fields should contain email and password
    let fields = body["flows"]["sign_up"]["fields"].as_array().unwrap();
    assert!(fields.iter().any(|f| f["name"] == "email"));
    assert!(fields.iter().any(|f| f["name"] == "password"));
    // Google OAuth should appear as enabled
    let providers = body["flows"]["sign_in"]["oauth_providers"].as_array().unwrap();
    let google = providers.iter().find(|p| p["provider"] == "google").unwrap();
    assert_eq!(google["enabled"], true);
}

/// Manifest returns 404 for an unknown org ID.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_manifest_returns_404_for_unknown_org(pool: PgPool) {
    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/manifest?org_id=org_does_not_exist_xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Response body MUST NOT contain `client_secret` or `client_id` at any level.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_manifest_strips_oauth_secrets(pool: PgPool) {
    seed_org_with_config(
        &pool,
        "org_manifest_sec",
        "manifest-sec",
        serde_json::json!({
            "primary_color": "#3B82F6",
            "background_color": "#FFFFFF",
            "text_color": "#1F2937",
            "font_family": "Inter"
        }),
        serde_json::json!({
            "fields": { "email": true, "password": true, "phone": false, "custom_fields": [] },
            "oauth": {
                "google": { "enabled": true, "client_id": "SUPER_SECRET_CLIENT_ID", "client_secret": "SUPER_SECRET_VALUE" },
                "github": { "enabled": true, "client_id": "GH_CLIENT_ID", "client_secret": "GH_SECRET" },
                "microsoft": { "enabled": false, "client_id": null, "client_secret": null }
            },
            "custom_css": "",
            "redirect_urls": []
        }),
    )
    .await;

    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/manifest?org_id=org_manifest_sec")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = std::str::from_utf8(&body_bytes).unwrap();

    // These strings MUST NOT appear anywhere in the serialised response.
    assert!(
        !body_str.contains("client_secret"),
        "Response body must not contain 'client_secret'"
    );
    assert!(
        !body_str.contains("client_id"),
        "Response body must not contain 'client_id'"
    );
    assert!(
        !body_str.contains("SUPER_SECRET"),
        "Response body must not contain secret values"
    );
}

/// Response has `cache-control: public, max-age=60` header.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_manifest_cache_control_header(pool: PgPool) {
    seed_org(&pool, "org_manifest_cc", "manifest-cc").await;

    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/manifest?org_id=org_manifest_cc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let cache_control = response
        .headers()
        .get("cache-control")
        .expect("cache-control header must be present")
        .to_str()
        .unwrap();

    assert!(
        cache_control.contains("max-age=60"),
        "cache-control must contain max-age=60, got: {cache_control}"
    );
    assert!(
        cache_control.contains("public"),
        "cache-control must contain 'public', got: {cache_control}"
    );
}

/// When `auth_config` is NULL in the DB, response should contain default fields (email + password).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_manifest_default_fields_when_auth_config_null(pool: PgPool) {
    // Insert org with no branding or auth_config (NULLs).
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ('org_manifest_null', 'Null Config Corp', 'manifest-null', NOW(), NOW())",
    )
    .execute(&pool)
    .await
    .expect("seed org with null config");

    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/manifest?org_id=org_manifest_null")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let fields = body["flows"]["sign_up"]["fields"].as_array().unwrap();
    assert!(!fields.is_empty(), "Default fields must not be empty");
    assert!(
        fields.iter().any(|f| f["name"] == "email"),
        "Default fields must include email"
    );
    assert!(
        fields.iter().any(|f| f["name"] == "password"),
        "Default fields must include password"
    );

    // Default branding
    assert_eq!(body["branding"]["primary_color"], "#3B82F6");
    assert_eq!(body["branding"]["font_family"], "Inter");
}
