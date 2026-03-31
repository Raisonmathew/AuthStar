use api_server::{
    router::create_router,
    state::AppState,
    config::{
        Config, ServerConfig, DatabaseConfig, RedisConfig, JwtConfig, StripeConfig,
        EIAAConfig, EmailConfig,
    },
};
use auth_core::JwtService;
use keystore::Keystore;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use redis::aio::ConnectionManager;
use moka::future::Cache;

const ES256_PRIVATE_PEM: &str = include_str!("../../../.keys/private.pem");
const ES256_PUBLIC_PEM: &str = include_str!("../../../.keys/public.pem");

// ─── Test State Builder ───────────────────────────────────────────────────────

async fn create_test_state(pool: PgPool) -> AppState {
    let config = Config {
        app_env: "test".into(),
        server: ServerConfig { host: "127.0.0.1".into(), port: 3000 },
        database: DatabaseConfig {
            url: "postgres://postgres:postgres@localhost:5432/idaas".into(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_secs: 5,
        },
        redis: RedisConfig { url: "redis://127.0.0.1:6379".into() },
        jwt: JwtConfig {
            private_key: ES256_PRIVATE_PEM.to_string(),
            public_key: ES256_PUBLIC_PEM.to_string(),
            issuer: "test_issuer".into(),
            audience: "test_audience".into(),
            expiration_seconds: 3600,
        },
        stripe: StripeConfig { secret_key: "sk_test".into(), webhook_secret: "wh_test".into() },
        eiaa: EIAAConfig {
            runtime_grpc_addr: "http://127.0.0.1:50099".into(),
            compiler_sk_b64: None,
            iplocate_api_key: None,
            iplocate_enabled: false,
        },
        email: EmailConfig {
            sendgrid_api_key: "sg_test".into(),
            from_email: "test@example.com".into(),
            from_name: "Test".into(),
        },
        allowed_origins: vec!["http://localhost:3000".into()],
        frontend_url: "http://localhost:3000".into(),
        passkey_rp_id: "localhost".into(),
        passkey_origin: "http://localhost:3000".into(),
        require_email_verification: false,
    };

    let redis_client = redis::Client::open(config.redis.url.as_str()).expect("redis client");
    let redis = ConnectionManager::new(redis_client.clone()).await.expect("redis connection");

    let jwt_service = Arc::new(
        JwtService::new_ec(
            &config.jwt.private_key,
            &config.jwt.public_key,
            config.jwt.issuer.clone(),
            config.jwt.audience.clone(),
            config.jwt.expiration_seconds,
        )
        .expect("jwt service"),
    );

    let ks = keystore::InMemoryKeystore::ephemeral();
    let compiler_kid = ks.generate_ed25519().expect("keystore");

    let runtime_client =
        api_server::clients::runtime_client::SharedRuntimeClient::new(config.eiaa.runtime_grpc_addr.clone())
            .await
            .unwrap();

    let stripe_service = billing_engine::services::StripeService::new(pool.clone(), config.stripe.secret_key.clone());
    let webhook_service = billing_engine::services::WebhookService::new(pool.clone());
    let app_service = org_manager::services::AppService::new(pool.clone());
    let organization_service = org_manager::services::OrganizationService::new(pool.clone());
    let user_service = identity_engine::services::UserService::new(pool.clone());
    let oauth_service = identity_engine::services::OAuthService::new(pool.clone(), redis_client.clone(), [0u8; 32]);

    let email_config = email_service::EmailServiceConfig::from_legacy(
        config.email.sendgrid_api_key.clone(),
        config.email.from_email.clone(),
        config.email.from_name.clone(),
        3,
        1000,
    );
    let email_service = email_service::EmailService::new(email_config);
    let verification_service = identity_engine::services::VerificationService::new(pool.clone(), email_service.clone());
    let mfa_service = identity_engine::services::MfaService::new(pool.clone(), "IDaaS".into());
    let passkey_service = identity_engine::services::PasskeyService::new(
        pool.clone(),
        redis.clone(),
        "localhost",
        "http://localhost:3000",
    )
    .expect("passkey service");

    let eiaa_flow_service =
        api_server::services::eiaa_flow_service::EiaaFlowService::new(pool.clone(), redis.clone(), email_service.clone());
    let capsule_cache = api_server::services::CapsuleCacheService::new(redis.clone(), 3600);
    let audit_writer = api_server::services::AuditWriterBuilder::new(pool.clone()).build();
    let runtime_key_cache = api_server::services::RuntimeKeyCache::with_ttl(300);
    let attestation_verifier = api_server::services::AttestationVerifier::new();
    let risk_engine = risk_engine::RiskEngine::new(pool.clone());
    let decision_cache = api_server::services::AttestationDecisionCache::new();
    let user_factor_service = api_server::services::UserFactorService::new(pool.clone());
    let nonce_store = api_server::services::NonceStore::new(pool.clone());
    let wasm_cache = Arc::new(
        Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(3600))
            .build(),
    );

    AppState {
        db: pool.clone(),
        redis: redis.clone(),
        nonce_store,
        jwt_service,
        config: Arc::new(config),
        runtime_client,
        ks,
        compiler_kid,
        stripe_service,
        webhook_service,
        app_service,
        organization_service,
        user_service,
        verification_service,
        mfa_service,
        oauth_service,
        passkey_service,
        eiaa_flow_service,
        email_service,
        capsule_cache,
        audit_writer,
        runtime_key_cache,
        attestation_verifier,
        risk_engine,
        decision_cache,
        user_factor_service,
        wasm_cache,
        sso_connection_service: api_server::services::SsoConnectionService::new(pool.clone()),
        api_key_service: api_server::services::ApiKeyService::new(pool.clone()),
        audit_query_service: api_server::services::AuditQueryService::new(pool.clone()),
        invitation_service: org_manager::services::InvitationService::new(pool.clone()),
    }
}

// ─── Seed Helpers ─────────────────────────────────────────────────────────────

/// Insert a minimal organisation and return its `id`.
async fn seed_org_minimal(pool: &PgPool, id: &str, slug: &str) {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{slug} Corp"))
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed org minimal");
}

/// Insert an org with explicit branding and auth_config JSON.
async fn seed_org_with_config(
    pool: &PgPool,
    id: &str,
    slug: &str,
    branding: serde_json::Value,
    auth_config: serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, branding, auth_config, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{slug} Corp"))
    .bind(slug)
    .bind(branding)
    .bind(auth_config)
    .execute(pool)
    .await
    .expect("seed org with config");
}

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
    seed_org_minimal(&pool, "org_manifest_cc", "manifest-cc").await;

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
