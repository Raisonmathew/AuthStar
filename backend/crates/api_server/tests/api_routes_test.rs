use api_server::{router::create_router, state::AppState, config::{Config, ServerConfig, DatabaseConfig, RedisConfig, JwtConfig, StripeConfig, EIAAConfig, EmailConfig}};
use auth_core::JwtService;
use keystore::Keystore; // Import trait for generate_ed25519
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt; // for `oneshot`
use redis::aio::ConnectionManager;

// Use project keys for testing
const ES256_PRIVATE_PEM: &str = include_str!("../../../.keys/private.pem");
const ES256_PUBLIC_PEM: &str = include_str!("../../../.keys/public.pem");

// Helper to create test state
async fn create_test_state(pool: PgPool) -> AppState {
    let config = Config {
        app_env: "test".into(),
        server: ServerConfig { host: "127.0.0.1".into(), port: 3000 },
        database: DatabaseConfig { url: "postgres://postgres:postgres@localhost:5432/idaas".into(), max_connections: 5, min_connections: 1, acquire_timeout_secs: 5 },
        redis: RedisConfig { url: "redis://127.0.0.1:6379".into() }, // Assume local redis
        jwt: JwtConfig {
            private_key: ES256_PRIVATE_PEM.to_string(),
            public_key: ES256_PUBLIC_PEM.to_string(),
            issuer: "test_issuer".into(),
            audience: "test_audience".into(),
            expiration_seconds: 3600,
        },
        stripe: StripeConfig { secret_key: "sk_test".into(), webhook_secret: "wh_test".into() },
        eiaa: EIAAConfig {
            runtime_grpc_addr: "http://127.0.0.1:50099".into(), // Non-existent port
            compiler_sk_b64: None,
            iplocate_api_key: None,
            iplocate_enabled: false,
        },
        email: EmailConfig { sendgrid_api_key: "sg_test".into(), from_email: "test@example.com".into(), from_name: "Test".into() },
        allowed_origins: vec!["http://localhost:3000".into()],
        frontend_url: "http://localhost:3000".into(),
        passkey_rp_id: "localhost".into(),
        passkey_origin: "http://localhost:3000".into(),
        require_email_verification: false,
    };

    // Replicate initialization logic from state.rs roughly
    let redis_client = redis::Client::open(config.redis.url.as_str()).expect("redis client");
    // Use a connection manager if possible, or just client
    let redis = ConnectionManager::new(redis_client.clone()).await.expect("redis connection");

    let jwt_service = Arc::new(JwtService::new_ec(
        &config.jwt.private_key,
        &config.jwt.public_key,
        config.jwt.issuer.clone(),
        config.jwt.audience.clone(),
        config.jwt.expiration_seconds,
    ).expect("jwt service"));

    let ks = keystore::InMemoryKeystore::ephemeral();
    let compiler_kid = ks.generate_ed25519().expect("keystore");

    let runtime_client = api_server::clients::runtime_client::SharedRuntimeClient::new(config.eiaa.runtime_grpc_addr.clone()).await.unwrap();

    // Services
    let stripe_service = billing_engine::services::StripeService::new(pool.clone(), config.stripe.secret_key.clone());
    let webhook_service = billing_engine::services::WebhookService::new(pool.clone());
    let app_service = org_manager::services::AppService::new(pool.clone());
    let organization_service = org_manager::services::OrganizationService::new(pool.clone());
    let user_service = identity_engine::services::UserService::new(pool.clone());
    let oauth_service = identity_engine::services::OAuthService::new(pool.clone(), redis_client.clone(), [0u8; 32]);
    
    let email_config = email_service::EmailServiceConfig::from_legacy(config.email.sendgrid_api_key.clone(), config.email.from_email.clone(), config.email.from_name.clone(), 3, 1000);
    let email_service = email_service::EmailService::new(email_config);
    let verification_service = identity_engine::services::VerificationService::new(pool.clone(), email_service.clone());
    let mfa_service = identity_engine::services::MfaService::new(pool.clone(), "IDaaS".into());
    
    let passkey_service = identity_engine::services::PasskeyService::new(pool.clone(), redis.clone(), "localhost", "http://localhost:3000")
        .expect("passkey service");
    
    let eiaa_flow_service = api_server::services::eiaa_flow_service::EiaaFlowService::new(pool.clone(), redis.clone(), email_service.clone());
    let capsule_cache = api_server::services::CapsuleCacheService::new(redis.clone(), 3600);
    let audit_writer = api_server::services::AuditWriterBuilder::new(pool.clone()).build();
    let runtime_key_cache = api_server::services::RuntimeKeyCache::with_ttl(300);
    let attestation_verifier = api_server::services::AttestationVerifier::new();
    let risk_engine = risk_engine::RiskEngine::new(pool.clone());
    let decision_cache = api_server::services::AttestationDecisionCache::new();
    let user_factor_service = api_server::services::UserFactorService::new(pool.clone());

    let nonce_store = api_server::services::NonceStore::new(pool.clone());

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
        wasm_cache: Arc::new(moka::future::Cache::builder().max_capacity(64).build()),
        sso_connection_service: api_server::services::SsoConnectionService::new(pool.clone()),
        api_key_service: api_server::services::ApiKeyService::new(pool.clone()),
        audit_query_service: api_server::services::AuditQueryService::new(pool.clone()),
        invitation_service: org_manager::services::InvitationService::new(pool.clone()),
    }
}

// Helper to seed organization
async fn seed_organization(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ('org_123', 'Test Org', 'test-org', NOW(), NOW())"
    )
    .execute(pool)
    .await
    .expect("seed org");
}

async fn seed_user_and_session(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO users (id) VALUES ('test_user')"
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_organization_id, tenant_id, expires_at) VALUES ('sess_123', 'test_user', 'org_123', 'org_123', NOW() + INTERVAL '1 hour')"
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_health_check(pool: PgPool) {
    seed_organization(&pool).await;
    let state = create_test_state(pool).await;
    let app = create_router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("x-org-slug", "test-org")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_eiaa_protection_unauth(pool: PgPool) {
    seed_organization(&pool).await;
    let state = create_test_state(pool).await;
    let app = create_router(state.clone());

    // Protected route: /api/eiaa/v1/runtime/keys
    // Request without Authorization header
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/eiaa/v1/runtime/keys")
                .header("x-org-slug", "test-org")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_eiaa_protection_fail_closed(pool: PgPool) {
    seed_organization(&pool).await;
    seed_user_and_session(&pool).await;
    let state = create_test_state(pool).await;
    let app = create_router(state.clone());

    // 1. Generate a valid JWT
    let user_id = "test_user";
    // generate_token(user_id, session_id, tenant_id, session_type)
    // tenant_id must match the organization id "org_123" for some checks? 
    // Usually auth middleware checks if token is valid.
    let token = state.jwt_service.generate_token(user_id, "sess_123", "org_123", "end_user").expect("generate token");

    // 2. Access Protected Route: /api/eiaa/v1/runtime/keys
    // This route hits EiaaAuthzLayer -> "eiaa:manage" -> Runtime check
    // Our Runtime client is dead (port 50099).
    // The middleware should attempt authorization, fail to contact runtime, and return Error (500 or 503).
    // IF the middleware was missing, it might hit the handler (which might allow or fail differently).
    // Note: /runtime/keys route tries to get keys from runtime. 
    // Wait, the handler ITSELF calls the runtime too!
    // So 500 could come from middleware OR handler.
    // Let's pick a route where handler doesn't call runtime immediately or check the Logs? 
    // Or better: Use an invalid action? No, middleware checks configured action.
    
    // Actually, if middleware catches it, it logs "EIAA Authorization failed".
    // If we get 500, it means it tried to contact runtime.
    // Ideally we want to distinguish "Runtime down during Auth" vs "Runtime down during Handler".
    // 
    // Reverted to this route as it is explicitly EIAA protected.
    // The handler does NOT contact runtime immediately (it hits DB).
    // So if we get runtime connection error, it MUST be the middleware.
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/eiaa/v1/runtime/keys") // Reverted to this route as it is explicitly EIAA protected
                .header("Authorization", format!("Bearer {token}"))
                .header("x-org-slug", "test-org")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    // Expect 500 Internal Server Error (because middleware fails to dial runtime)
    // or specifically 403 Forbidden if fail_open=false and it can't decide?
    // EiaaAuthzLayer failing to execute usually returns AppError::Internal.
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
#[ignore = "Requires DATABASE_URL and Redis to be set"]
async fn test_malformed_authorization_header() {
    let pool = sqlx::PgPool::connect("postgres://postgres:postgres@localhost:5432/idaas_test").await.unwrap_or_else(|_| {
        // Fallback for CI without DB, using whatever works for the other tests
        PgPoolOptions::new().max_connections(1).connect_lazy("postgres://postgres:postgres@localhost:5432/idaas_test").unwrap()
    });
    let state = create_test_state(pool).await;
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("Authorization", "Bearer invalid_unicode__token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The middleware should cleanly extract the header and fail verification, returning 401.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
