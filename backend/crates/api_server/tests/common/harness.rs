//! Shared test harness for API server integration tests.
//!
//! Provides `TestHarness` which boots a full in-process API server (Axum + mock gRPC)
//! using `Config::from_env()` + `AppState::new_with_pool()` — the same path production
//! uses. This avoids manually constructing `AppState` fields, which breaks whenever the
//! struct layout changes.
//!
//! # Usage
//!
//! ```rust
//! use common::harness::TestHarness;
//!
//! #[sqlx::test(migrations = "../db_migrations/migrations")]
//! async fn my_test(pool: PgPool) {
//!     let h = TestHarness::spawn(pool).await;
//!     let res = h.client.get(format!("{}/api/v1/health", h.base_url)).send().await.unwrap();
//!     assert_eq!(res.status(), 200);
//! }
//! ```

use api_server::{config::Config, state::AppState, router};
use grpc_api::eiaa::runtime::{
    capsule_runtime_server::{CapsuleRuntime, CapsuleRuntimeServer},
    Attestation, AttestationBody, Decision, ExecuteRequest, ExecuteResponse,
    GetPublicKeysRequest, GetPublicKeysResponse,
};
use reqwest::Client;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

// ─── Mock gRPC Runtime ────────────────────────────────────────────────────────

/// A mock `CapsuleRuntime` that always returns `allow: true`.
#[derive(Default)]
pub struct MockRuntimeService;

#[tonic::async_trait]
impl CapsuleRuntime for MockRuntimeService {
    async fn execute(
        &self,
        _request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        Ok(Response::new(ExecuteResponse {
            decision: Some(Decision {
                allow: true,
                reason: String::new(),
                requirement: None,
                metadata: None,
            }),
            attestation: Some(Attestation {
                body: Some(AttestationBody {
                    capsule_hash_b64: String::new(),
                    decision_hash_b64: String::new(),
                    executed_at_unix: 0,
                    expires_at_unix: 0,
                    nonce_b64: String::new(),
                    runtime_kid: String::new(),
                    ast_hash_b64: String::new(),
                    wasm_hash_b64: String::new(),
                    lowering_version: String::new(),
                    achieved_aal: String::new(),
                    verified_capabilities: vec![],
                    risk_snapshot_hash: String::new(),
                }),
                signature_b64: String::new(),
            }),
        }))
    }

    async fn get_public_keys(
        &self,
        _request: Request<GetPublicKeysRequest>,
    ) -> Result<Response<GetPublicKeysResponse>, Status> {
        Ok(Response::new(GetPublicKeysResponse { keys: vec![] }))
    }
}

/// Start a mock gRPC server on a random port. Returns the `http://host:port` address.
pub async fn start_mock_grpc() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random gRPC port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CapsuleRuntimeServer::new(MockRuntimeService))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });
    format!("http://{addr}")
}

// ─── Env Var Setup ────────────────────────────────────────────────────────────

const ES256_PRIVATE_PEM: &str = include_str!("../../../../.keys/private.pem");
const ES256_PUBLIC_PEM: &str = include_str!("../../../../.keys/public.pem");

/// Set the constant env vars that `Config::from_env()` requires.
/// Safe to call multiple times (idempotent values).
fn ensure_test_env() {
    // 32-byte key → 43 base64url chars
    std::env::set_var(
        "OAUTH_TOKEN_ENCRYPTION_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    std::env::set_var("APP_ENV", "test");
    std::env::set_var("IDAAS_BOOTSTRAP_PASSWORD", "test_admin_password_123");
    std::env::set_var("JWT_PRIVATE_KEY", ES256_PRIVATE_PEM);
    std::env::set_var("JWT_PUBLIC_KEY", ES256_PUBLIC_PEM);
    // Remove real SendGrid key so emails aren't sent
    std::env::remove_var("SENDGRID_API_KEY");
}

// ─── TestHarness ──────────────────────────────────────────────────────────────

/// A fully-booted test environment: Axum server + mock gRPC + AppState.
pub struct TestHarness {
    /// Base URL of the Axum server, e.g. `http://127.0.0.1:12345`
    pub base_url: String,
    /// Shared state – useful for generating tokens, accessing services, etc.
    pub state: AppState,
    /// Pre-configured HTTP client with CSRF & Origin headers.
    pub client: Client,
}

impl TestHarness {
    /// Boot the full stack from a `#[sqlx::test]`-provided pool.
    pub async fn spawn(pool: PgPool) -> Self {
        ensure_test_env();

        let grpc_addr = start_mock_grpc().await;

        let mut config = Config::from_env().expect("Config::from_env");
        config.eiaa.runtime_grpc_addr = grpc_addr;
        config.email.sendgrid_api_key = String::new();
        config.app_env = "development".to_string();
        config.server.port = 0;
        config.allowed_origins = vec!["http://localhost:3000".into()];

        let state = AppState::new_with_pool(config, pool.clone())
            .await
            .expect("AppState::new_with_pool");

        api_server::bootstrap::seed_system_org(&pool)
            .await
            .expect("seed_system_org");

        let app = router::create_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            state,
            client: test_client(),
        }
    }
}

// ─── create_test_state ────────────────────────────────────────────────────────

/// Build an `AppState` (without an HTTP server) for in-process `oneshot()` testing.
/// Each call starts its own mock gRPC server so tests can run in parallel.
pub async fn create_test_state(pool: PgPool) -> AppState {
    ensure_test_env();

    let grpc_addr = start_mock_grpc().await;

    let mut config = Config::from_env().expect("Config::from_env");
    config.eiaa.runtime_grpc_addr = grpc_addr;
    config.email.sendgrid_api_key = String::new();
    config.app_env = "development".to_string();
    config.server.port = 0;
    config.allowed_origins = vec!["http://localhost:3000".into()];

    AppState::new_with_pool(config, pool)
        .await
        .expect("AppState::new_with_pool")
}

// ─── HTTP Client ──────────────────────────────────────────────────────────────

/// Build a `reqwest::Client` pre-configured with Origin + CSRF headers
/// matching the allowed origin used in `TestHarness::spawn`.
pub fn test_client() -> Client {
    Client::builder()
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert("Origin", "http://localhost:3000".parse().unwrap());
            h.insert("Cookie", "__csrf=test_csrf_token".parse().unwrap());
            h.insert("X-CSRF-Token", "test_csrf_token".parse().unwrap());
            h
        })
        .build()
        .unwrap()
}
