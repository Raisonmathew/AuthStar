use sqlx::PgPool;
use api_server::{config::Config, state::AppState, router};
use reqwest::{Client, StatusCode};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use serde_json::{json, Value};

// Helper to spawn the app
use grpc_api::eiaa::runtime::{ExecuteRequest, ExecuteResponse, GetPublicKeysRequest, GetPublicKeysResponse, Decision, Attestation, AttestationBody};
use grpc_api::eiaa::runtime::capsule_runtime_server::{CapsuleRuntime, CapsuleRuntimeServer};
use tonic::{Request, Response, Status};

#[derive(Default)]
struct MockRuntimeService;

#[tonic::async_trait]
impl CapsuleRuntime for MockRuntimeService {
    async fn execute(
        &self,
        _request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        Ok(Response::new(ExecuteResponse {
            decision: Some(Decision {
                allow: true,
                reason: "".to_string(),
                requirement: None,
                metadata: None,
            }),
            attestation: Some(Attestation {
                body: Some(AttestationBody {
                    capsule_hash_b64: "".to_string(),
                    decision_hash_b64: "".to_string(),
                    executed_at_unix: 0,
                    expires_at_unix: 0,
                    nonce_b64: "".to_string(),
                    runtime_kid: "".to_string(),
                    ast_hash_b64: "".to_string(),
                    wasm_hash_b64: "".to_string(),
                    lowering_version: "".to_string(),
                    achieved_aal: "".to_string(),
                    verified_capabilities: vec![],
                    risk_snapshot_hash: "".to_string(),
                }),
                signature_b64: "".to_string(),
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

async fn spawn_app(pool: PgPool) -> (String, AppState) {
    // Ensure required env vars are set for testing
    // Must be exactly 32 bytes, base64url encoded (no pad). 43 'A's = 32 bytes of zeros.
    std::env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    std::env::set_var("APP_ENV", "test");
    std::env::remove_var("SENDGRID_API_KEY");
    
    // Start mock gRPC server on a random port
    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind random port for gRPC");
    let grpc_addr = grpc_listener.local_addr().unwrap();
    std::env::set_var("RUNTIME_GRPC_ADDR", format!("http://{grpc_addr}"));
    
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CapsuleRuntimeServer::new(MockRuntimeService))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(grpc_listener))
            .await
            .expect("gRPC server failed");
    });
    let mut config = Config::from_env().expect("Failed to load config");
    // Clear the sendgrid api key so that the email service doesn't try to use it and fail
    config.email.sendgrid_api_key = String::new();
    config.app_env = "development".to_string(); // ensure development to suppress email failure
    // Use random port
    config.server.port = 0;
    config.allowed_origins = vec!["http://localhost:3000".into()];
    
    // Create state with test pool
    let state = AppState::new_with_pool(config.clone(), pool.clone())
        .await
        .expect("Failed to init state");

    // Bootstrap system org
    api_server::bootstrap::seed_system_org(&pool).await.expect("Failed to bootstrap");

    // Create router
    let app = router::create_router(state.clone());

    // Spawn server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });

    (format!("http://127.0.0.1:{port}"), state)
}

/// Build a reqwest client that bypasses CSRF by setting an Origin header
/// matching the allowed origin configured in spawn_app.
fn test_client() -> Client {
    Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("Origin", "http://localhost:3000".parse().unwrap());
            // CSRF double-submit: set matching cookie and header
            headers.insert("Cookie", "__csrf=test_csrf_token".parse().unwrap());
            headers.insert("X-CSRF-Token", "test_csrf_token".parse().unwrap());
            headers
        })
        .build()
        .unwrap()
}

#[sqlx::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_admin_signup_flow(pool: PgPool) -> anyhow::Result<()> {
    // 1. Setup
    let (base_url, _state) = spawn_app(pool.clone()).await;
    let client = test_client();

    // 2. Init Flow (Target System Org for Tenant Creation)
    // Route: /api/hosted/auth/flows (hosted_routes::router() mounted at /api/hosted)
    let init_res = client.post(format!("{base_url}/api/hosted/auth/flows"))
        .json(&json!({
            "org_id": "system",
            "app_id": "admin_console",
            "redirect_uri": "http://localhost:3000/callback",
            "intent": "create_tenant"
        }))
        .send()
        .await?;

    assert_eq!(init_res.status(), StatusCode::OK);
    let init_body: Value = init_res.json().await?;
    let flow_id = init_body["flow_id"].as_str().unwrap();
    
    println!("Flow ID: {flow_id}");

    // 3. Submit Credentials (with org_name)
    // Route: /api/hosted/auth/flows/:flow_id/submit
    // The hosted SubmitStepRequest deserializes "type" (not "step_type")
    let email = format!("admin-{}@test.com", uuid::Uuid::new_v4());
    let org_name = format!("Test Org {}", uuid::Uuid::new_v4());
    
    let submit_creds_res = client.post(format!("{base_url}/api/hosted/auth/flows/{flow_id}/submit"))
        .json(&json!({
            "type": "credentials",
            "value": {
                "email": email,
                "password": "StrongPassword123!",
                "first_name": "Test",
                "last_name": "Admin",
                "org_name": org_name
            }
        }))
        .send()
        .await?;
        
    let status = submit_creds_res.status();
    let body_bytes = submit_creds_res.bytes().await?;
    if status != StatusCode::OK {
        panic!("Status: {}, Body: {:?}", status, String::from_utf8_lossy(&body_bytes));
    }
    
    // 4. Get Verification Code from DB directly
    // Wait slightly for async insertion if any (though sqlx is awaited)
    // The previous call returned OK, so ticket should be inserted.
    
    // Need to find the ticket. Credentials step creates a ticket.
    // Ticket ID is in execution_state, but that's internal.
    // Query by email.
    let code: Option<String> = sqlx::query_scalar(
        "SELECT verification_code FROM signup_tickets WHERE email = $1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    
    let code = code.expect("Verification code not found in DB");
    println!("Got verification code: {code}");

    // 5. Submit Verification Code
    let verification_res = client.post(format!("{base_url}/api/hosted/auth/flows/{flow_id}/submit"))
        .json(&json!({
            "type": "email_verification",
            "value": code
        }))
        .send()
        .await?;

    let verify_status = verification_res.status();
    let verify_body_bytes = verification_res.bytes().await?;
    if verify_status != StatusCode::OK {
        panic!("Verify step - Status: {}, Body: {:?}", verify_status, String::from_utf8_lossy(&verify_body_bytes));
    }
    let verify_body: Value = serde_json::from_slice(&verify_body_bytes)?;
    
    // Check if decision is ready
    assert_eq!(verify_body["status"], "decision_ready");

    // 6. Verify Tenant Creation in DB
    let org_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE name = $1)"
    )
    .bind(&org_name)
    .fetch_one(&pool)
    .await?;
    
    assert!(org_exists, "Organization was not created");
    
    // Email is stored in the identities table, not the users table
    let user_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identities WHERE identifier = $1 AND type = 'email')"
    )
    .bind(&email)
    .fetch_one(&pool)
    .await?;

    assert!(user_exists, "User was not created");

    Ok(())
}

#[sqlx::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_provider_admin_login(pool: PgPool) -> anyhow::Result<()> {
    // 1. Setup
    let (base_url, _state) = spawn_app(pool.clone()).await;
    let client = test_client();

    // 2. Create a provider admin first (manual seeding)
    // The schema stores user data across multiple tables:
    //   - users: core identity (id, first_name, last_name, organization_id)
    //   - identities: email/phone/oauth (type, identifier, verified)
    //   - passwords: password hashes (user_id, password_hash)
    let user_id = shared_types::id_generator::generate_id("usr");
    let email = "provider@admin.com";
    let password_hash = auth_core::hash_password("ProviderPass123!").unwrap();
    
    // Ensure system org exists (spawn_app calls bootstrap, so it should be there)
    
    // Insert user (no email/password_hash columns on users table)
    sqlx::query(
        "INSERT INTO users (id, first_name, last_name, organization_id) VALUES ($1, 'Provider', 'Admin', 'system')"
    )
    .bind(&user_id)
    .execute(&pool)
    .await?;

    // Insert identity (email)
    sqlx::query(
        "INSERT INTO identities (id, user_id, type, identifier, verified, organization_id) VALUES ('ident_prov', $1, 'email', $2, true, 'system')"
    )
    .bind(&user_id)
    .bind(email)
    .execute(&pool)
    .await?;

    // Insert password
    sqlx::query(
        "INSERT INTO passwords (user_id, password_hash) VALUES ($1, $2)"
    )
    .bind(&user_id)
    .bind(&password_hash)
    .execute(&pool)
    .await?;

    // Insert membership
    sqlx::query(
        "INSERT INTO memberships (id, user_id, organization_id, role) VALUES ('mem_prov', $1, 'system', 'OWNER')"
    )
    .bind(&user_id)
    .execute(&pool)
    .await?;

    // 3. Init Login Flow
    // Route: /api/hosted/auth/flows
    let init_res = client.post(format!("{base_url}/api/hosted/auth/flows"))
        .json(&json!({
            "org_id": "system",
            "app_id": "admin_console",
            "redirect_uri": "http://localhost:3000/callback",
            "intent": "login"
        }))
        .send()
        .await?;

    assert_eq!(init_res.status(), StatusCode::OK);
    let init_body: Value = init_res.json().await?;
    let flow_id = init_body["flow_id"].as_str().unwrap();

    // 4. Submit Email (identify user)
    // Route: /api/hosted/auth/flows/:flow_id/submit
    // The hosted SubmitStepRequest deserializes "type" (not "step_type")
    let login_res = client.post(format!("{base_url}/api/hosted/auth/flows/{flow_id}/submit"))
        .json(&json!({
            "type": "email",
            "value": email
        }))
        .send()
        .await?;
    let status = login_res.status();
    let body_bytes = login_res.bytes().await?;
    if status != StatusCode::OK {
        panic!("Login Status: {}, Body: {:?}", status, String::from_utf8_lossy(&body_bytes));
    }

    // 5. Submit Password
    let password_res = client.post(format!("{base_url}/api/hosted/auth/flows/{flow_id}/submit"))
        .json(&json!({
            "type": "password",
            "value": "ProviderPass123!"
        }))
        .send()
        .await?;
        
    assert_eq!(password_res.status(), StatusCode::OK);
    let body: Value = password_res.json().await?;
    
    // It might demand MFA (AAL2/3) per valid policy.
    // If risk is low, it might just succeed or ask for OTP.
    // The bootstrapped policy requires AAL2 if password is used.
    // "password_admin_login_policy": requires Assurance AAL2 [otp, passkey]
    
    // So we expect NextStep with acceptable_capabilities including "otp"
    if let Some(status) = body["status"].as_str() {
        if status == "decision_ready" {
             println!("Login success (AAL2 might correspond to decision ready in some configs, or denied if not reached)");
             // Check achieved_aal?
        }
    } else {
        // Should be asking for Step Up (MFA) or completing if policy allows
    }
    
    println!("Login Response: {body:?}");
    
    Ok(())
}
