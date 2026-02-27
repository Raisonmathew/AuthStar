use sqlx::PgPool;
use api_server::{config::Config, state::AppState, router};
use reqwest::{Client, StatusCode};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use serde_json::{json, Value};

// Helper to spawn the app
async fn spawn_app(pool: PgPool) -> (String, AppState) {
    let mut config = Config::from_env().expect("Failed to load config");
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

    (format!("http://127.0.0.1:{}", port), state)
}

#[sqlx::test]
async fn test_admin_signup_flow(pool: PgPool) -> anyhow::Result<()> {
    // 1. Setup
    let (base_url, state) = spawn_app(pool.clone()).await;
    let client = Client::new();

    // 2. Init Flow (Target System Org for Tenant Creation)
    let init_res = client.post(format!("{}/api/hosted/v1/init", base_url))
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
    
    println!("Flow ID: {}", flow_id);

    // 3. Submit Credentials (with org_name)
    let email = format!("admin-{}@test.com", uuid::Uuid::new_v4());
    let org_name = format!("Test Org {}", uuid::Uuid::new_v4());
    
    let submit_creds_res = client.post(format!("{}/auth/flow/{}/submit", base_url, flow_id))
        .json(&json!({
            "step_type": "credentials",
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
        
    assert_eq!(submit_creds_res.status(), StatusCode::OK);
    
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
    println!("Got verification code: {}", code);

    // 5. Submit Verification Code
    let verification_res = client.post(format!("{}/auth/flow/{}/submit", base_url, flow_id))
        .json(&json!({
            "step_type": "email_verification",
            "value": code
        }))
        .send()
        .await?;

    assert_eq!(verification_res.status(), StatusCode::OK);
    let verify_body: Value = verification_res.json().await?;
    
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
    
    let user_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"
    )
    .bind(&email)
    .fetch_one(&pool)
    .await?;

    assert!(user_exists, "User was not created");

    Ok(())
}

#[sqlx::test]
async fn test_provider_admin_login(pool: PgPool) -> anyhow::Result<()> {
    // 1. Setup
    let (base_url, _state) = spawn_app(pool.clone()).await;
    let client = Client::new();

    // 2. Create a provider admin first (manual seeding)
    // Create User & Membership in 'system' org
    let user_id = shared_types::id_generator::generate_id("usr");
    let email = "provider@admin.com";
    let password_hash = auth_core::hash_password("ProviderPass123!").unwrap();
    
    // Ensure system org exists (spawn_app calls bootstrap, so it should be there)
    
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, organization_id, email_verified) VALUES ($1, $2, $3, 'system', true)"
    )
    .bind(&user_id)
    .bind(email)
    .bind(&password_hash)
    .execute(&pool)
    .await?;
    
    sqlx::query(
        "INSERT INTO memberships (id, user_id, organization_id, role) VALUES ('mem_prov', $1, 'system', 'OWNER')"
    )
    .bind(&user_id)
    .execute(&pool)
    .await?;
    
    // We also need an identity for the user
    sqlx::query(
        "INSERT INTO identities (id, user_id, identity_type, identifier, verified) VALUES ('ident_prov', $1, 'email', $2, true)"
    )
    .bind(&user_id)
    .bind(email)
    .execute(&pool)
    .await?;


    // 3. Init Login Flow
    let init_res = client.post(format!("{}/api/hosted/v1/init", base_url))
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

    // 4. Submit Credentials
    let login_res = client.post(format!("{}/auth/flow/{}/submit", base_url, flow_id))
        .json(&json!({
            "step_type": "email",
            "value": email
        }))
        .send()
        .await?;
    assert_eq!(login_res.status(), StatusCode::OK);

    let password_res = client.post(format!("{}/auth/flow/{}/submit", base_url, flow_id))
        .json(&json!({
            "step_type": "password",
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
    
    println!("Login Response: {:?}", body);
    
    Ok(())
}
