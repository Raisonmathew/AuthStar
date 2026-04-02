mod common;

use common::harness::TestHarness;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

#[sqlx::test]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_admin_signup_flow(pool: PgPool) -> anyhow::Result<()> {
    // 1. Setup
    let h = TestHarness::spawn(pool.clone()).await;
    let base_url = &h.base_url;
    let client = &h.client;

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
    let h = TestHarness::spawn(pool.clone()).await;
    let base_url = &h.base_url;
    let client = &h.client;

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
