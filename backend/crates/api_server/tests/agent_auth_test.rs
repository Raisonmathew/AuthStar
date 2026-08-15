//! AI Agent Authentication & Authorization — Integration Test Suite
//!
//! Covers all new AI agent endpoints, EIAA middleware extensions, audit chain
//! routes, and webhook service across every Sprint A–D feature:
//!
//! ## Coverage areas
//! - **Sprint A** — Agent registration, token issuance, delegation depth
//! - **Sprint B** — Tool-call authorization, capsule dispatch, blocklist
//! - **Sprint C** — Audit task chain, agent history, cursor pagination
//! - **Sprint D** — Webhook payload HMAC, event kind serialization
//! - **Security** — Tenant isolation, session-type gate, JWT forgery, replay
//!
//! ## Running
//! ```bash
//! export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/authstar_test
//! cargo test -p api_server --test agent_auth_test -- --nocapture
//! ```

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

mod common;
use common::harness::TestHarness;
use common::seed::*;

// ─── shared helpers ────────────────────────────────────────────────────────────

/// Seed an admin session row and mint the matching JWT.
///
/// The EIAA middleware looks up the `sid` claim in the `sessions` table
/// (tenant-scoped, non-revoked, not expired) before authorising admin routes.
/// This helper seeds that row so the middleware accepts the token.
async fn admin_token(h: &TestHarness, pool: &PgPool, user_id: &str, tenant_id: &str) -> String {
    // Use a deterministic but unique session id so parallel tests don't collide.
    let sid = format!("sess_adm_{}_{}", user_id, tenant_id);
    seed_admin_session(pool, &sid, user_id, tenant_id).await;
    h.state
        .jwt_service
        .generate_token(user_id, &sid, tenant_id, "admin")
        .expect("mint admin token")
}

/// Mint an **agent** JWT with full agent claims.
fn agent_token(
    h: &TestHarness,
    agent_id: &str,
    tenant_id: &str,
    task_id: &str,
    allowed_tools: Option<Vec<String>>,
    delegation_chain: Option<Vec<String>>,
) -> String {
    let now = Utc::now();
    let claims = auth_core::jwt::Claims {
        sub: agent_id.to_string(),
        iss: h.state.config.jwt.issuer.clone(),
        aud: h.state.config.jwt.audience.clone(),
        exp: now.timestamp() + 3600,
        iat: now.timestamp(),
        nbf: now.timestamp(),
        sid: String::new(), // agent tokens have empty sid
        tenant_id: tenant_id.to_string(),
        session_type: "agent".to_string(),
        agent_id: Some(agent_id.to_string()),
        model_id: Some("claude-3-5-sonnet-20241022".to_string()),
        task_id: Some(task_id.to_string()),
        delegation_chain,
        allowed_tools,
        principal_source: Some("pre_registered".to_string()),
    };
    h.state.jwt_service.sign_claims(&claims).expect("mint agent token")
}

/// Seed an `agent_principals` row directly (bypasses HTTP layer for test setup).
async fn seed_agent(pool: &PgPool, tenant_id: &str, agent_id: &str, name: &str) {
    sqlx::query(
        r#"
        INSERT INTO agent_principals
            (id, tenant_id, agent_id, name, model_id, allowed_tools,
             max_delegation_depth, token_ttl_seconds, principal_source, active)
        VALUES
            (gen_random_uuid()::text, $1, $2, $3,
             'claude-3-5-sonnet-20241022', 'web_search send_email', 3, 3600,
             'pre_registered', TRUE)
        ON CONFLICT (agent_id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed_agent");
}

/// Seed an `agent_principals` row with custom allowed_tools and max_delegation_depth.
async fn seed_agent_custom(
    pool: &PgPool,
    tenant_id: &str,
    agent_id: &str,
    name: &str,
    allowed_tools: &str,
    max_depth: i16,
) {
    sqlx::query(
        r#"
        INSERT INTO agent_principals
            (id, tenant_id, agent_id, name, model_id, allowed_tools,
             max_delegation_depth, token_ttl_seconds, principal_source, active)
        VALUES
            (gen_random_uuid()::text, $1, $2, $3,
             'claude-3-5-sonnet-20241022', $4, $5, 3600,
             'pre_registered', TRUE)
        ON CONFLICT (agent_id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(name)
    .bind(allowed_tools)
    .bind(max_depth)
    .execute(pool)
    .await
    .expect("seed_agent_custom");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint A — Agent Registration
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A.1: Registering a new agent returns 201 with the expected payload.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_success(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_reg_1", "reg-1").await;
    seed_user(&pool, "usr_reg_1", "org_reg_1").await;

    let token = admin_token(&h, &pool, "usr_reg_1", "org_reg_1").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/register", h.base_url))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Claude Assistant",
            "model_id": "claude-3-5-sonnet-20241022",
            "allowed_tools": "web_search send_email",
            "max_delegation_depth": 2,
            "token_ttl_seconds": 1800
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let body: Value = res.json().await.unwrap();
    assert!(body["agent_id"].as_str().unwrap().starts_with("agt_"));
    assert_eq!(body["name"], "Claude Assistant");
    assert_eq!(body["max_delegation_depth"], 2);
    assert_eq!(body["token_ttl_seconds"], 1800);
    assert_eq!(body["principal_source"], "pre_registered");
}

/// A.2: Re-registering the same name upserts (updates) the agent.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_upsert(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_reg_2", "reg-2").await;
    seed_user(&pool, "usr_reg_2", "org_reg_2").await;

    let token = admin_token(&h, &pool, "usr_reg_2", "org_reg_2").await;
    let url = format!("{}/api/v1/agents/register", h.base_url);

    // First registration
    let res1 = h
        .client
        .post(&url)
        .bearer_auth(&token)
        .json(&json!({ "name": "Shared Agent", "allowed_tools": "web_search" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res1.status(), StatusCode::CREATED);
    let first_id = res1.json::<Value>().await.unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Second registration with same name — must return same agent_id
    let res2 = h
        .client
        .post(&url)
        .bearer_auth(&token)
        .json(&json!({
            "name": "Shared Agent",
            "allowed_tools": "web_search send_email",
            "token_ttl_seconds": 7200
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res2.status(), StatusCode::CREATED);
    let body2: Value = res2.json().await.unwrap();
    assert_eq!(body2["agent_id"].as_str().unwrap(), first_id.as_str());
    // Updated fields should reflect new values
    assert_eq!(body2["token_ttl_seconds"], 7200);
}

/// A.3: Registration with max_delegation_depth out-of-range returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_invalid_depth(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_reg_3", "reg-3").await;
    seed_user(&pool, "usr_reg_3", "org_reg_3").await;

    let token = admin_token(&h, &pool, "usr_reg_3", "org_reg_3").await;

    for bad_depth in [0_i64, 9] {
        let res = h
            .client
            .post(format!("{}/api/v1/agents/register", h.base_url))
            .bearer_auth(&token)
            .json(&json!({
                "name": format!("Agent d{bad_depth}"),
                "max_delegation_depth": bad_depth
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "depth={bad_depth} must be rejected"
        );
    }
}

/// A.4: Registration with token_ttl_seconds out of range returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_invalid_ttl(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_reg_4", "reg-4").await;
    seed_user(&pool, "usr_reg_4", "org_reg_4").await;

    let token = admin_token(&h, &pool, "usr_reg_4", "org_reg_4").await;

    for bad_ttl in [0_i64, 59, 86401] {
        let res = h
            .client
            .post(format!("{}/api/v1/agents/register", h.base_url))
            .bearer_auth(&token)
            .json(&json!({ "name": format!("Agent ttl{bad_ttl}"), "token_ttl_seconds": bad_ttl }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "ttl={bad_ttl} must be rejected"
        );
    }
}

/// A.5: cimd_metadata_url must use https:// — http:// returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_cimd_url_must_be_https(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_reg_5", "reg-5").await;
    seed_user(&pool, "usr_reg_5", "org_reg_5").await;

    let token = admin_token(&h, &pool, "usr_reg_5", "org_reg_5").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/register", h.base_url))
        .bearer_auth(&token)
        .json(&json!({
            "name": "CIMD Agent",
            "cimd_metadata_url": "http://evil.example.com/meta"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// A.6: Registration requires an authenticated session.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_register_agent_requires_auth(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;

    let res = h
        .client
        .post(format!("{}/api/v1/agents/register", h.base_url))
        .json(&json!({ "name": "Unauthenticated" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint A — Token Issuance
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// B.1: Admin session can issue an agent token for a registered agent.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_success(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_1", "tok-1").await;
    seed_user(&pool, "usr_tok_1", "org_tok_1").await;
    seed_agent(&pool, "org_tok_1", "agt_tok_001", "Token Agent").await;

    let token = admin_token(&h, &pool, "usr_tok_1", "org_tok_1").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({
            "agent_id": "agt_tok_001",
            "task_id": "task_tok_abc",
            "delegation_chain": []
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["agent_id"], "agt_tok_001");
    assert_eq!(body["task_id"], "task_tok_abc");
    assert!(body["expires_in"].as_i64().unwrap() > 0);

    // Verify the returned JWT decodes correctly as an agent token
    let agent_jwt = body["token"].as_str().unwrap();
    let decoded = h.state.jwt_service.verify_token(agent_jwt).unwrap();
    assert_eq!(decoded.session_type, "agent");
    assert_eq!(decoded.agent_id.as_deref(), Some("agt_tok_001"));
    assert_eq!(decoded.task_id.as_deref(), Some("task_tok_abc"));
    assert_eq!(decoded.sid, ""); // agent tokens have empty sid
}

/// B.2: End-user session cannot issue an agent token (session_type gate).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_end_user_blocked(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_2", "tok-2").await;
    seed_user(&pool, "usr_tok_2", "org_tok_2").await;
    seed_agent(&pool, "org_tok_2", "agt_tok_002", "Token Agent 2").await;

    // End-user token — must also have a valid session row so the EIAA middleware
    // session-validity check passes and the route's session_type gate fires (403).
    seed_admin_session(&pool, "sess_eu_tok2", "usr_tok_2", "org_tok_2").await;
    let token = h
        .state
        .jwt_service
        .generate_token("usr_tok_2", "sess_eu_tok2", "org_tok_2", "end_user")
        .unwrap();

    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "agent_id": "agt_tok_002", "task_id": "task_eu" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// B.3: Agent session cannot issue a second agent token (no sub-agent self-issuance).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_agent_session_blocked(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_3", "tok-3").await;
    seed_agent(&pool, "org_tok_3", "agt_tok_003", "Parent Agent").await;

    let agt = agent_token(&h, "agt_tok_003", "org_tok_3", "task_parent", None, None);

    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({ "agent_id": "agt_tok_003", "task_id": "task_sub" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// B.4: Issuing token for an inactive agent returns 404.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_inactive_agent(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_4", "tok-4").await;
    seed_user(&pool, "usr_tok_4", "org_tok_4").await;
    // Seed inactive agent
    sqlx::query(
        "INSERT INTO agent_principals (id, tenant_id, agent_id, name, allowed_tools, active)
         VALUES (gen_random_uuid()::text, $1, $2, $3, '', FALSE)
         ON CONFLICT (agent_id) DO NOTHING",
    )
    .bind("org_tok_4")
    .bind("agt_tok_inactive")
    .bind("Inactive Agent")
    .execute(&pool)
    .await
    .unwrap();

    let token = admin_token(&h, &pool, "usr_tok_4", "org_tok_4").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "agent_id": "agt_tok_inactive", "task_id": "task_x" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// B.5: Token issuance with delegation depth at max returns 403.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_depth_exceeded(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_5", "tok-5").await;
    seed_user(&pool, "usr_tok_5", "org_tok_5").await;
    // max_delegation_depth = 1 → providing chain of length 1 already saturates it
    seed_agent_custom(
        &pool,
        "org_tok_5",
        "agt_tok_depth",
        "Depth Agent",
        "web_search",
        1,
    )
    .await;

    let token = admin_token(&h, &pool, "usr_tok_5", "org_tok_5").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({
            "agent_id": "agt_tok_depth",
            "task_id": "task_deep",
            "delegation_chain": ["usr_human123"]   // length 1 == max_depth → exceed
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// B.6: Requested tool override must be a subset of registered allowed_tools.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issue_agent_token_tool_override_not_subset(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tok_6", "tok-6").await;
    seed_user(&pool, "usr_tok_6", "org_tok_6").await;
    seed_agent_custom(
        &pool,
        "org_tok_6",
        "agt_tok_tools",
        "Tool Agent",
        "web_search",
        3,
    )
    .await;

    let token = admin_token(&h, &pool, "usr_tok_6", "org_tok_6").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({
            "agent_id": "agt_tok_tools",
            "task_id": "task_tools",
            // "make_payment" is NOT in registered allowed_tools
            "allowed_tools": ["web_search", "make_payment"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint A — Agent Lifecycle (List, Get, Deactivate, Update)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// C.1: List agents returns only active agents for the tenant.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_list_agents(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_list_1", "list-1").await;
    seed_user(&pool, "usr_list_1", "org_list_1").await;
    seed_agent(&pool, "org_list_1", "agt_list_001", "Listed Agent 1").await;
    seed_agent(&pool, "org_list_1", "agt_list_002", "Listed Agent 2").await;
    // Inactive agent — should NOT appear
    sqlx::query(
        "INSERT INTO agent_principals (id, tenant_id, agent_id, name, allowed_tools, active)
         VALUES (gen_random_uuid()::text, $1, $2, $3, '', FALSE)
         ON CONFLICT (agent_id) DO NOTHING",
    )
    .bind("org_list_1")
    .bind("agt_list_inactive")
    .bind("Inactive")
    .execute(&pool)
    .await
    .unwrap();

    let token = admin_token(&h, &pool, "usr_list_1", "org_list_1").await;
    let res = h
        .client
        .get(format!("{}/api/v1/agents", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Vec<Value> = res.json().await.unwrap();
    assert_eq!(body.len(), 2, "exactly two active agents expected");
    let ids: Vec<&str> = body.iter().map(|v| v["agent_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"agt_list_001"));
    assert!(ids.contains(&"agt_list_002"));
    assert!(!ids.contains(&"agt_list_inactive"));
}

/// C.2: Get agent by ID succeeds for an active agent.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_agent_by_id(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_get_1", "get-1").await;
    seed_user(&pool, "usr_get_1", "org_get_1").await;
    seed_agent(&pool, "org_get_1", "agt_get_001", "Get Agent").await;

    let token = admin_token(&h, &pool, "usr_get_1", "org_get_1").await;
    let res = h
        .client
        .get(format!("{}/api/v1/agents/agt_get_001", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["agent_id"], "agt_get_001");
    assert_eq!(body["name"], "Get Agent");
    assert_eq!(body["active"], true);
}

/// C.3: Get a non-existent agent returns 404.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_agent_not_found(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_get_2", "get-2").await;
    seed_user(&pool, "usr_get_2", "org_get_2").await;

    let token = admin_token(&h, &pool, "usr_get_2", "org_get_2").await;
    let res = h
        .client
        .get(format!("{}/api/v1/agents/agt_nonexistent", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// C.4: Deactivate agent sets active=FALSE; subsequent get returns 404.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_deactivate_agent(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_deact_1", "deact-1").await;
    seed_user(&pool, "usr_deact_1", "org_deact_1").await;
    seed_agent(&pool, "org_deact_1", "agt_deact_001", "Deact Agent").await;

    let token = admin_token(&h, &pool, "usr_deact_1", "org_deact_1").await;

    // Deactivate
    let res = h
        .client
        .delete(format!("{}/api/v1/agents/agt_deact_001", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Verify: get returns 404
    let res2 = h
        .client
        .get(format!("{}/api/v1/agents/agt_deact_001", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res2.status(), StatusCode::NOT_FOUND);
}

/// C.5: Deactivating an already-inactive agent returns 404.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_deactivate_already_inactive_agent(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_deact_2", "deact-2").await;
    seed_user(&pool, "usr_deact_2", "org_deact_2").await;
    sqlx::query(
        "INSERT INTO agent_principals (id, tenant_id, agent_id, name, allowed_tools, active)
         VALUES (gen_random_uuid()::text, $1, $2, $3, '', FALSE)
         ON CONFLICT (agent_id) DO NOTHING",
    )
    .bind("org_deact_2")
    .bind("agt_deact_inactive")
    .bind("Already Inactive")
    .execute(&pool)
    .await
    .unwrap();

    let token = admin_token(&h, &pool, "usr_deact_2", "org_deact_2").await;
    let res = h
        .client
        .delete(format!("{}/api/v1/agents/agt_deact_inactive", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// C.6: Update agent — partial update via PUT with COALESCE semantics.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_update_agent(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_upd_1", "upd-1").await;
    seed_user(&pool, "usr_upd_1", "org_upd_1").await;
    seed_agent(&pool, "org_upd_1", "agt_upd_001", "Update Agent").await;

    let token = admin_token(&h, &pool, "usr_upd_1", "org_upd_1").await;
    let res = h
        .client
        .put(format!("{}/api/v1/agents/agt_upd_001", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "token_ttl_seconds": 7200 }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["token_ttl_seconds"], 7200);
    // Other fields are unchanged by COALESCE
    assert_eq!(body["agent_id"], "agt_upd_001");
}

/// C.7: Update with invalid depth returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_update_agent_invalid_depth(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_upd_2", "upd-2").await;
    seed_user(&pool, "usr_upd_2", "org_upd_2").await;
    seed_agent(&pool, "org_upd_2", "agt_upd_002", "Update Agent 2").await;

    let token = admin_token(&h, &pool, "usr_upd_2", "org_upd_2").await;
    let res = h
        .client
        .put(format!("{}/api/v1/agents/agt_upd_002", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "max_delegation_depth": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint B — Tool-Call Authorization (authorize_tool_call)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// D.1: Agent session can call authorize — empty tool_name returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_authorize_tool_call_empty_tool_name(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_authz_1", "authz-1").await;
    seed_agent(&pool, "org_authz_1", "agt_authz_001", "Authz Agent").await;

    let agt = agent_token(
        &h,
        "agt_authz_001",
        "org_authz_1",
        "task_authz_1",
        Some(vec!["web_search".into()]),
        None,
    );

    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_authz_001/authorize", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({ "tool_name": "" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// D.2: Human session calling /authorize returns 403.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_authorize_tool_call_human_session_blocked(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_authz_2", "authz-2").await;
    seed_user(&pool, "usr_authz_2", "org_authz_2").await;
    seed_agent(&pool, "org_authz_2", "agt_authz_002", "Authz Agent 2").await;

    let human_tok = admin_token(&h, &pool, "usr_authz_2", "org_authz_2").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_authz_002/authorize", h.base_url))
        .bearer_auth(&human_tok)
        .json(&json!({ "tool_name": "web_search" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// D.3: agent_id in JWT mismatch with path parameter returns 403.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_authorize_tool_call_agent_id_mismatch(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_authz_3", "authz-3").await;
    seed_agent(&pool, "org_authz_3", "agt_authz_003a", "Agent A").await;
    seed_agent(&pool, "org_authz_3", "agt_authz_003b", "Agent B").await;

    // JWT claims agent 003a but path says 003b
    let agt = agent_token(
        &h,
        "agt_authz_003a",
        "org_authz_3",
        "task_mismatch",
        None,
        None,
    );

    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_authz_003b/authorize", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({ "tool_name": "web_search" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint B — Record Execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// E.1: Record execution returns 201 with execution_id, tool_name, task_id.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_record_execution_success(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rec_1", "rec-1").await;
    seed_agent(&pool, "org_rec_1", "agt_rec_001", "Record Agent").await;

    let agt = agent_token(
        &h,
        "agt_rec_001",
        "org_rec_1",
        "task_rec_001",
        Some(vec!["web_search".into()]),
        None,
    );

    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_rec_001/executions", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({
            "tool_name": "web_search",
            "task_id": "task_rec_001",
            "allowed": true,
            "delegation_depth": 0
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let body: Value = res.json().await.unwrap();
    assert!(body["execution_id"].as_str().is_some());
    assert_eq!(body["tool_name"], "web_search");
    assert_eq!(body["task_id"], "task_rec_001");
}

/// E.2: Record execution with empty tool_name returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_record_execution_empty_tool_name(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rec_2", "rec-2").await;
    seed_agent(&pool, "org_rec_2", "agt_rec_002", "Record Agent 2").await;

    let agt = agent_token(&h, "agt_rec_002", "org_rec_2", "task_rec_002", None, None);

    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_rec_002/executions", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({
            "tool_name": "",
            "task_id": "task_rec_002",
            "allowed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// E.3: Record execution with empty task_id returns 400.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_record_execution_empty_task_id(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rec_3", "rec-3").await;
    seed_agent(&pool, "org_rec_3", "agt_rec_003", "Record Agent 3").await;

    let agt = agent_token(&h, "agt_rec_003", "org_rec_3", "task_rec_003", None, None);

    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_rec_003/executions", h.base_url))
        .bearer_auth(&agt)
        .json(&json!({ "tool_name": "web_search", "task_id": "", "allowed": true }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// E.4: Human session calling /executions returns 403.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_record_execution_human_session_blocked(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rec_4", "rec-4").await;
    seed_user(&pool, "usr_rec_4", "org_rec_4").await;
    seed_agent(&pool, "org_rec_4", "agt_rec_004", "Record Agent 4").await;

    let human_tok = admin_token(&h, &pool, "usr_rec_4", "org_rec_4").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_rec_004/executions", h.base_url))
        .bearer_auth(&human_tok)
        .json(&json!({ "tool_name": "web_search", "task_id": "task_x", "allowed": true }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint F — Token Revocation (Redis Blocklist)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// F.1: Revoke endpoint writes a Redis blocklist key.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_agent_tokens_writes_blocklist(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rev_1", "rev-1").await;
    seed_user(&pool, "usr_rev_1", "org_rev_1").await;
    seed_agent(&pool, "org_rev_1", "agt_rev_001", "Revoke Agent").await;

    let token = admin_token(&h, &pool, "usr_rev_1", "org_rev_1").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_rev_001/revoke", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Verify Redis blocklist key exists
    let exists: i64 = redis::cmd("EXISTS")
        .arg("agent_blocklist:agt_rev_001")
        .query_async::<_, i64>(&mut h.state.redis.clone())
        .await
        .unwrap_or(0);
    assert_eq!(exists, 1, "blocklist key must be set in Redis");
}

/// F.2: Revoking a non-existent agent returns 404.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_revoke_nonexistent_agent_returns_404(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_rev_2", "rev-2").await;
    seed_user(&pool, "usr_rev_2", "org_rev_2").await;

    let token = admin_token(&h, &pool, "usr_rev_2", "org_rev_2").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/agt_does_not_exist/revoke", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint C — Audit Chain Routes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// G.1: Task chain query returns empty array when task has no executions.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_task_chain_empty(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_chain_1", "chain-1").await;
    seed_user(&pool, "usr_chain_1", "org_chain_1").await;

    let token = admin_token(&h, &pool, "usr_chain_1", "org_chain_1").await;
    let res = h
        .client
        .get(format!("{}/api/v1/audit/task/task_nonexistent", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());
}

/// G.2: Agent history query returns empty array for agent with no executions.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_agent_history_empty(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_hist_1", "hist-1").await;
    seed_user(&pool, "usr_hist_1", "org_hist_1").await;
    seed_agent(&pool, "org_hist_1", "agt_hist_001", "History Agent").await;

    let token = admin_token(&h, &pool, "usr_hist_1", "org_hist_1").await;
    let res = h
        .client
        .get(format!("{}/api/v1/audit/agent/agt_hist_001", h.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());
}

/// G.3: limit parameter is clamped between 1 and 100.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_task_chain_limit_clamping(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_chain_2", "chain-2").await;
    seed_user(&pool, "usr_chain_2", "org_chain_2").await;

    let token = admin_token(&h, &pool, "usr_chain_2", "org_chain_2").await;

    // limit=0 → should be clamped to 1 (valid request, not an error)
    let res0 = h
        .client
        .get(format!(
            "{}/api/v1/audit/task/task_x?limit=0",
            h.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res0.status(), StatusCode::OK);

    // limit=200 → should be clamped to 100 (valid request, not an error)
    let res200 = h
        .client
        .get(format!(
            "{}/api/v1/audit/task/task_x?limit=200",
            h.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res200.status(), StatusCode::OK);
}

/// G.4: Audit routes require authentication.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_audit_routes_require_auth(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;

    for path in [
        "/api/v1/audit/task/task_xyz",
        "/api/v1/audit/agent/agt_xyz",
    ] {
        let res = h
            .client
            .get(format!("{}{path}", h.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{path} should require auth"
        );
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Security — Tenant Isolation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// H.1: Tenant A cannot see Tenant B's agents via list.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_tenant_isolation_list_agents(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_ti_a", "ti-a").await;
    seed_org(&pool, "org_ti_b", "ti-b").await;
    seed_user(&pool, "usr_ti_a", "org_ti_a").await;
    seed_user(&pool, "usr_ti_b", "org_ti_b").await;
    seed_agent(&pool, "org_ti_a", "agt_ti_a_001", "TI Agent A").await;
    seed_agent(&pool, "org_ti_b", "agt_ti_b_001", "TI Agent B").await;

    // Tenant A token must only see Tenant A's agent
    let tok_a = admin_token(&h, &pool, "usr_ti_a", "org_ti_a").await;
    let res_a = h
        .client
        .get(format!("{}/api/v1/agents", h.base_url))
        .bearer_auth(&tok_a)
        .send()
        .await
        .unwrap();
    let body_a: Vec<Value> = res_a.json().await.unwrap();
    assert!(
        body_a.iter().all(|v| v["agent_id"] != "agt_ti_b_001"),
        "Tenant A must not see Tenant B's agents"
    );

    // Tenant B token must only see Tenant B's agent
    let tok_b = admin_token(&h, &pool, "usr_ti_b", "org_ti_b").await;
    let res_b = h
        .client
        .get(format!("{}/api/v1/agents", h.base_url))
        .bearer_auth(&tok_b)
        .send()
        .await
        .unwrap();
    let body_b: Vec<Value> = res_b.json().await.unwrap();
    assert!(
        body_b.iter().all(|v| v["agent_id"] != "agt_ti_a_001"),
        "Tenant B must not see Tenant A's agents"
    );
}

/// H.2: Tenant A cannot retrieve Tenant B's agent by ID.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_tenant_isolation_get_agent(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tg_a", "tg-a").await;
    seed_org(&pool, "org_tg_b", "tg-b").await;
    seed_user(&pool, "usr_tg_a", "org_tg_a").await;
    seed_agent(&pool, "org_tg_b", "agt_tg_b_001", "Cross-Tenant Target").await;

    // Tenant A token trying to get Tenant B's agent → 404 (RLS hides the row)
    let tok_a = admin_token(&h, &pool, "usr_tg_a", "org_tg_a").await;
    let res = h
        .client
        .get(format!("{}/api/v1/agents/agt_tg_b_001", h.base_url))
        .bearer_auth(&tok_a)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// H.3: Tenant A token cannot issue tokens for Tenant B's agent.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_tenant_isolation_token_issuance(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_tt_a", "tt-a").await;
    seed_org(&pool, "org_tt_b", "tt-b").await;
    seed_user(&pool, "usr_tt_a", "org_tt_a").await;
    seed_agent(&pool, "org_tt_b", "agt_tt_b_001", "Cross-Tenant Agent").await;

    let tok_a = admin_token(&h, &pool, "usr_tt_a", "org_tt_a").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&tok_a)
        .json(&json!({ "agent_id": "agt_tt_b_001", "task_id": "task_cross" }))
        .send()
        .await
        .unwrap();

    // RLS prevents Tenant A from loading Tenant B's agent → 404
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Security — JWT Forgery & Structural Invariants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// I.1: Malformed Bearer token returns 401 (no panic).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_malformed_bearer_token_rejected(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;

    for bad_token in ["not-a-jwt", "Bearer x.y.z", "ey.not.valid"] {
        let res = h
            .client
            .get(format!("{}/api/v1/agents", h.base_url))
            .header("Authorization", format!("Bearer {bad_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "bad token '{bad_token}' must be rejected"
        );
    }
}

/// I.2: Expired agent JWT is rejected by the middleware.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_expired_agent_token_rejected(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_exp_1", "exp-1").await;
    seed_agent(&pool, "org_exp_1", "agt_exp_001", "Expired Agent").await;

    let now = Utc::now();
    let claims = auth_core::jwt::Claims {
        sub: "agt_exp_001".to_string(),
        iss: h.state.config.jwt.issuer.clone(),
        aud: h.state.config.jwt.audience.clone(),
        exp: now.timestamp() - 3600, // already expired
        iat: now.timestamp() - 7200,
        nbf: now.timestamp() - 7200,
        sid: String::new(),
        tenant_id: "org_exp_1".to_string(),
        session_type: "agent".to_string(),
        agent_id: Some("agt_exp_001".to_string()),
        model_id: None,
        task_id: Some("task_exp".to_string()),
        delegation_chain: None,
        allowed_tools: None,
        principal_source: None,
    };
    let expired_tok = h.state.jwt_service.sign_claims(&claims).unwrap();

    let res = h
        .client
        .get(format!("{}/api/v1/agents", h.base_url))
        .bearer_auth(&expired_tok)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// I.3: Agent token claims sid must be empty — verify the issuance produces empty sid.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issued_agent_token_has_empty_sid(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_sid_1", "sid-1").await;
    seed_user(&pool, "usr_sid_1", "org_sid_1").await;
    seed_agent(&pool, "org_sid_1", "agt_sid_001", "SID Agent").await;

    let token = admin_token(&h, &pool, "usr_sid_1", "org_sid_1").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "agent_id": "agt_sid_001", "task_id": "task_sid" }))
        .send()
        .await
        .unwrap();

    let agent_jwt = res.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let decoded = h.state.jwt_service.verify_token(&agent_jwt).unwrap();
    assert_eq!(decoded.sid, "", "agent token must have empty sid (not session-bound)");
}

/// I.4: Agent token must carry session_type = "agent".
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_issued_agent_token_session_type(pool: PgPool) {
    let h = TestHarness::spawn(pool.clone()).await;
    seed_org(&pool, "org_stype_1", "stype-1").await;
    seed_user(&pool, "usr_stype_1", "org_stype_1").await;
    seed_agent(&pool, "org_stype_1", "agt_stype_001", "SType Agent").await;

    let token = admin_token(&h, &pool, "usr_stype_1", "org_stype_1").await;
    let res = h
        .client
        .post(format!("{}/api/v1/agents/token", h.base_url))
        .bearer_auth(&token)
        .json(&json!({ "agent_id": "agt_stype_001", "task_id": "task_stype" }))
        .send()
        .await
        .unwrap();

    let agent_jwt = res.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let decoded = h.state.jwt_service.verify_token(&agent_jwt).unwrap();
    assert_eq!(decoded.session_type, "agent");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Sprint D — Webhook Service: HMAC & Event Kind Serialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// J.1: AgentEventKind serializes to dot-separated format for webhook routing.
#[test]
fn test_agent_event_kind_serialization() {
    use api_server::services::AgentEventKind;

    let cases = vec![
        (AgentEventKind::AgentActionAuthorized, "agent.action.authorized"),
        (AgentEventKind::AgentActionDenied, "agent.action.denied"),
        (AgentEventKind::AgentTaskCompleted, "agent.task.completed"),
    ];

    for (kind, expected) in cases {
        let serialized = serde_json::to_value(&kind).unwrap();
        assert_eq!(
            serialized.as_str().unwrap(),
            expected,
            "event kind must serialize to '{expected}'"
        );
    }
}

/// J.2: AgentWebhookPayload round-trips through JSON without data loss.
#[test]
fn test_agent_webhook_payload_roundtrip() {
    use api_server::services::{AgentEventKind, AgentWebhookPayload};

    let original = AgentWebhookPayload {
        event: AgentEventKind::AgentActionAuthorized,
        timestamp: "2026-03-06T10:00:10Z".to_string(),
        tenant_id: "tenant_acme".to_string(),
        task_id: Some("task_xyz789".to_string()),
        agent_id: Some("agt_abc123".to_string()),
        model_id: Some("claude-3-5-sonnet-20241022".to_string()),
        tool_name: Some("web_search".to_string()),
        decision_ref: "dec_001".to_string(),
        risk_score: Some(12),
        attestation_signature_b64: Some("sig_abc".to_string()),
    };

    let json_str = serde_json::to_string(&original).unwrap();
    let restored: AgentWebhookPayload = serde_json::from_str(&json_str).unwrap();

    assert_eq!(restored.event, original.event);
    assert_eq!(restored.tenant_id, original.tenant_id);
    assert_eq!(restored.task_id, original.task_id);
    assert_eq!(restored.decision_ref, original.decision_ref);
    assert_eq!(restored.risk_score, Some(12));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Edge Cases — Agent Token Claims Backward Compatibility
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// K.1: Legacy JWT without agent fields deserializes correctly (serde default).
#[test]
fn test_legacy_jwt_claims_backward_compat() {
    // Simulate a JWT payload from before Sprint A — no agent fields at all.
    let legacy_json = serde_json::json!({
        "sub": "usr_legacy",
        "iss": "authstar",
        "aud": "authstar",
        "exp": 9999999999_i64,
        "iat": 1700000000_i64,
        "nbf": 1700000000_i64,
        "sid": "sess_legacy",
        "tenant_id": "org_legacy",
        "session_type": "admin"
    });

    let claims: auth_core::jwt::Claims = serde_json::from_value(legacy_json).unwrap();
    assert_eq!(claims.sub, "usr_legacy");
    assert_eq!(claims.session_type, "admin");
    assert!(claims.agent_id.is_none());
    assert!(claims.model_id.is_none());
    assert!(claims.task_id.is_none());
    assert!(claims.delegation_chain.is_none());
    assert!(claims.allowed_tools.is_none());
    assert!(claims.principal_source.is_none());
}

/// K.2: Agent JWT with all optional fields present deserializes correctly.
#[test]
fn test_agent_jwt_claims_full_deserialization() {
    let agent_json = serde_json::json!({
        "sub": "agt_abc123",
        "iss": "authstar",
        "aud": "authstar",
        "exp": 9999999999_i64,
        "iat": 1700000000_i64,
        "nbf": 1700000000_i64,
        "sid": "",
        "tenant_id": "acme",
        "session_type": "agent",
        "agent_id": "agt_abc123",
        "model_id": "claude-3-5-sonnet-20241022",
        "task_id": "task_xyz789",
        "delegation_chain": ["usr_human123"],
        "allowed_tools": ["web_search", "send_email"],
        "principal_source": "pre_registered"
    });

    let claims: auth_core::jwt::Claims = serde_json::from_value(agent_json).unwrap();
    assert_eq!(claims.session_type, "agent");
    assert_eq!(claims.agent_id.as_deref(), Some("agt_abc123"));
    assert_eq!(claims.model_id.as_deref(), Some("claude-3-5-sonnet-20241022"));
    assert_eq!(claims.task_id.as_deref(), Some("task_xyz789"));
    assert_eq!(
        claims.delegation_chain.as_ref().unwrap(),
        &vec!["usr_human123".to_string()]
    );
    assert_eq!(
        claims.allowed_tools.as_ref().unwrap(),
        &vec!["web_search".to_string(), "send_email".to_string()]
    );
    assert_eq!(claims.principal_source.as_deref(), Some("pre_registered"));
    assert_eq!(claims.sid, ""); // empty sid
}

/// K.3: Agent token skips serialization of None fields (clean JWT payload).
#[test]
fn test_agent_jwt_none_fields_skipped_in_serialization() {
    let claims = auth_core::jwt::Claims {
        sub: "usr_human".to_string(),
        iss: "authstar".to_string(),
        aud: "authstar".to_string(),
        exp: 9999999999,
        iat: 1700000000,
        nbf: 1700000000,
        sid: "sess_123".to_string(),
        tenant_id: "acme".to_string(),
        session_type: "admin".to_string(),
        agent_id: None,
        model_id: None,
        task_id: None,
        delegation_chain: None,
        allowed_tools: None,
        principal_source: None,
    };

    let json_val = serde_json::to_value(&claims).unwrap();
    assert!(
        json_val.get("agent_id").is_none(),
        "agent_id must be absent in human JWT"
    );
    assert!(
        json_val.get("model_id").is_none(),
        "model_id must be absent in human JWT"
    );
    assert!(
        json_val.get("task_id").is_none(),
        "task_id must be absent in human JWT"
    );
}
