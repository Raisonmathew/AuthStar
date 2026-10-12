//! Policy Builder Integration Tests
//!
//! Covers the full lifecycle: create config → add group → add rule → compile → activate.
//! FIX-2: Verifies that activate_config() now writes to eiaa_capsules.
//!
//! ## Running
//! ```bash
//! export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/authstar_test
//! cargo test --test policy_builder_integration_test -- --nocapture --include-ignored
//! ```

#![allow(dead_code)]
mod common;

use common::harness::TestHarness;
use common::seed::*;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

// ─── Lifecycle: create → group → rule → compile → activate ──────────────────

/// PB.1: Full lifecycle — create config, add group, add rule, compile, activate.
///       Verifies that activate writes a row to eiaa_capsules.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_policy_builder_full_lifecycle(pool: PgPool) -> anyhow::Result<()> {
    let h = TestHarness::spawn(pool.clone()).await;

    // Seed a tenant admin
    let org_id = "org_pb_lifecycle";
    let user_id = "usr_pb_lifecycle";
    seed_org(&pool, org_id, "pb-lifecycle").await;
    seed_user(&pool, user_id, org_id).await;
    seed_membership(&pool, "mem_pb_lifecycle", user_id, org_id, "owner").await;

    let sid = format!("sess_pb_lifecycle_{org_id}");
    seed_admin_session(&pool, &sid, user_id, org_id).await;
    let token = h
        .state
        .jwt_service
        .generate_token(user_id, &sid, org_id, "end_user")
        .expect("mint token");

    let base = &h.base_url;
    let client = &h.client;

    // 1. List actions — we need a valid action_key
    let actions_res = client
        .get(format!("{base}/api/v1/policy-builder/actions"))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(actions_res.status(), StatusCode::OK, "list actions");
    let actions: Value = actions_res.json().await?;
    let action_key = actions
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|a| a["action_key"].as_str())
        .unwrap_or("billing:read");

    // 2. Create config
    let create_res = client
        .post(format!("{base}/api/v1/policy-builder/configs"))
        .bearer_auth(&token)
        .json(&json!({
            "action_key":   action_key,
            "display_name": "PB Lifecycle Test",
            "description":  "Integration test — full lifecycle"
        }))
        .send()
        .await?;
    assert_eq!(create_res.status(), StatusCode::OK, "create config");
    let config: Value = create_res.json().await?;
    let config_id = config["id"].as_str().expect("config id");
    assert_eq!(config["state"].as_str(), Some("draft"));

    // 3. Add a rule group
    let group_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/groups"))
        .bearer_auth(&token)
        .json(&json!({
            "display_name":  "High-Risk Block",
            "match_mode":    "any",
            "on_match":      "deny",
            "on_no_match":   "continue",
            "stepup_methods": []
        }))
        .send()
        .await?;
    assert_eq!(group_res.status(), StatusCode::OK, "add group");
    let group: Value = group_res.json().await?;
    let group_id = group["id"].as_str().expect("group id");

    // 4. List templates and find block_high_risk
    let tmpl_res = client
        .get(format!("{base}/api/v1/policy-builder/templates"))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(tmpl_res.status(), StatusCode::OK, "list templates");
    let templates: Value = tmpl_res.json().await?;
    let template_slug = templates
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|t| t["slug"].as_str())
        .unwrap_or("block_high_risk");

    // 5. Add a rule to the group
    let rule_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/groups/{group_id}/rules"))
        .bearer_auth(&token)
        .json(&json!({
            "template_slug": template_slug,
            "display_name":  "Block high risk",
            "param_values":  { "block_threshold": 80, "stepup_threshold": 50 }
        }))
        .send()
        .await?;
    assert_eq!(rule_res.status(), StatusCode::OK, "add rule");

    // 6. Compile
    let compile_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/compile"))
        .bearer_auth(&token)
        .send()
        .await?;
    let compile_status = compile_res.status();
    let compile_body: Value = compile_res.json().await?;
    assert_eq!(compile_status, StatusCode::OK, "compile: {compile_body}");
    assert!(compile_body["version_id"].as_str().is_some(), "version_id present");
    assert!(compile_body["ast_hash_b64"].as_str().is_some(), "ast_hash_b64 present");

    // Config should now be in "compiled" state
    let cfg_res = client
        .get(format!("{base}/api/v1/policy-builder/configs/{config_id}"))
        .bearer_auth(&token)
        .send()
        .await?;
    let cfg: Value = cfg_res.json().await?;
    assert_eq!(cfg["state"].as_str(), Some("compiled"), "state after compile");

    // 7. Activate — this is the critical fix: must write to eiaa_capsules
    let activate_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/activate"))
        .bearer_auth(&token)
        .send()
        .await?;
    let activate_status = activate_res.status();
    let activate_body: Value = activate_res.json().await?;
    assert_eq!(activate_status, StatusCode::OK, "activate: {activate_body}");
    assert_eq!(activate_body["status"].as_str(), Some("activated"));

    let capsule_hash = activate_body["capsule_hash_b64"]
        .as_str()
        .expect("capsule_hash_b64 in activate response");

    // ── CRITICAL: verify capsule was written to eiaa_capsules ──────────────
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT tenant_id, action, capsule_hash_b64 FROM eiaa_capsules WHERE capsule_hash_b64 = $1",
    )
    .bind(capsule_hash)
    .fetch_optional(&pool)
    .await?;

    assert!(
        row.is_some(),
        "eiaa_capsules must contain the activated capsule (hash: {capsule_hash})"
    );
    let (db_tenant, db_action, _) = row.unwrap();
    assert_eq!(db_tenant, org_id, "capsule tenant_id must match");
    assert_eq!(db_action, action_key, "capsule action must match");

    // Config should now be in "active" state
    let cfg_after: Value = client
        .get(format!("{base}/api/v1/policy-builder/configs/{config_id}"))
        .bearer_auth(&token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(cfg_after["state"].as_str(), Some("active"), "state after activate");
    assert_eq!(
        cfg_after["active_capsule_hash_b64"].as_str(),
        Some(capsule_hash),
        "active_capsule_hash_b64 must match eiaa_capsules row"
    );

    Ok(())
}

// ─── Permission enforcement ──────────────────────────────────────────────────

/// PB.2: TenantDeveloper (non-owner/admin role) cannot compile or activate.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_policy_builder_developer_cannot_compile(pool: PgPool) -> anyhow::Result<()> {
    let h = TestHarness::spawn(pool.clone()).await;

    let org_id = "org_pb_devperm";
    let admin_id = "usr_pb_admin";
    let dev_id = "usr_pb_dev";
    seed_org(&pool, org_id, "pb-devperm").await;
    seed_user(&pool, admin_id, org_id).await;
    seed_user(&pool, dev_id, org_id).await;
    seed_membership(&pool, "mem_pb_admin", admin_id, org_id, "owner").await;
    seed_membership(&pool, "mem_pb_dev", dev_id, org_id, "member").await;

    let admin_sid = "sess_pb_admin_devperm";
    let dev_sid = "sess_pb_dev_devperm";
    seed_admin_session(&pool, admin_sid, admin_id, org_id).await;
    seed_admin_session(&pool, dev_sid, dev_id, org_id).await;

    let admin_token = h.state.jwt_service.generate_token(admin_id, admin_sid, org_id, "end_user").unwrap();
    let dev_token = h.state.jwt_service.generate_token(dev_id, dev_sid, org_id, "end_user").unwrap();

    let base = &h.base_url;
    let client = &h.client;

    // Admin creates a config
    let create_res = client
        .post(format!("{base}/api/v1/policy-builder/configs"))
        .bearer_auth(&admin_token)
        .json(&json!({ "action_key": "org:read", "display_name": "Dev Perm Test" }))
        .send()
        .await?;
    assert_eq!(create_res.status(), StatusCode::OK);
    let config: Value = create_res.json().await?;
    let config_id = config["id"].as_str().unwrap();

    // Developer should be able to GET the config
    let get_res = client
        .get(format!("{base}/api/v1/policy-builder/configs/{config_id}"))
        .bearer_auth(&dev_token)
        .send()
        .await?;
    assert_eq!(get_res.status(), StatusCode::OK, "developer can read");

    // Developer must NOT be able to compile
    let compile_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/compile"))
        .bearer_auth(&dev_token)
        .send()
        .await?;
    assert_eq!(
        compile_res.status(),
        StatusCode::FORBIDDEN,
        "developer must be denied compile"
    );

    // Developer must NOT be able to activate
    let activate_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/activate"))
        .bearer_auth(&dev_token)
        .send()
        .await?;
    assert_eq!(
        activate_res.status(),
        StatusCode::FORBIDDEN,
        "developer must be denied activate"
    );

    Ok(())
}

/// PB.3: Cross-tenant access must return 404 (not 403 — don't leak config existence).
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_policy_builder_cross_tenant_404(pool: PgPool) -> anyhow::Result<()> {
    let h = TestHarness::spawn(pool.clone()).await;

    let org_a = "org_pb_cross_a";
    let org_b = "org_pb_cross_b";
    let user_a = "usr_pb_cross_a";
    let user_b = "usr_pb_cross_b";
    seed_org(&pool, org_a, "pb-cross-a").await;
    seed_org(&pool, org_b, "pb-cross-b").await;
    seed_user(&pool, user_a, org_a).await;
    seed_user(&pool, user_b, org_b).await;
    seed_membership(&pool, "mem_pb_cross_a", user_a, org_a, "owner").await;
    seed_membership(&pool, "mem_pb_cross_b", user_b, org_b, "owner").await;

    let sid_a = "sess_pb_cross_a";
    let sid_b = "sess_pb_cross_b";
    seed_admin_session(&pool, sid_a, user_a, org_a).await;
    seed_admin_session(&pool, sid_b, user_b, org_b).await;

    let token_a = h.state.jwt_service.generate_token(user_a, sid_a, org_a, "end_user").unwrap();
    let token_b = h.state.jwt_service.generate_token(user_b, sid_b, org_b, "end_user").unwrap();

    let base = &h.base_url;
    let client = &h.client;

    // Org A creates a config
    let create_res = client
        .post(format!("{base}/api/v1/policy-builder/configs"))
        .bearer_auth(&token_a)
        .json(&json!({ "action_key": "audit:read", "display_name": "Cross-Tenant Test" }))
        .send()
        .await?;
    assert_eq!(create_res.status(), StatusCode::OK);
    let config: Value = create_res.json().await?;
    let config_id_a = config["id"].as_str().unwrap();

    // Org B must get 404 when accessing Org A's config
    let get_res = client
        .get(format!("{base}/api/v1/policy-builder/configs/{config_id_a}"))
        .bearer_auth(&token_b)
        .send()
        .await?;
    assert_eq!(
        get_res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant read must return 404"
    );

    // Org B must get 404 when trying to compile Org A's config
    let compile_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id_a}/compile"))
        .bearer_auth(&token_b)
        .send()
        .await?;
    assert_eq!(
        compile_res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant compile must return 404"
    );

    Ok(())
}

// ─── Simulate ────────────────────────────────────────────────────────────────

/// PB.4: Simulate endpoint returns correct decision and trace.
#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_policy_builder_simulate(pool: PgPool) -> anyhow::Result<()> {
    let h = TestHarness::spawn(pool.clone()).await;

    let org_id = "org_pb_simulate";
    let user_id = "usr_pb_simulate";
    seed_org(&pool, org_id, "pb-simulate").await;
    seed_user(&pool, user_id, org_id).await;
    seed_membership(&pool, "mem_pb_simulate", user_id, org_id, "owner").await;
    let sid = "sess_pb_simulate";
    seed_admin_session(&pool, sid, user_id, org_id).await;
    let token = h.state.jwt_service.generate_token(user_id, sid, org_id, "end_user").unwrap();

    let base = &h.base_url;
    let client = &h.client;

    // Create config → add deny-high-risk group → add block_high_risk rule
    let config: Value = client
        .post(format!("{base}/api/v1/policy-builder/configs"))
        .bearer_auth(&token)
        .json(&json!({ "action_key": "user:read", "display_name": "Simulate Test" }))
        .send()
        .await?
        .json()
        .await?;
    let config_id = config["id"].as_str().unwrap();

    let group: Value = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/groups"))
        .bearer_auth(&token)
        .json(&json!({
            "display_name": "Block High Risk",
            "match_mode": "any",
            "on_match": "deny",
            "on_no_match": "continue",
            "stepup_methods": []
        }))
        .send()
        .await?
        .json()
        .await?;
    let group_id = group["id"].as_str().unwrap();

    client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/groups/{group_id}/rules"))
        .bearer_auth(&token)
        .json(&json!({
            "template_slug": "block_high_risk",
            "display_name": "Block risk > 80",
            "param_values": { "block_threshold": 80, "stepup_threshold": 50 }
        }))
        .send()
        .await?;

    // Simulate with HIGH risk — should be deny
    let sim_res = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/simulate"))
        .bearer_auth(&token)
        .json(&json!({ "context": { "risk_score": 90.0 } }))
        .send()
        .await?;
    assert_eq!(sim_res.status(), StatusCode::OK);
    let sim: Value = sim_res.json().await?;
    assert_eq!(sim["decision"].as_str(), Some("deny"), "high risk should deny: {sim}");
    assert!(sim["groups_evaluated"].as_array().is_some());
    assert!(!sim["human_explanation"].as_array().unwrap().is_empty());

    // Simulate with LOW risk — should be allow (continue through all groups)
    let sim_low: Value = client
        .post(format!("{base}/api/v1/policy-builder/configs/{config_id}/simulate"))
        .bearer_auth(&token)
        .json(&json!({ "context": { "risk_score": 10.0 } }))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(sim_low["decision"].as_str(), Some("allow"), "low risk should allow");

    Ok(())
}
