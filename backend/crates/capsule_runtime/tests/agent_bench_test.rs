//! AI Agent Authentication and Authorization Latency & Stress Benchmark Test
//!
//! Measures:
//! 1. Agent JWT Minting & Cryptographic Verification Latency (Authentication)
//! 2. WASM Capsule Execution Latency + Ed25519 Attestation (Authorization)
//! 3. Full End-to-End Auth + Authz Flow Latency (Sequential)
//! 4. Concurrency Stress Test: 100,000 requests across 32 parallel worker threads
//!
//! Measures:
//! 1. Agent JWT Minting & Cryptographic Verification Latency (Authentication)
//! 2. WASM Capsule Execution Latency + Ed25519 Attestation (Authorization)
//! 3. Full End-to-End Auth + Authz Flow Latency
//! 4. High-Load Concurrency Stress Test (10,000 requests across 16 parallel worker threads)

use anyhow::Result;
use auth_core::{jwt::Claims, JwtService};
use capsule_compiler::{
    ast::{self, Comparator, Condition, Step},
    compile,
};
use capsule_runtime::{execute, ExecuteParams, RuntimeContext};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use keystore::{KeyId, Keystore};
use std::sync::Arc;
use std::time::Instant;

struct MockKeystore {
    signing_key: SigningKey,
}

impl MockKeystore {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[1u8; 32]),
        }
    }

    fn verifier(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Keystore for MockKeystore {
    fn sign(&self, _key_id: &KeyId, data: &[u8]) -> Result<ed25519_dalek::Signature> {
        Ok(self.signing_key.sign(data))
    }

    fn generate_ed25519(&self) -> Result<KeyId> {
        Ok(KeyId("mock-kid".to_string()))
    }
    fn import_ed25519(&self, _sk_bytes: &[u8]) -> Result<KeyId> {
        Ok(KeyId("mock-kid".to_string()))
    }
    fn public_key(&self, kid: &KeyId) -> Result<keystore::PublicKey> {
        Ok(keystore::PublicKey {
            kid: kid.clone(),
            key: self.verifier(),
        })
    }
    fn list_public_keys(&self) -> Vec<keystore::PublicKey> {
        vec![keystore::PublicKey {
            kid: KeyId("mock-kid".to_string()),
            key: self.verifier(),
        }]
    }
}

fn build_agent_policy(tool_name: &str, model_id: &str, max_depth: u8) -> ast::Program {
    let inner_allow_branch = vec![Step::Allow(true)];
    let inner_deny_branch = vec![Step::Deny(true)];

    let post_tool_check = vec![
        Step::AuthorizeToolCall {
            tool_name: tool_name.to_string(),
            resource_pattern: None,
            require_user_confirmation: false,
        },
        Step::Conditional {
            condition: Condition::AuthzResult {
                comparator: Comparator::Eq,
                value: Some(1),
            },
            then_branch: inner_allow_branch,
            else_branch: Some(inner_deny_branch),
        },
    ];

    let risk_gate = Step::Conditional {
        condition: Condition::RiskScore {
            comparator: Comparator::Gt,
            value: Some(80),
        },
        then_branch: vec![Step::Deny(true)],
        else_branch: Some(post_tool_check),
    };

    ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyAgentIdentity {
                model_id: model_id.to_string(),
                model_version: None,
            },
            Step::CheckDelegationChain {
                max_depth,
                require_human_origin: true,
            },
            Step::EvaluateRisk {
                profile: "agent_default".to_string(),
            },
            risk_gate,
        ],
    }
}

fn create_agent_runtime_context(tool: &str, model: &str) -> RuntimeContext {
    RuntimeContext {
        subject_id: 1,
        risk_score: 15,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 2,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
        credential_attempts: std::collections::HashMap::new(),
        required_actions: Vec::new(),
        sub_decisions: std::collections::HashMap::new(),
        principal_type: "ai_agent".to_string(),
        agent_id: Some("agt_audit_agent_01".to_string()),
        model_id: Some(model.to_string()),
        task_id: Some("task_chain_123".to_string()),
        delegation_chain: vec!["usr_human_root".to_string()],
        tool_name: Some(tool.to_string()),
        tool_args_hash: None,
        allowed_tools: vec![tool.to_string(), "web_search".to_string()],
        principal_source: "pre_registered".to_string(),
    }
}

#[test]
fn test_ai_auth_authz_stress_and_latency() -> Result<()> {
    println!("\n================================================================================");
    println!("          AUTHSTAR AI AGENT AUTHENTICATION & AUTHORIZATION SPEED & STRESS AUDIT  ");
    println!("================================================================================");

    let ks = MockKeystore::new();
    let kid = KeyId("agent-compiler-key".to_string());
    let model = "claude-3-5-sonnet-20241022";
    let tool = "execute_code";

    // 1. Measure Compilation Latency
    let compile_start = Instant::now();
    let program = build_agent_policy(tool, model, 3);
    let capsule = compile(
        program,
        "tenant_finance_prod".to_string(),
        format!("agent:{}", tool),
        1000,
        2000000000,
        &ks,
        &kid,
    )?;
    let compile_duration = compile_start.elapsed();
    println!("[1] Capsule Compilation (One-time/Cached): {:?}", compile_duration);

    let sign_sk = SigningKey::from_bytes(&[2u8; 32]);
    let sign_fn = Arc::new(move |d: &[u8]| Ok(sign_sk.sign(d)));

    // 2. Measure Authentication (Agent JWT Token Issuance & Verification)
    let private_key = include_str!("../../../.keys/private.pem");
    let public_key = include_str!("../../../.keys/public.pem");
    let jwt_service = JwtService::new_ec(
        private_key,
        public_key,
        "https://auth.authstar.io".to_string(),
        "https://api.authstar.io".to_string(),
        60,
    )?;

    let agent_claims = Claims {
        sub: "agt_audit_agent_01".to_string(),
        iss: "https://auth.authstar.io".to_string(),
        aud: "https://api.authstar.io".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        sid: String::new(),
        tenant_id: "tenant_finance_prod".to_string(),
        session_type: "agent".to_string(),
        agent_id: Some("agt_audit_agent_01".to_string()),
        model_id: Some(model.to_string()),
        model_version: None,
        task_id: Some("task_chain_123".to_string()),
        delegation_chain: Some(vec!["usr_human_root".to_string()]),
        allowed_tools: Some(vec![tool.to_string(), "web_search".to_string()]),
        principal_source: Some("pre_registered".to_string()),
    };

    // Benchmark JWT Minting (Signing)
    let runs = 1_000;
    let mut mint_latencies = Vec::with_capacity(runs);
    let mut tokens = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t_start = Instant::now();
        let tok = jwt_service.sign_claims(&agent_claims)?;
        mint_latencies.push(t_start.elapsed().as_micros());
        tokens.push(tok);
    }
    mint_latencies.sort_unstable();
    let mint_avg = mint_latencies.iter().sum::<u128>() as f64 / runs as f64;
    let mint_p50 = mint_latencies[runs * 50 / 100];
    let mint_p95 = mint_latencies[runs * 95 / 100];
    let mint_p99 = mint_latencies[runs * 99 / 100];

    // Benchmark JWT Verification (Decoding + Signature Verification)
    let sample_token = &tokens[0];
    let mut verify_latencies = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t_start = Instant::now();
        let verified = jwt_service.verify_token(sample_token)?;
        verify_latencies.push(t_start.elapsed().as_micros());
        assert_eq!(verified.agent_id.as_deref(), Some("agt_audit_agent_01"));
    }
    verify_latencies.sort_unstable();
    let verify_avg = verify_latencies.iter().sum::<u128>() as f64 / runs as f64;
    let verify_p50 = verify_latencies[runs * 50 / 100];
    let verify_p95 = verify_latencies[runs * 95 / 100];
    let verify_p99 = verify_latencies[runs * 99 / 100];

    println!("\n[2] Agent Authentication Latency (ES256 ECDSA P-256 Cryptography):");
    println!("    • Agent JWT Minting (Sign):   Avg: {:>5.1} µs | p50: {:>5} µs | p95: {:>5} µs | p99: {:>5} µs", mint_avg, mint_p50, mint_p95, mint_p99);
    println!("    • Agent JWT Verify (Auth):    Avg: {:>5.1} µs | p50: {:>5} µs | p95: {:>5} µs | p99: {:>5} µs", verify_avg, verify_p50, verify_p95, verify_p99);

    // 3. Warm up execution
    let ctx = create_agent_runtime_context(tool, model);
    let (warmup_out, warmup_att) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: ctx.clone(),
        runtime_kid: "runtime_k1",
        sign_fn: &*sign_fn,
        now_unix: 1700000000,
        expires_at_unix: 1700003600,
        nonce_b64: "nonce_abc123",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })?;
    assert_eq!(warmup_out.decision, 1);
    assert!(!warmup_att.signature_b64.is_empty());

    // 3. Measure Single Execution Latency Breakdown
    let runs = 1_000;
    let mut latencies_micros = Vec::with_capacity(runs);

    for i in 0..runs {
        let nonce = format!("nonce_{}", i);
        let start = Instant::now();
        let (out, att) = execute(ExecuteParams {
            capsule: &capsule,
            input_ctx: ctx.clone(),
            runtime_kid: "runtime_k1",
            sign_fn: &*sign_fn,
            now_unix: 1700000000,
            expires_at_unix: 1700003600,
            nonce_b64: &nonce,
            expected_ast_hash: None,
            expected_wasm_hash: None,
        })?;
        let elapsed = start.elapsed().as_micros();
        latencies_micros.push(elapsed);
        assert_eq!(out.decision, 1);
        assert!(!att.signature_b64.is_empty());
    }

    latencies_micros.sort_unstable();
    let p50 = latencies_micros[runs * 50 / 100];
    let p90 = latencies_micros[runs * 90 / 100];
    let p95 = latencies_micros[runs * 95 / 100];
    let p99 = latencies_micros[runs * 99 / 100];
    let avg = latencies_micros.iter().sum::<u128>() as f64 / runs as f64;
    let min = latencies_micros[0];
    let max = latencies_micros[runs - 1];

    println!("\n[3] EIAA WASM Capsule Execution + Ed25519 Attestation (Sequential 1,000 runs):");
    println!("    • Min Latency:    {:>6} µs ({:.3} ms)", min, min as f64 / 1000.0);
    println!("    • Avg Latency:    {:>6.1} µs ({:.3} ms)", avg, avg / 1000.0);
    println!("    • p50 (Median):   {:>6} µs ({:.3} ms)", p50, p50 as f64 / 1000.0);
    println!("    • p90 Latency:    {:>6} µs ({:.3} ms)", p90, p90 as f64 / 1000.0);
    println!("    • p95 Latency:    {:>6} µs ({:.3} ms)", p95, p95 as f64 / 1000.0);
    println!("    • p99 Latency:    {:>6} µs ({:.3} ms)", p99, p99 as f64 / 1000.0);
    println!("    • Max Latency:    {:>6} µs ({:.3} ms)", max, max as f64 / 1000.0);

    // 4. End-to-End Auth + Authz Flow (JWT Auth + Context Extract + WASM Capsule + Attestation)
    let mut e2e_latencies = Vec::with_capacity(runs);
    for i in 0..runs {
        let t_start = Instant::now();
        // Step 1: Authenticate Agent (Verify JWT signature & claims)
        let claims = jwt_service.verify_token(sample_token)?;
        // Step 2: Extract Claims into Context
        let e2e_ctx = RuntimeContext {
            subject_id: 1,
            risk_score: 15,
            factors_satisfied: vec![],
            verifications_satisfied: vec![],
            auth_evidence: None,
            authz_decision: 1,
            assurance_level: 2,
            verified_capabilities: vec![],
            context_values: std::collections::HashMap::new(),
            password_breach_count: 0,
            credential_attempts: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            sub_decisions: std::collections::HashMap::new(),
            principal_type: claims.session_type.clone(),
            agent_id: claims.agent_id.clone(),
            model_id: claims.model_id.clone(),
            task_id: claims.task_id.clone(),
            delegation_chain: claims.delegation_chain.clone().unwrap_or_default(),
            tool_name: Some(tool.to_string()),
            tool_args_hash: None,
            allowed_tools: claims.allowed_tools.clone().unwrap_or_default(),
            principal_source: claims.principal_source.clone().unwrap_or_default(),
        };
        // Step 3: Authorize via WASM Capsule + Cryptographic Attestation
        let nonce = format!("nonce_e2e_{}", i);
        let (out, _) = execute(ExecuteParams {
            capsule: &capsule,
            input_ctx: e2e_ctx,
            runtime_kid: "runtime_k1",
            sign_fn: &*sign_fn,
            now_unix: 1700000000,
            expires_at_unix: 1700003600,
            nonce_b64: &nonce,
            expected_ast_hash: None,
            expected_wasm_hash: None,
        })?;
        assert_eq!(out.decision, 1);
        e2e_latencies.push(t_start.elapsed().as_micros());
    }
    e2e_latencies.sort_unstable();
    let e2e_avg = e2e_latencies.iter().sum::<u128>() as f64 / runs as f64;
    let e2e_p50 = e2e_latencies[runs * 50 / 100];
    let e2e_p90 = e2e_latencies[runs * 90 / 100];
    let e2e_p95 = e2e_latencies[runs * 95 / 100];
    let e2e_p99 = e2e_latencies[runs * 99 / 100];

    println!("\n[4] Complete End-to-End Flow (JWT Verification + Context + WASM Eval + Ed25519 Attestation):");
    println!("    • Avg Latency:    {:>6.1} µs ({:.3} ms)", e2e_avg, e2e_avg / 1000.0);
    println!("    • p50 (Median):   {:>6} µs ({:.3} ms)", e2e_p50, e2e_p50 as f64 / 1000.0);
    println!("    • p90 Latency:    {:>6} µs ({:.3} ms)", e2e_p90, e2e_p90 as f64 / 1000.0);
    println!("    • p95 Latency:    {:>6} µs ({:.3} ms)", e2e_p95, e2e_p95 as f64 / 1000.0);
    println!("    • p99 Latency:    {:>6} µs ({:.3} ms)", e2e_p99, e2e_p99 as f64 / 1000.0);

    // 5. Concurrency & High Load Stress Test (50,000 full decisions across 16 threads)
    let total_stress_requests = 50_000;
    let concurrency = 16;
    let requests_per_thread = total_stress_requests / concurrency;

    let capsule_arc = Arc::new(capsule);
    let jwt_service_arc = Arc::new(jwt_service);
    let sample_tok = sample_token.clone();
    let stress_start = Instant::now();

    let mut handles = Vec::new();
    for thread_id in 0..concurrency {
        let cap = Arc::clone(&capsule_arc);
        let s_fn = Arc::clone(&sign_fn);
        let jwt_s = Arc::clone(&jwt_service_arc);
        let tok = sample_tok.clone();
        let tool_name = tool.to_string();
        handles.push(std::thread::spawn(move || {
            let mut thread_latencies = Vec::with_capacity(requests_per_thread);
            for req_i in 0..requests_per_thread {
                let nonce = format!("t{}_req{}", thread_id, req_i);
                let t_start = Instant::now();
                let claims = jwt_s.verify_token(&tok).expect("jwt verify in stress");
                let thread_ctx = RuntimeContext {
                    subject_id: 1,
                    risk_score: 15,
                    factors_satisfied: vec![],
                    verifications_satisfied: vec![],
                    auth_evidence: None,
                    authz_decision: 1,
                    assurance_level: 2,
                    verified_capabilities: vec![],
                    context_values: std::collections::HashMap::new(),
                    password_breach_count: 0,
                    credential_attempts: std::collections::HashMap::new(),
                    required_actions: Vec::new(),
                    sub_decisions: std::collections::HashMap::new(),
                    principal_type: claims.session_type.clone(),
                    agent_id: claims.agent_id.clone(),
                    model_id: claims.model_id.clone(),
                    task_id: claims.task_id.clone(),
                    delegation_chain: claims.delegation_chain.clone().unwrap_or_default(),
                    tool_name: Some(tool_name.clone()),
                    tool_args_hash: None,
                    allowed_tools: claims.allowed_tools.clone().unwrap_or_default(),
                    principal_source: claims.principal_source.clone().unwrap_or_default(),
                };
                let (res, _) = execute(ExecuteParams {
                    capsule: &cap,
                    input_ctx: thread_ctx,
                    runtime_kid: "runtime_k1",
                    sign_fn: &*s_fn,
                    now_unix: 1700000000,
                    expires_at_unix: 1700003600,
                    nonce_b64: &nonce,
                    expected_ast_hash: None,
                    expected_wasm_hash: None,
                })
                .expect("Execution in stress thread");
                let el = t_start.elapsed().as_micros();
                thread_latencies.push(el);
                assert_eq!(res.decision, 1);
            }
            thread_latencies
        }));
    }

    let mut all_stress_latencies = Vec::with_capacity(total_stress_requests);
    for h in handles {
        let lats = h.join().expect("thread join");
        all_stress_latencies.extend(lats);
    }

    let stress_total_duration = stress_start.elapsed();
    all_stress_latencies.sort_unstable();
    let s_p50 = all_stress_latencies[all_stress_latencies.len() * 50 / 100];
    let s_p90 = all_stress_latencies[all_stress_latencies.len() * 90 / 100];
    let s_p95 = all_stress_latencies[all_stress_latencies.len() * 95 / 100];
    let s_p99 = all_stress_latencies[all_stress_latencies.len() * 99 / 100];
    let s_avg = all_stress_latencies.iter().sum::<u128>() as f64 / all_stress_latencies.len() as f64;
    let s_min = all_stress_latencies[0];
    let s_max = all_stress_latencies[all_stress_latencies.len() - 1];
    let rps = total_stress_requests as f64 / stress_total_duration.as_secs_f64();

    println!("\n[5] Concurrency Stress Test Results (50,000 full Auth+Authz requests, 16 parallel threads):");
    println!("    • Total Time:     {:.2} ms ({:?})", stress_total_duration.as_secs_f64() * 1000.0, stress_total_duration);
    println!("    • Throughput:     {:>6.0} authorizations/second", rps);
    println!("    • Min Latency:    {:>6} µs ({:.3} ms)", s_min, s_min as f64 / 1000.0);
    println!("    • Avg Latency:    {:>6.1} µs ({:.3} ms)", s_avg, s_avg / 1000.0);
    println!("    • p50 (Median):   {:>6} µs ({:.3} ms)", s_p50, s_p50 as f64 / 1000.0);
    println!("    • p90 Latency:    {:>6} µs ({:.3} ms)", s_p90, s_p90 as f64 / 1000.0);
    println!("    • p95 Latency:    {:>6} µs ({:.3} ms)", s_p95, s_p95 as f64 / 1000.0);
    println!("    • p99 Latency:    {:>6} µs ({:.3} ms)", s_p99, s_p99 as f64 / 1000.0);
    println!("    • Max Latency:    {:>6} µs ({:.3} ms)", s_max, s_max as f64 / 1000.0);
    println!("================================================================================\n");

    Ok(())
}
