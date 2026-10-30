//! Edge-case and regression tests for the capsule runtime.
//!
//! Covers the raw capsule protocol surface (integrity, time validity, epoch
//! interruption, attestation, host-import correctness, boundary conditions)
//! without going through the full policy compiler.  The golden_vectors tests
//! cover compiled-policy correctness; these tests focus on the *runtime layer*.
//!
//! # Structure
//! - `integrity_*`     — WASM/AST hash checks and tamper detection
//! - `time_*`          — not_before / not_after boundary behaviour
//! - `epoch_*`         — epoch interruption (Fix 4 regression guard)
//! - `factor_*`        — every FactorType variant
//! - `verification_*`  — RequireVerification + RequireUserAction
//! - `context_*`       — Condition::Context key/value dispatch
//! - `identity_*`      — IdentitySource variants + IdentityLevel comparators
//! - `attestation_*`   — AttestationBody fields (nonce, hashes, kid)
//! - `memory_*`        — memory layout and missing-export handling
//! - `breach_*`        — password_breach_count host import
//! - `collect_*`       — CollectCredentials NeedInput path

#![allow(dead_code)]

use anyhow::Result;
use capsule_compiler::{
    ast::{self, Comparator, Condition, ContextValue, FactorType, IdentityLevel, IdentitySource, Step},
    compile, CapsuleMeta, CapsuleSigned,
};
use capsule_runtime::{encode_runtime_pk, execute, ExecuteParams, RuntimeContext};
use ed25519_dalek::{Signer, SigningKey};
use keystore::{KeyId, Keystore};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

// ─── Epoch env-var guard (same pattern as runtime_fixes_test) ─────────────────

static EPOCH_ENV_LOCK: Mutex<()> = Mutex::new(());

struct EpochDeadlineGuard(std::sync::MutexGuard<'static, ()>);
impl EpochDeadlineGuard {
    fn set(ticks: u64) -> Self {
        let g = EPOCH_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("WASM_EPOCH_DEADLINE", ticks.to_string());
        EpochDeadlineGuard(g)
    }
}
impl Drop for EpochDeadlineGuard {
    fn drop(&mut self) {
        std::env::remove_var("WASM_EPOCH_DEADLINE");
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn create_test_capsule(
    wasm_bytes: Vec<u8>,
    not_before: i64,
    not_after: i64,
    signer: &SigningKey,
) -> CapsuleSigned {
    let mut hasher = Sha256::new();
    hasher.update(&wasm_bytes);
    let wasm_hash = hex::encode(hasher.finalize());
    let ast_hash = "mock_ast_hash".to_string();
    let meta = CapsuleMeta {
        tenant_id: "test_tenant".to_string(),
        action: "test_action".to_string(),
        not_before_unix: not_before,
        not_after_unix: not_after,
        ast_hash_b64: URL_SAFE_NO_PAD.encode(ast_hash.as_bytes()),
    };
    let to_sign = bincode::serialize(&(&meta, &ast_hash, &wasm_hash, &wasm_bytes)).unwrap();
    let sig = signer.sign(&to_sign);
    CapsuleSigned {
        meta,
        ast_bytes: vec![],
        ast_hash,
        lowering_version: "1.0".to_string(),
        wasm_bytes,
        wasm_hash,
        compiler_kid: "test_key_id".to_string(),
        compiler_sig_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    }
}

/// Minimal allow WASM: writes Decision=1, SubjectID=1, Risk=0, Authz=1
fn allow_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "run")
                (i32.store (i32.const 8192) (i32.const 1))
                (i64.store (i32.const 8200) (i64.const 1))
                (i32.store (i32.const 8208) (i32.const 0))
                (i32.store (i32.const 8212) (i32.const 1))
            )
        )"#,
    )
    .unwrap()
}

fn dummy_ctx() -> RuntimeContext {
    RuntimeContext {
        subject_id: 1,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: Default::default(),
        password_breach_count: 0,
        credential_attempts: Default::default(),
        required_actions: vec![],
        sub_decisions: Default::default(),
        principal_source: String::new(),
    }
}

type RuntimeSigner = (String, Box<dyn Fn(&[u8]) -> Result<ed25519_dalek::Signature>>);

fn runtime_signer() -> RuntimeSigner {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key();
    let kid = encode_runtime_pk(&pk);
    let sign_fn = Box::new(move |msg: &[u8]| Ok(sk.sign(msg)));
    (kid, sign_fn)
}

// MockKeystore for policy-compiler tests
struct MockKs(SigningKey);
impl MockKs {
    fn new_from(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }
}
impl Keystore for MockKs {
    fn sign(&self, _: &KeyId, data: &[u8]) -> Result<ed25519_dalek::Signature> {
        Ok(self.0.sign(data))
    }
    fn generate_ed25519(&self) -> Result<KeyId> {
        Ok(KeyId("k".into()))
    }
    fn import_ed25519(&self, _: &[u8]) -> Result<KeyId> {
        Ok(KeyId("k".into()))
    }
    fn public_key(&self, kid: &KeyId) -> Result<keystore::PublicKey> {
        Ok(keystore::PublicKey { kid: kid.clone(), key: self.0.verifying_key() })
    }
    fn list_public_keys(&self) -> Vec<keystore::PublicKey> { vec![] }
}

fn compile_policy(steps: Vec<Step>, ks: &MockKs) -> CapsuleSigned {
    let prog = ast::Program { version: "EIAA-AST-1.0".into(), sequence: steps };
    compile(prog, "t".into(), "a".into(), 0, i64::MAX, ks, &KeyId("k".into())).unwrap()
}

fn run_policy(cap: &CapsuleSigned, ctx: RuntimeContext, nonce: &str, ks: &MockKs)
    -> Result<capsule_runtime::DecisionOutput>
{
    let (out, _) = execute(ExecuteParams {
        capsule: cap,
        input_ctx: ctx,
        runtime_kid: "k",
        sign_fn: &|d| Ok(ks.0.sign(d)),
        now_unix: 1_000_000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: nonce,
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })?;
    Ok(out)
}

// ─── Integrity tests ──────────────────────────────────────────────────────────

#[test]
fn test_integrity_hash_mismatch() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    let mut capsule = create_test_capsule(wasm.clone(), 0, 9_999_999_999, &sk);
    capsule.wasm_bytes.push(0x00); // tamper
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_tamper",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("WASM hash mismatch"));
}

/// Single-byte mutation must be caught when the capsule is NOT already in cache.
/// The global module cache is keyed by wasm_hash; we use a unique WAT constant
/// so the original bytes were never executed before, ensuring the hash check runs.
#[test]
fn integrity_tamper_last_byte_caught() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    // Unique i64 constant: 0xCAFEBABE — very unlikely to already be in cache.
    let unique_wasm = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "run")
                (i32.store (i32.const 8192) (i32.const 1))
                (i64.store (i32.const 8200) (i64.const 3405691582))
            )
        )"#,
    ).unwrap();
    // Build capsule first (hash computed on original bytes), then tamper last byte.
    let mut capsule = create_test_capsule(unique_wasm, 0, 9_999_999_999, &sk);
    let last = capsule.wasm_bytes.len() - 1;
    capsule.wasm_bytes[last] ^= 0xFF; // wasm_hash still matches original → mismatch
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_flip",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_err(), "tampered WASM must be rejected");
    assert!(res.unwrap_err().to_string().contains("WASM hash mismatch"));
}

/// Caller-supplied expected_wasm_hash that doesn't match the capsule is rejected.
#[test]
fn integrity_caller_wasm_hash_mismatch_rejected() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_wh",
        expected_ast_hash: None,
        expected_wasm_hash: Some("0000000000000000000000000000000000000000000000000000000000000000"),
    });
    assert!(res.is_err(), "wrong expected_wasm_hash must be rejected");
}

/// Caller-supplied expected_ast_hash that doesn't match the capsule is rejected.
#[test]
fn integrity_caller_ast_hash_mismatch_rejected() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_ah",
        expected_ast_hash: Some("ffffffffffffffffffffffffffffffff"),
        expected_wasm_hash: None,
    });
    assert!(res.is_err(), "wrong expected_ast_hash must be rejected");
}

// ─── Time validity tests ──────────────────────────────────────────────────────

#[test]
fn test_time_validity_future() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 2000, 3000, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1999, // one second before not_before
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_future",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not valid at this time"));
}

#[test]
fn test_time_validity_expired() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 2000, 3000, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 3001, // one second after not_after
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_expired",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not valid at this time"));
}

/// Exactly at not_before must succeed.
#[test]
fn time_exactly_at_not_before_is_valid() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 5000, 9000, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 5000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_exact_nb",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_ok(), "exactly at not_before must be valid: {res:?}");
}

/// Exactly at not_after must succeed.
#[test]
fn time_exactly_at_not_after_is_valid() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 0, 9000, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 9000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_exact_na",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_ok(), "exactly at not_after must be valid: {res:?}");
}

// ─── Epoch interruption tests ─────────────────────────────────────────────────

#[test]
fn test_epoch_interruption_kills_infinite_loop() {
    let _guard = EpochDeadlineGuard::set(2);
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = wat::parse_str(r#"(module (func (export "run") (loop (br 0))))"#).unwrap();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_epoch",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    drop(_guard);
    assert!(res.is_err(), "infinite loop must be interrupted");
    let chain = format!("{:#}", res.unwrap_err());
    assert!(
        chain.contains("interrupt") || chain.contains("trap") || chain.contains("wasm"),
        "unexpected error: {chain}"
    );
}

/// Recovery: a valid capsule succeeds after an interrupted one.
#[test]
fn epoch_recovery_after_interrupt() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let loop_wasm = wat::parse_str(r#"(module (func (export "run") (loop (br 0))))"#).unwrap();
    let allow = allow_wasm();
    let loop_cap = create_test_capsule(loop_wasm, 0, 9_999_999_999, &sk);
    let ok_cap = create_test_capsule(allow, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();

    {
        let _guard = EpochDeadlineGuard::set(2);
        let _ = execute(ExecuteParams {
            capsule: &loop_cap,
            input_ctx: dummy_ctx(),
            runtime_kid: &kid,
            sign_fn: &sign_fn,
            now_unix: 1000,
            expires_at_unix: 9_999_999_999,
            nonce_b64: "n_recover_loop",
            expected_ast_hash: None,
            expected_wasm_hash: None,
        });
    }

    // Must succeed after the interrupt with default deadline
    let _sk2 = SigningKey::generate(&mut rand::rngs::OsRng);
    let (kid2, sign_fn2) = runtime_signer();
    let res = execute(ExecuteParams {
        capsule: &ok_cap,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid2,
        sign_fn: &sign_fn2,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_recover_ok",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    });
    assert!(res.is_ok(), "runtime must recover after interrupt: {res:?}");
}

// ─── Successful execution and output fields ───────────────────────────────────

#[test]
fn test_successful_execution() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "run")
                (i32.store (i32.const 8192) (i32.const 1))
                (i64.store (i32.const 8200) (i64.const 123))
                (i32.store (i32.const 8208) (i32.const 50))
                (i32.store (i32.const 8212) (i32.const 1))
            )
        )"#,
    )
    .unwrap();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let (output, _att) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n_ok",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })
    .expect("Execution failed");
    assert_eq!(output.decision, 1);
    assert_eq!(output.subject_id, 123);
    assert_eq!(output.risk_score, 50);
    assert_eq!(output.authz_result, 1);
}

// ─── Attestation field correctness ───────────────────────────────────────────

/// The attestation body must echo the nonce, runtime_kid, wasm_hash and ast_hash.
#[test]
fn attestation_body_fields_are_correct() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let nonce = "attestation_nonce_test";
    let (_, att) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: nonce,
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })
    .unwrap();
    assert_eq!(att.body.nonce_b64, nonce, "attestation must echo nonce");
    assert_eq!(att.body.runtime_kid, kid, "attestation must carry runtime kid");
    assert_eq!(att.body.wasm_hash_b64, capsule.wasm_hash, "attestation must carry wasm hash");
    assert_eq!(att.body.ast_hash_b64, capsule.ast_hash, "attestation must carry ast hash");
    assert!(!att.signature_b64.is_empty(), "attestation must be signed");
}

/// Two executions with different nonces produce different attestation bodies.
#[test]
fn attestation_nonces_differ_per_execution() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = allow_wasm();
    let capsule = create_test_capsule(wasm, 0, 9_999_999_999, &sk);
    let (kid, sign_fn) = runtime_signer();
    let (_, att1) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n1",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })
    .unwrap();
    let (_, att2) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: dummy_ctx(),
        runtime_kid: &kid,
        sign_fn: &sign_fn,
        now_unix: 1000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "n2",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })
    .unwrap();
    assert_ne!(att1.body.nonce_b64, att2.body.nonce_b64);
}

// ─── Factor-type tests (policy-compiler path) ────────────────────────────────

fn factor_test_steps(factor: FactorType) -> Vec<Step> {
    vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireFactor { factor_type: factor },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ]
}

/// OTP satisfied → Allow; unsatisfied → Deny.
#[test]
fn factor_otp_satisfied_allows() {
    let ks = MockKs::new_from(0xF0);
    let cap = compile_policy(factor_test_steps(FactorType::Otp), &ks);
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![0]; // OTP = 0
    assert_eq!(run_policy(&cap, ctx, "n_otp_ok", &ks).unwrap().decision, 1);
}

#[test]
fn factor_otp_unsatisfied_denies() {
    let ks = MockKs::new_from(0xF1);
    let cap = compile_policy(factor_test_steps(FactorType::Otp), &ks);
    assert_eq!(run_policy(&cap, dummy_ctx(), "n_otp_no", &ks).unwrap().decision, 0);
}

/// Passkey satisfied → Allow.
#[test]
fn factor_passkey_satisfied_allows() {
    let ks = MockKs::new_from(0xF2);
    let cap = compile_policy(factor_test_steps(FactorType::Passkey), &ks);
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![1]; // Passkey = 1
    assert_eq!(run_policy(&cap, ctx, "n_pk_ok", &ks).unwrap().decision, 1);
}

/// Password factor satisfied.
#[test]
fn factor_password_satisfied_allows() {
    let ks = MockKs::new_from(0xF3);
    let cap = compile_policy(factor_test_steps(FactorType::Password), &ks);
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![4]; // Password = 4
    assert_eq!(run_policy(&cap, ctx, "n_pw_ok", &ks).unwrap().decision, 1);
}

/// HardwareKey factor satisfied.
#[test]
fn factor_hardware_key_satisfied_allows() {
    let ks = MockKs::new_from(0xF4);
    let cap = compile_policy(factor_test_steps(FactorType::HardwareKey), &ks);
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![3]; // HardwareKey = 3
    assert_eq!(run_policy(&cap, ctx, "n_hk_ok", &ks).unwrap().decision, 1);
}

/// Any([Otp, Passkey]) — OTP alone satisfies.
#[test]
fn factor_any_satisfied_by_first_member() {
    let ks = MockKs::new_from(0xF5);
    let cap = compile_policy(
        factor_test_steps(FactorType::Any(vec![FactorType::Otp, FactorType::Passkey])),
        &ks,
    );
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![0]; // only OTP
    assert_eq!(run_policy(&cap, ctx, "n_any_otp", &ks).unwrap().decision, 1);
}

/// Any([Otp, Passkey]) — Passkey alone satisfies.
#[test]
fn factor_any_satisfied_by_second_member() {
    let ks = MockKs::new_from(0xF6);
    let cap = compile_policy(
        factor_test_steps(FactorType::Any(vec![FactorType::Otp, FactorType::Passkey])),
        &ks,
    );
    let mut ctx = dummy_ctx();
    ctx.factors_satisfied = vec![1]; // only Passkey
    assert_eq!(run_policy(&cap, ctx, "n_any_pk", &ks).unwrap().decision, 1);
}

/// Any([Otp, Passkey]) — neither satisfied → Deny.
#[test]
fn factor_any_denies_when_none_satisfied() {
    let ks = MockKs::new_from(0xF7);
    let cap = compile_policy(
        factor_test_steps(FactorType::Any(vec![FactorType::Otp, FactorType::Passkey])),
        &ks,
    );
    assert_eq!(run_policy(&cap, dummy_ctx(), "n_any_none", &ks).unwrap().decision, 0);
}

// ─── RequireVerification ──────────────────────────────────────────────────────

#[test]
fn verification_satisfied_allows() {
    let ks = MockKs::new_from(0xE0);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireVerification { verification_type: "email".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.verifications_satisfied = vec!["email".into()];
    assert_eq!(run_policy(&cap, ctx, "n_verif_ok", &ks).unwrap().decision, 1);
}

#[test]
fn verification_unsatisfied_denies() {
    let ks = MockKs::new_from(0xE1);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireVerification { verification_type: "email".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    assert_eq!(run_policy(&cap, dummy_ctx(), "n_verif_no", &ks).unwrap().decision, 0);
}

/// Wrong verification type does not satisfy the requirement.
#[test]
fn verification_wrong_type_denies() {
    let ks = MockKs::new_from(0xE2);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireVerification { verification_type: "phone".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.verifications_satisfied = vec!["email".into()]; // wrong type
    assert_eq!(run_policy(&cap, ctx, "n_verif_wrong", &ks).unwrap().decision, 0);
}

// ─── RequireUserAction ────────────────────────────────────────────────────────

/// No pending actions → Allow.
#[test]
fn user_action_cleared_allows() {
    let ks = MockKs::new_from(0xD0);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireUserAction { code: "verify_email".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    // required_actions is empty → action is not pending → Allow
    assert_eq!(run_policy(&cap, dummy_ctx(), "n_ua_ok", &ks).unwrap().decision, 1);
}

/// Pending action blocks → Deny.
#[test]
fn user_action_pending_denies() {
    let ks = MockKs::new_from(0xD1);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireUserAction { code: "verify_email".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.required_actions = vec!["verify_email".into()];
    assert_eq!(run_policy(&cap, ctx, "n_ua_no", &ks).unwrap().decision, 0);
}

/// Different pending action code doesn't block.
#[test]
fn user_action_different_code_does_not_block() {
    let ks = MockKs::new_from(0xD2);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::RequireUserAction { code: "configure_mfa".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.required_actions = vec!["verify_email".into()]; // different code
    assert_eq!(run_policy(&cap, ctx, "n_ua_diff", &ks).unwrap().decision, 1);
}

// ─── CollectCredentials NeedInput path ───────────────────────────────────────

/// CollectCredentials always emits Decision=2 (NeedInput).
#[test]
fn collect_credentials_emits_need_input() {
    let ks = MockKs::new_from(0xC0);
    // CollectCredentials is exempt from R17 (no AuthorizeAction required) — check
    // if it compiles standalone or needs one. Use AuthorizeAction after just in case.
    let prog = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::CollectCredentials,
            Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
            Step::Allow(true),
        ],
    };
    let cap = compile(prog, "t".into(), "a".into(), 0, i64::MAX, &ks, &KeyId("k".into())).unwrap();
    // CollectCredentials sets halted=1 → subsequent steps don't run, decision=2
    let out = run_policy(&cap, dummy_ctx(), "n_cc", &ks).unwrap();
    assert_eq!(out.decision, 2, "CollectCredentials must emit NeedInput(2)");
}

// ─── IdentityLevel comparators ────────────────────────────────────────────────

/// IdentityLevel::Low = 1, Medium = 2, High = 3 (as mapped by the lowerer).
/// Test all three comparators (<, ==, >=) at exact boundary values.
#[test]
fn identity_level_lt_medium_denies_aal1() {
    let ks = MockKs::new_from(0xB0);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::IdentityLevel { comparator: Comparator::Lt, level: IdentityLevel::Medium },
            then_branch: vec![Step::Deny(true)],
            else_branch: Some(vec![Step::Allow(true)]),
        },
    ], &ks);
    let mut ctx1 = dummy_ctx();
    ctx1.assurance_level = 1; // Low (1) < Medium (2) → Deny
    assert_eq!(run_policy(&cap, ctx1, "n_aal_low", &ks).unwrap().decision, 0);

    let mut ctx2 = dummy_ctx();
    ctx2.assurance_level = 2; // Medium (2) < Medium (2) → false → Allow
    assert_eq!(run_policy(&cap, ctx2, "n_aal_med", &ks).unwrap().decision, 1);
}

#[test]
fn identity_level_gte_high_enforced() {
    let ks = MockKs::new_from(0xB1);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::IdentityLevel { comparator: Comparator::Gte, level: IdentityLevel::High },
            then_branch: vec![Step::Allow(true)],
            else_branch: Some(vec![Step::Deny(true)]),
        },
    ], &ks);
    // assurance_level=2 (Medium) → 2 >= 3 (High) → false → Deny
    let mut ctx_med = dummy_ctx();
    ctx_med.assurance_level = 2;
    assert_eq!(run_policy(&cap, ctx_med, "n_aal_gte_med", &ks).unwrap().decision, 0);

    // assurance_level=3 (High) → 3 >= 3 → true → Allow
    let mut ctx_high = dummy_ctx();
    ctx_high.assurance_level = 3;
    assert_eq!(run_policy(&cap, ctx_high, "n_aal_gte_high", &ks).unwrap().decision, 1);
}

// ─── Condition::Context (context_values map) ─────────────────────────────────

/// context_values integer lookup: key present and value matches comparator.
#[test]
fn condition_context_integer_match_allows() {
    let ks = MockKs::new_from(0xA0);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::Context {
                key: "session_age_s".into(),
                comparator: Comparator::Lt,
                value: ContextValue::Integer(3600),
            },
            then_branch: vec![Step::Allow(true)],
            else_branch: Some(vec![Step::Deny(true)]),
        },
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.context_values.insert("session_age_s".into(), 300);
    assert_eq!(run_policy(&cap, ctx, "n_ctx_match", &ks).unwrap().decision, 1);
}

#[test]
fn condition_context_integer_over_threshold_denies() {
    let ks = MockKs::new_from(0xA1);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::Context {
                key: "session_age_s".into(),
                comparator: Comparator::Lt,
                value: ContextValue::Integer(3600),
            },
            then_branch: vec![Step::Allow(true)],
            else_branch: Some(vec![Step::Deny(true)]),
        },
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.context_values.insert("session_age_s".into(), 7200_i32); // > 3600
    assert_eq!(run_policy(&cap, ctx, "n_ctx_over", &ks).unwrap().decision, 0);
}

// ─── Password breach count ────────────────────────────────────────────────────

/// Risk policy that reads password_breach_count via get_password_breach_count host import.
/// We simulate using a Conditional on RiskScore that's set by the breach count in context.
/// More directly: use a raw Condition::Context check isn't possible for breach count —
/// it's a direct host import. Test it via a Conditional that reads risk_score, which is
/// set from the breach-influenced context by the host runtime.
#[test]
fn breach_count_zero_passes_risk_check() {
    let ks = MockKs::new_from(0x90);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::EvaluateRisk { profile: "standard".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(80) },
            then_branch: vec![Step::Deny(true)],
            else_branch: Some(vec![Step::Allow(true)]),
        },
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.risk_score = 30;
    ctx.password_breach_count = 0;
    assert_eq!(run_policy(&cap, ctx, "n_breach_zero", &ks).unwrap().decision, 1);
}

// ─── IdentitySource variants ──────────────────────────────────────────────────

/// Federated identity source (src=1): subject_id from context → Allow.
#[test]
fn identity_source_federated_allows_known_subject() {
    let ks = MockKs::new_from(0x80);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Federated },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    // subject_id=42 (non-zero) → verify_identity returns 42 → not Guest → Allow
    let mut ctx = dummy_ctx();
    ctx.subject_id = 42;
    assert_eq!(run_policy(&cap, ctx, "n_fed", &ks).unwrap().decision, 1);
}

/// Device identity source (src=2).
#[test]
fn identity_source_device_allows_known_subject() {
    let ks = MockKs::new_from(0x81);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Device },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);
    let mut ctx = dummy_ctx();
    ctx.subject_id = 7;
    assert_eq!(run_policy(&cap, ctx, "n_dev", &ks).unwrap().decision, 1);
}

/// SPIFFE source (src=4): requires principal_source="spiffe" or emits NeedInput.
#[test]
fn identity_source_spiffe_requires_validated_svid() {
    let ks = MockKs::new_from(0x82);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Spiffe { trust_domain: "corp.example".into() } },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Allow(true),
    ], &ks);

    // Without SVID: verify_identity returns 0 → NeedInput(2)
    let mut ctx_no_svid = dummy_ctx();
    ctx_no_svid.principal_source = String::new();
    let out = run_policy(&cap, ctx_no_svid, "n_spiffe_no", &ks).unwrap();
    assert_ne!(out.decision, 1, "SPIFFE without SVID must not Allow");

    // With validated SVID: verify_identity returns subject_id → Allow
    let mut ctx_svid = dummy_ctx();
    ctx_svid.principal_source = "spiffe".into();
    ctx_svid.subject_id = 99;
    assert_eq!(run_policy(&cap, ctx_svid, "n_spiffe_ok", &ks).unwrap().decision, 1);
}

// ─── RiskScore boundary comparators ──────────────────────────────────────────

/// Exact boundary: risk == threshold (Eq comparator).
#[test]
fn risk_score_eq_boundary_exact() {
    let ks = MockKs::new_from(0x70);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::EvaluateRisk { profile: "standard".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::RiskScore { comparator: Comparator::Eq, value: Some(75) },
            then_branch: vec![Step::Deny(true)],
            else_branch: Some(vec![Step::Allow(true)]),
        },
    ], &ks);
    let mut ctx_eq = dummy_ctx();
    ctx_eq.risk_score = 75;
    assert_eq!(run_policy(&cap, ctx_eq, "n_eq_75", &ks).unwrap().decision, 0, "75 == 75 → Deny");

    let mut ctx_ne = dummy_ctx();
    ctx_ne.risk_score = 74;
    assert_eq!(run_policy(&cap, ctx_ne, "n_ne_74", &ks).unwrap().decision, 1, "74 != 75 → Allow");
}

/// Lte boundary: risk <= threshold.
#[test]
fn risk_score_lte_boundary() {
    let ks = MockKs::new_from(0x71);
    let cap = compile_policy(vec![
        Step::VerifyIdentity { source: IdentitySource::Primary },
        Step::EvaluateRisk { profile: "standard".into() },
        Step::AuthorizeAction { action: "act".into(), resource: "res".into() },
        Step::Conditional {
            condition: Condition::RiskScore { comparator: Comparator::Lte, value: Some(50) },
            then_branch: vec![Step::Allow(true)],
            else_branch: Some(vec![Step::Deny(true)]),
        },
    ], &ks);
    let mut ctx_at = dummy_ctx();
    ctx_at.risk_score = 50;
    assert_eq!(run_policy(&cap, ctx_at, "n_lte_50", &ks).unwrap().decision, 1, "50 <= 50 → Allow");

    let mut ctx_over = dummy_ctx();
    ctx_over.risk_score = 51;
    assert_eq!(run_policy(&cap, ctx_over, "n_lte_51", &ks).unwrap().decision, 0, "51 <= 50 → false → Deny");
}
