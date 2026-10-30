//! Golden-vector tests for the capsule compiler + runtime.
//!
//! Each vector pins a concrete AST → expected (AST hash, WASM hash, decision) triple.
//! A hash change in any vector means the lowering changed in an incompatible way —
//! capsules compiled with the old lowerer will produce a different WASM hash than
//! the one stored in the database, causing every cached capsule to fail attestation.
//!
//! # Adding a new vector
//! 1. Write the AST, compile it, `println!` the actual hashes.
//! 2. Run once to record them, then add `assert_eq!` guards.
//! 3. Never comment out a hash assertion — that defeats the purpose of the vector.
//!
//! # Hash stability note
//! V1 hash assertions are enabled.  V1's program is identical to V5
//! (canonicalization check); both must hash identically.

use anyhow::Result;
use capsule_compiler::{
    ast::{self, Comparator, Condition, FactorType, IdentityLevel, IdentitySource, Step},
    compile,
};
use capsule_runtime::{execute, ExecuteParams, RuntimeContext};
use ed25519_dalek::{Signer, SigningKey};
use keystore::{KeyId, Keystore};

// ─── Shared infrastructure ────────────────────────────────────────────────────

struct MockKeystore {
    signing_key: SigningKey,
}

impl MockKeystore {
    /// Deterministic key so compiled WASM bytes (and their hashes) are stable
    /// across runs and machines.
    fn new() -> Self {
        Self { signing_key: SigningKey::from_bytes(&[1u8; 32]) }
    }

    fn exec(
        &self,
        capsule: &capsule_compiler::CapsuleSigned,
        input_ctx: RuntimeContext,
        nonce: &str,
    ) -> Result<(capsule_runtime::DecisionOutput, attestation::Attestation)> {
        execute(ExecuteParams {
            capsule,
            input_ctx,
            runtime_kid: "k",
            sign_fn: &|d| Ok(self.signing_key.sign(d)),
            now_unix: 1_000_000,
            expires_at_unix: 9_999_999_999,
            nonce_b64: nonce,
            expected_ast_hash: Some(&capsule.ast_hash),
            expected_wasm_hash: Some(&capsule.wasm_hash),
        })
    }
}

impl Keystore for MockKeystore {
    fn sign(&self, _: &KeyId, data: &[u8]) -> Result<ed25519_dalek::Signature> {
        Ok(self.signing_key.sign(data))
    }
    fn generate_ed25519(&self) -> Result<KeyId> { Ok(KeyId("mock-kid".into())) }
    fn import_ed25519(&self, _: &[u8]) -> Result<KeyId> { Ok(KeyId("mock-kid".into())) }
    fn public_key(&self, kid: &KeyId) -> Result<keystore::PublicKey> {
        Ok(keystore::PublicKey { kid: kid.clone(), key: self.signing_key.verifying_key() })
    }
    fn list_public_keys(&self) -> Vec<keystore::PublicKey> {
        vec![keystore::PublicKey {
            kid: KeyId("mock-kid".into()),
            key: self.signing_key.verifying_key(),
        }]
    }
}

fn ctx(risk: i32, factors: Vec<i32>, authz: i32) -> RuntimeContext {
    RuntimeContext {
        subject_id: 42,
        risk_score: risk,
        factors_satisfied: factors,
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: authz,
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

// ─── Vector 1: Simple allow ───────────────────────────────────────────────────

#[test]
fn test_vector_1_simple_allow() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::AuthorizeAction { action: "read".into(), resource: "profile".into() },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash  = "57078bd87d78a598faf3b50f9541b7141e68f9ad8e048d6df188c219c16eb70e";
    let expected_wasm_hash = "86f0a7a74bce8418248d7f9c9ed0fb6bce437cf4edd61b10443fd66005efa377";

    let ks = MockKeystore::new();
    let capsule = compile(program, "t".into(), "a".into(), 0, i64::MAX, &ks, &KeyId("test-key".into()))?;

    assert_eq!(capsule.ast_hash,  expected_ast_hash,  "V1 AST Hash Mismatch");
    assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V1 WASM Hash Mismatch");

    let (out, att) = ks.exec(&capsule, ctx(0, vec![], 1), "v1_n1")?;
    assert_eq!(out.decision,    1,  "V1 Decision");
    assert_eq!(out.subject_id,  42, "V1 SubjectID");
    assert_eq!(out.authz_result, 1, "V1 AuthzResult");
    assert!(!att.signature_b64.is_empty(), "V1 attestation must be signed");
    Ok(())
}

// ─── Vector 2: Risk-based step-up ────────────────────────────────────────────

#[test]
fn test_vector_2_risk_step_up() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::EvaluateRisk { profile: "default".into() },
            Step::Conditional {
                condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(80) },
                then_branch: vec![Step::RequireFactor { factor_type: FactorType::Otp }],
                else_branch: None,
            },
            Step::AuthorizeAction { action: "transfer".into(), resource: "bank".into() },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash  = "e9c94829aab9b50bd18188c8bd97ffac82fec990902a7ad8d8c4cc638948ec7a";
    let expected_wasm_hash = "fdc994780ef6cba37b8511266940d356d0f0e572190c82d161dee1a9d948e7eb";

    let ks = MockKeystore::new();
    let capsule = compile(program, "t2".into(), "a2".into(), 0, i64::MAX, &ks, &KeyId("test-key-2".into()))?;

    assert_eq!(capsule.ast_hash,  expected_ast_hash,  "V2 AST Hash Mismatch");
    assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V2 WASM Hash Mismatch");

    // Low risk → Allow without MFA
    let (out_low, _) = ks.exec(&capsule, ctx(0, vec![], 1), "v2_low")?;
    assert_eq!(out_low.decision, 1, "V2 Low risk Allow");

    // High risk + OTP satisfied → Allow
    let (out_hi_ok, _) = ks.exec(&capsule, ctx(90, vec![0], 1), "v2_hi_ok")?;
    assert_eq!(out_hi_ok.decision, 1, "V2 High risk + OTP Allow");

    // High risk + no MFA → Deny
    let (out_hi_fail, _) = ks.exec(&capsule, ctx(90, vec![], 1), "v2_hi_fail")?;
    assert_eq!(out_hi_fail.decision, 0, "V2 High risk + No MFA Deny");

    Ok(())
}

// ─── Vector 3: Risk hard-deny above threshold ─────────────────────────────────

#[test]
fn test_vector_3_risk_deny() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::EvaluateRisk { profile: "strict".into() },
            Step::Conditional {
                condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(90) },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            Step::AuthorizeAction { action: "transfer".into(), resource: "bank".into() },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash  = "dfe48e63be874e546880cc4e649b12f7ca283ea419e310a6388bfed99243d2dc";
    let expected_wasm_hash = "16aeff4156e3cb7864fdbe16d98f70c2ca99865bceca28d14b5b5c0cd8edd4e9";

    let ks = MockKeystore::new();
    let capsule = compile(program, "t3".into(), "a3".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    assert_eq!(capsule.ast_hash,  expected_ast_hash,  "V3 AST Hash Mismatch");
    assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V3 WASM Hash Mismatch");

    let (out_allow, _) = ks.exec(&capsule, ctx(50, vec![], 1), "v3_allow")?;
    assert_eq!(out_allow.decision, 1, "V3 Moderate risk Allow");

    // Exactly at threshold (90) — Gt means 90 is NOT denied
    let (out_at, _) = ks.exec(&capsule, ctx(90, vec![], 1), "v3_at")?;
    assert_eq!(out_at.decision, 1, "V3 Risk exactly at threshold → Allow");

    // One above threshold → Deny
    let (out_deny, _) = ks.exec(&capsule, ctx(91, vec![], 1), "v3_deny")?;
    assert_eq!(out_deny.decision, 0, "V3 Risk > threshold → Deny");

    Ok(())
}

// ─── Vector 4: AuthorizeAction gate ──────────────────────────────────────────

#[test]
fn test_vector_4_authz_denial() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::AuthorizeAction { action: "sys".into(), resource: "root".into() },
            Step::Conditional {
                condition: Condition::AuthzResult { comparator: Comparator::Eq, value: Some(0) },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash  = "2432bc069ad9b26935dad7409b4745b327360ee03bfee73646970c4f1741ecbb";
    let expected_wasm_hash = "5094971b447ab034fda791be07763c0a0e2a91362280bae99c470dc096a2c281";

    let ks = MockKeystore::new();
    let capsule = compile(program, "t4".into(), "a4".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    assert_eq!(capsule.ast_hash,  expected_ast_hash,  "V4 AST Hash Mismatch");
    assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V4 WASM Hash Mismatch");

    let (out_ok, _) = ks.exec(&capsule, ctx(0, vec![], 1), "v4_ok")?;
    assert_eq!(out_ok.decision, 1, "V4 AuthZ Allow");

    let (out_deny, _) = ks.exec(&capsule, ctx(0, vec![], 0), "v4_deny")?;
    assert_eq!(out_deny.decision, 0, "V4 AuthZ Deny");

    Ok(())
}

// ─── Vector 5: AST canonicalization stability ─────────────────────────────────
//
// V5 uses the exact same AST as V1 with different compiler key ID.
// The AST hash must be identical to V1 — it is content-addressed, not key-addressed.
// The WASM hash may differ (compiler_kid is included in the signature metadata
// but the WASM bytes themselves only depend on the AST, not the key).

#[test]
fn test_vector_5_canonicalization() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::AuthorizeAction { action: "read".into(), resource: "profile".into() },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    // Different kid than V1 ("k" vs "test-key") — AST hash must still match.
    let capsule = compile(program, "t".into(), "a".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    let v1_ast_hash = "57078bd87d78a598faf3b50f9541b7141e68f9ad8e048d6df188c219c16eb70e";
    assert_eq!(capsule.ast_hash, v1_ast_hash, "V5 AST hash must equal V1 (canonicalization stability)");

    Ok(())
}

// ─── Vector 6: Nested conditionals ───────────────────────────────────────────

#[test]
fn test_vector_6_nesting() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::EvaluateRisk { profile: "def".into() },
            Step::Conditional {
                condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(50) },
                then_branch: vec![Step::Conditional {
                    condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(90) },
                    then_branch: vec![Step::Deny(true)],
                    else_branch: Some(vec![Step::RequireFactor { factor_type: FactorType::Otp }]),
                }],
                else_branch: None,
            },
            Step::AuthorizeAction { action: "transfer".into(), resource: "bank".into() },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash  = "1c2bb124052293243ef3392878d571c372a64b0d11f0dd23e4cb0cd11d487322";
    let expected_wasm_hash = "60ed77dbb380555135c73841005097b39444c8d107db26a9a25a1a37bd4dba87";

    let ks = MockKeystore::new();
    let capsule = compile(program, "t".into(), "a".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    assert_eq!(capsule.ast_hash,  expected_ast_hash,  "V6 AST Hash Mismatch");
    assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V6 WASM Hash Mismatch");

    // Risk 10: outer conditional false → Allow
    let (out_10, _) = ks.exec(&capsule, ctx(10, vec![], 1), "v6_10")?;
    assert_eq!(out_10.decision, 1, "V6 Risk 10 Allow");

    // Risk 60 + no OTP → inner OTP required, Deny
    let (out_60_fail, _) = ks.exec(&capsule, ctx(60, vec![], 1), "v6_60_fail")?;
    assert_eq!(out_60_fail.decision, 0, "V6 Risk 60 No OTP Deny");

    // Risk 60 + OTP → Allow
    let (out_60_ok, _) = ks.exec(&capsule, ctx(60, vec![0], 1), "v6_60_ok")?;
    assert_eq!(out_60_ok.decision, 1, "V6 Risk 60 OTP Allow");

    // Risk 95 + OTP → inner conditional true (>90) → Deny regardless of OTP
    let (out_95, _) = ks.exec(&capsule, ctx(95, vec![0], 1), "v6_95")?;
    assert_eq!(out_95.decision, 0, "V6 Risk 95 Deny");

    Ok(())
}

// ─── Vector 7: IdentityLevel AAL gate ────────────────────────────────────────

#[test]
fn test_vector_7_identity_level_gate() -> Result<()> {
    // Policy: require AAL ≥ Medium (2) to read sensitive data.
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::AuthorizeAction { action: "read".into(), resource: "secrets".into() },
            Step::Conditional {
                condition: Condition::IdentityLevel {
                    comparator: Comparator::Lt,
                    level: IdentityLevel::Medium,
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: Some(vec![Step::Allow(true)]),
            },
        ],
    };

    let ks = MockKeystore::new();
    let capsule = compile(program, "t7".into(), "a7".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    // AAL 1 (Low) < Medium → Deny
    let mut ctx_aal1 = ctx(0, vec![], 1);
    ctx_aal1.assurance_level = 1;
    let (out_low, _) = ks.exec(&capsule, ctx_aal1, "v7_aal1")?;
    assert_eq!(out_low.decision, 0, "V7 AAL1 < Medium → Deny");

    // AAL 2 (Medium) — not < Medium → Allow
    let mut ctx_aal2 = ctx(0, vec![], 1);
    ctx_aal2.assurance_level = 2;
    let (out_med, _) = ks.exec(&capsule, ctx_aal2, "v7_aal2")?;
    assert_eq!(out_med.decision, 1, "V7 AAL2 ≥ Medium → Allow");

    // AAL 3 (High) → Allow
    let mut ctx_aal3 = ctx(0, vec![], 1);
    ctx_aal3.assurance_level = 3;
    let (out_high, _) = ks.exec(&capsule, ctx_aal3, "v7_aal3")?;
    assert_eq!(out_high.decision, 1, "V7 AAL3 ≥ Medium → Allow");

    Ok(())
}

// ─── Vector 8: RequireVerification gate ──────────────────────────────────────

#[test]
fn test_vector_8_require_verification() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::RequireVerification { verification_type: "email".into() },
            Step::AuthorizeAction { action: "write".into(), resource: "profile".into() },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let capsule = compile(program, "t8".into(), "a8".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    // Email verified → Allow
    let mut ctx_verified = ctx(0, vec![], 1);
    ctx_verified.verifications_satisfied = vec!["email".into()];
    let (out_ok, _) = ks.exec(&capsule, ctx_verified, "v8_ok")?;
    assert_eq!(out_ok.decision, 1, "V8 Email verified → Allow");

    // Not verified → Deny
    let (out_no, _) = ks.exec(&capsule, ctx(0, vec![], 1), "v8_no")?;
    assert_eq!(out_no.decision, 0, "V8 Unverified email → Deny");

    // Wrong verification type → Deny
    let mut ctx_phone = ctx(0, vec![], 1);
    ctx_phone.verifications_satisfied = vec!["phone".into()];
    let (out_phone, _) = ks.exec(&capsule, ctx_phone, "v8_phone")?;
    assert_eq!(out_phone.decision, 0, "V8 Wrong verification type → Deny");

    Ok(())
}

// ─── Vector 9: RequireUserAction gate ────────────────────────────────────────

#[test]
fn test_vector_9_require_user_action() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::RequireUserAction { code: "configure_mfa".into() },
            Step::AuthorizeAction { action: "access".into(), resource: "app".into() },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let capsule = compile(program, "t9".into(), "a9".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    // No pending actions → Allow
    let (out_ok, _) = ks.exec(&capsule, ctx(0, vec![], 1), "v9_ok")?;
    assert_eq!(out_ok.decision, 1, "V9 No pending action → Allow");

    // configure_mfa pending → Deny
    let mut ctx_pending = ctx(0, vec![], 1);
    ctx_pending.required_actions = vec!["configure_mfa".into()];
    let (out_block, _) = ks.exec(&capsule, ctx_pending, "v9_block")?;
    assert_eq!(out_block.decision, 0, "V9 Pending action → Deny");

    // Different action pending → Allow (doesn't block configure_mfa requirement)
    let mut ctx_other = ctx(0, vec![], 1);
    ctx_other.required_actions = vec!["verify_email".into()];
    let (out_other, _) = ks.exec(&capsule, ctx_other, "v9_other")?;
    assert_eq!(out_other.decision, 1, "V9 Unrelated pending action → Allow");

    Ok(())
}

// ─── Vector 11: Multiple factor types ────────────────────────────────────────

#[test]
fn test_vector_11_factor_types() -> Result<()> {
    // Policy: require any of [Passkey, HardwareKey]
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::RequireFactor {
                factor_type: FactorType::Any(vec![FactorType::Passkey, FactorType::HardwareKey]),
            },
            Step::AuthorizeAction { action: "admin".into(), resource: "settings".into() },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let capsule = compile(program, "t11".into(), "a11".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    // Passkey (1) only → Allow
    let (out_pk, _) = ks.exec(&capsule, ctx(0, vec![1], 1), "v11_pk")?;
    assert_eq!(out_pk.decision, 1, "V11 Passkey satisfies Any");

    // HardwareKey (3) only → Allow
    let (out_hk, _) = ks.exec(&capsule, ctx(0, vec![3], 1), "v11_hk")?;
    assert_eq!(out_hk.decision, 1, "V11 HardwareKey satisfies Any");

    // OTP only (0) → Deny (not in the Any list)
    let (out_otp, _) = ks.exec(&capsule, ctx(0, vec![0], 1), "v11_otp_denied")?;
    assert_eq!(out_otp.decision, 0, "V11 OTP alone doesn't satisfy Passkey|HardwareKey");

    // No factors → Deny
    let (out_none, _) = ks.exec(&capsule, ctx(0, vec![], 1), "v11_none")?;
    assert_eq!(out_none.decision, 0, "V11 No factors → Deny");

    Ok(())
}

// ─── Vector 12: Attestation carries correct hash and nonce ───────────────────

#[test]
fn test_vector_12_attestation_fields() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".into(),
        sequence: vec![
            Step::VerifyIdentity { source: IdentitySource::Primary },
            Step::AuthorizeAction { action: "read".into(), resource: "data".into() },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let capsule = compile(program, "t12".into(), "a12".into(), 0, i64::MAX, &ks, &KeyId("k".into()))?;

    let nonce = "unique_nonce_v12";
    let (out, att) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: ctx(0, vec![], 1),
        runtime_kid: "runtime-kid-v12",
        sign_fn: &|d| Ok(ks.signing_key.sign(d)),
        now_unix: 1_000_000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: nonce,
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })?;

    assert_eq!(out.decision, 1, "V12 Allow");
    assert_eq!(att.body.nonce_b64, nonce, "V12 attestation nonce echoed");
    assert_eq!(att.body.wasm_hash_b64, capsule.wasm_hash, "V12 attestation wasm hash");
    assert_eq!(att.body.ast_hash_b64, capsule.ast_hash, "V12 attestation ast hash");
    assert_eq!(att.body.runtime_kid, "runtime-kid-v12", "V12 attestation runtime kid");
    assert!(!att.signature_b64.is_empty(), "V12 attestation signed");

    // Different nonce → different attestation body
    let (_, att2) = execute(ExecuteParams {
        capsule: &capsule,
        input_ctx: ctx(0, vec![], 1),
        runtime_kid: "runtime-kid-v12",
        sign_fn: &|d| Ok(ks.signing_key.sign(d)),
        now_unix: 1_000_000,
        expires_at_unix: 9_999_999_999,
        nonce_b64: "different_nonce",
        expected_ast_hash: None,
        expected_wasm_hash: None,
    })?;
    assert_ne!(att.body.nonce_b64, att2.body.nonce_b64);

    Ok(())
}
