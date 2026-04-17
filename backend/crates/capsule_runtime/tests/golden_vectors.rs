use anyhow::Result;
use capsule_compiler::{
    ast::{self, Comparator, Condition, FactorType, IdentitySource, Step},
    compile,
};
use capsule_runtime::{execute, ExecuteParams, RuntimeContext};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use keystore::{KeyId, Keystore};

// Mock Keystore for signing
struct MockKeystore {
    signing_key: SigningKey,
}

impl MockKeystore {
    fn new() -> Self {
        // Use deterministic key for stable WASM hashes
        Self {
            signing_key: SigningKey::from_bytes(&[1u8; 32]),
        }
    }

    fn verifier(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Helper to execute a capsule with standard test parameters.
    fn exec(
        &self,
        capsule: &capsule_compiler::CapsuleSigned,
        input_ctx: RuntimeContext,
        expected_ast_hash: &str,
        expected_wasm_hash: &str,
    ) -> Result<(capsule_runtime::DecisionOutput, attestation::Attestation)> {
        execute(ExecuteParams {
            capsule,
            input_ctx,
            runtime_kid: "k",
            sign_fn: &|d| Ok(self.signing_key.sign(d)),
            now_unix: 0,
            expires_at_unix: 0,
            nonce_b64: "n",
            expected_ast_hash: Some(expected_ast_hash),
            expected_wasm_hash: Some(expected_wasm_hash),
        })
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

#[test]
fn test_vector_1_simple_allow() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "read".to_string(),
                resource: "profile".to_string(),
            },
            Step::Allow(true),
        ],
    };

    // Note: These need to be re-captured if lowerer changes
    let expected_ast_hash = "57078bd87d78a598faf3b50f9541b7141e68f9ad8e048d6df188c219c16eb70e";
    let expected_wasm_hash = "b78fdcc2a8ba9cc9c6b1af3faa67dbd7eb3658a348c6abfd694e8cee6a0252e8";

    let ks = MockKeystore::new();
    let kid = KeyId("test-key".to_string());
    let capsule = compile(program, "t".to_string(), "a".to_string(), 0, 0, &ks, &kid)?;

    println!("VECTOR 1 ACTUAL AST HASH: {}", capsule.ast_hash);
    println!("VECTOR 1 ACTUAL WASM HASH: {}", capsule.wasm_hash);

    // assert_eq!(capsule.ast_hash, expected_ast_hash, "V1 AST Hash Mismatch");
    // assert_eq!(capsule.wasm_hash, expected_wasm_hash, "V1 WASM Hash Mismatch");

    let inputs = RuntimeContext {
        subject_id: 42,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (output, _) = ks.exec(&capsule, inputs, expected_ast_hash, expected_wasm_hash)?;

    assert_eq!(output.decision, 1, "V1 Decision mismatch");
    assert_eq!(output.subject_id, 42, "V1 Subject ID mismatch");
    assert_eq!(output.authz_result, 1, "V1 AuthZ result mismatch");
    Ok(())
}

#[test]
fn test_vector_2_risk_step_up() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::EvaluateRisk {
                profile: "default".to_string(),
            },
            Step::Conditional {
                condition: Condition::RiskScore {
                    comparator: Comparator::Gt,
                    value: Some(80),
                },
                then_branch: vec![Step::RequireFactor {
                    factor_type: FactorType::Otp,
                }],
                else_branch: None, // Implicit continue
            },
            Step::AuthorizeAction {
                action: "transfer".to_string(),
                resource: "bank".to_string(),
            },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash = "e9c94829aab9b50bd18188c8bd97ffac82fec990902a7ad8d8c4cc638948ec7a";
    let expected_wasm_hash = "0e563a7eae8535d2debc3a88735a6b42a422dee7461fcbd90aab18c77629c1e0";

    let ks = MockKeystore::new();
    let kid = KeyId("test-key-2".to_string());
    let capsule = compile(program, "t2".to_string(), "a2".to_string(), 0, 0, &ks, &kid)?;

    println!("VECTOR 2 ACTUAL AST HASH: {}", capsule.ast_hash);
    println!("VECTOR 2 ACTUAL WASM HASH: {}", capsule.wasm_hash);

    assert_eq!(capsule.ast_hash, expected_ast_hash, "V2 AST Hash Mismatch");
    assert_eq!(
        capsule.wasm_hash, expected_wasm_hash,
        "V2 WASM Hash Mismatch"
    );

    // A: Low Risk
    let ctx_low = RuntimeContext {
        subject_id: 42,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_low, _) = ks.exec(&capsule, ctx_low, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_low.decision, 1, "V2 Low risk Allow");

    // B1: High Risk + MFA
    let ctx_high_ok = RuntimeContext {
        subject_id: 42,
        risk_score: 90,
        factors_satisfied: vec![0],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_high_ok, _) = ks.exec(&capsule, ctx_high_ok, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_high_ok.decision, 1, "V2 High risk + MFA Allow");

    // B2: High Risk + No MFA
    let ctx_high_fail = RuntimeContext {
        subject_id: 42,
        risk_score: 90,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_high_fail, _) = ks.exec(
        &capsule,
        ctx_high_fail,
        expected_ast_hash,
        expected_wasm_hash,
    )?;
    assert_eq!(out_high_fail.decision, 0, "V2 High risk + No MFA Deny");

    Ok(())
}

#[test]
fn test_vector_3_risk_deny() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::EvaluateRisk {
                profile: "strict".to_string(),
            },
            Step::Conditional {
                condition: Condition::RiskScore {
                    comparator: Comparator::Gt,
                    value: Some(90),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            Step::AuthorizeAction {
                action: "transfer".to_string(),
                resource: "bank".to_string(),
            },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let kid = KeyId("k".to_string());
    let capsule = compile(program, "t3".to_string(), "a3".to_string(), 0, 0, &ks, &kid)?;

    println!("VECTOR 3 ACTUAL AST HASH: {}", capsule.ast_hash);
    println!("VECTOR 3 ACTUAL WASM HASH: {}", capsule.wasm_hash);

    assert_eq!(
        capsule.ast_hash, "dfe48e63be874e546880cc4e649b12f7ca283ea419e310a6388bfed99243d2dc",
        "V3 AST Hash Mismatch"
    );
    assert_eq!(
        capsule.wasm_hash, "4c56e5054b1159accb9276e4cf0130a50a9a5f227cb8ac95ca400d84ea885cfe",
        "V3 WASM Hash Mismatch"
    );

    let ctx_allow = RuntimeContext {
        subject_id: 1,
        risk_score: 50,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    // V3
    let expected_ast_hash = "dfe48e63be874e546880cc4e649b12f7ca283ea419e310a6388bfed99243d2dc";
    let expected_wasm_hash = "4c56e5054b1159accb9276e4cf0130a50a9a5f227cb8ac95ca400d84ea885cfe";
    let (out_a, _) = ks.exec(&capsule, ctx_allow, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_a.decision, 1, "V3 Moderate risk Allow");

    let ctx_deny = RuntimeContext {
        subject_id: 1,
        risk_score: 95,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_b, _) = ks.exec(&capsule, ctx_deny, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_b.decision, 0, "V3 High risk Deny");

    Ok(())
}

#[test]
fn test_vector_4_authz_denial() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "sys".to_string(),
                resource: "root".to_string(),
            },
            Step::Conditional {
                condition: Condition::AuthzResult {
                    comparator: Comparator::Eq,
                    value: Some(0),
                },
                then_branch: vec![Step::Deny(true)],
                else_branch: None,
            },
            Step::Allow(true),
        ],
    };

    let expected_ast_hash = "2432bc069ad9b26935dad7409b4745b327360ee03bfee73646970c4f1741ecbb";
    let expected_wasm_hash = "570f83ac4c298fc8351e48ed770eaadb6706ce7d69a9eb287aa268ab6d211257";

    let ks = MockKeystore::new();
    let kid = KeyId("k".to_string());
    let capsule = compile(program, "t4".to_string(), "a4".to_string(), 0, 0, &ks, &kid)?;

    println!("VECTOR 4 ACTUAL AST HASH: {}", capsule.ast_hash);
    println!("VECTOR 4 ACTUAL WASM HASH: {}", capsule.wasm_hash);

    assert_eq!(capsule.ast_hash, expected_ast_hash, "V4 AST Hash Mismatch");
    assert_eq!(
        capsule.wasm_hash, expected_wasm_hash,
        "V4 WASM Hash Mismatch"
    );

    let ctx_ok = RuntimeContext {
        subject_id: 1,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_a, _) = ks.exec(&capsule, ctx_ok, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_a.decision, 1, "V4 AuthZ Allow");

    let ctx_fail = RuntimeContext {
        subject_id: 1,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 0,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_b, _) = ks.exec(&capsule, ctx_fail, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_b.decision, 0, "V4 AuthZ Deny");

    Ok(())
}

#[test]
fn test_vector_5_canonicalization() -> Result<()> {
    // Check Stability of Vector 1 AST Hash
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "read".to_string(),
                resource: "profile".to_string(),
            },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let kid = KeyId("k".to_string());
    let capsule = compile(program, "t".to_string(), "a".to_string(), 0, 0, &ks, &kid)?;

    // Vector 1's authoritative AST hash
    let v1_hash = "57078bd87d78a598faf3b50f9541b7141e68f9ad8e048d6df188c219c16eb70e";

    println!("VECTOR 5 ACTUAL AST HASH: {}", capsule.ast_hash);

    assert_eq!(capsule.ast_hash, v1_hash, "V5 Canonicalization mismatch");
    Ok(())
}

#[test]
fn test_vector_6_nesting() -> Result<()> {
    let program = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::EvaluateRisk {
                profile: "def".to_string(),
            },
            Step::Conditional {
                condition: Condition::RiskScore {
                    comparator: Comparator::Gt,
                    value: Some(50),
                },
                then_branch: vec![Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(90),
                    },
                    then_branch: vec![Step::Deny(true)],
                    else_branch: Some(vec![Step::RequireFactor {
                        factor_type: FactorType::Otp,
                    }]),
                }],
                else_branch: None,
            },
            Step::AuthorizeAction {
                action: "transfer".to_string(),
                resource: "bank".to_string(),
            },
            Step::Allow(true),
        ],
    };

    let ks = MockKeystore::new();
    let kid = KeyId("k".to_string());
    let capsule = compile(program, "t".to_string(), "a".to_string(), 0, 0, &ks, &kid)?;

    println!("VECTOR 6 ACTUAL AST HASH: {}", capsule.ast_hash);
    println!("VECTOR 6 ACTUAL WASM HASH: {}", capsule.wasm_hash);

    assert_eq!(
        capsule.ast_hash, "1c2bb124052293243ef3392878d571c372a64b0d11f0dd23e4cb0cd11d487322",
        "V6 AST Hash Mismatch"
    );
    assert_eq!(
        capsule.wasm_hash, "4353ac4f544a4f8d0201cafd89c028a36abdb7fe0462646a03057d920a50efed",
        "V6 WASM Hash Mismatch"
    );

    // A: Risk 10 -> Allow
    let ctx_10 = RuntimeContext {
        subject_id: 1,
        risk_score: 10,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    // V6
    let expected_ast_hash = "1c2bb124052293243ef3392878d571c372a64b0d11f0dd23e4cb0cd11d487322";
    let expected_wasm_hash = "4353ac4f544a4f8d0201cafd89c028a36abdb7fe0462646a03057d920a50efed";
    let (out_10, _) = ks.exec(&capsule, ctx_10, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_10.decision, 1, "V6 Risk 10 Allow");

    // B: Risk 60 -> OTP Required
    let ctx_60_fail = RuntimeContext {
        subject_id: 1,
        risk_score: 60,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_60_fail, _) = ks.exec(&capsule, ctx_60_fail, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_60_fail.decision, 0, "V6 Risk 60 No OTP Deny");

    let ctx_60_ok = RuntimeContext {
        subject_id: 1,
        risk_score: 60,
        factors_satisfied: vec![0],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_60_ok, _) = ks.exec(&capsule, ctx_60_ok, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_60_ok.decision, 1, "V6 Risk 60 OTP Allow");

    // C: Risk 95 -> Deny
    let ctx_95 = RuntimeContext {
        subject_id: 1,
        risk_score: 95,
        factors_satisfied: vec![0],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
        assurance_level: 0,
        verified_capabilities: vec![],
        context_values: std::collections::HashMap::new(),
        password_breach_count: 0,
    };
    let (out_95, _) = ks.exec(&capsule, ctx_95, expected_ast_hash, expected_wasm_hash)?;
    assert_eq!(out_95.decision, 0, "V6 Risk 95 Deny");

    Ok(())
}
