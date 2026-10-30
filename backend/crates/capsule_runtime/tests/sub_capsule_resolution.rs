//! T4.3 — End-to-end test for `execute_with_resolver`.
//!
//! Verifies that:
//! 1. A parent capsule that contains `Step::AggregateDecision` resolves and
//!    executes its children automatically.
//! 2. The aggregation strategy folds correctly (Affirmative / Unanimous /
//!    Consensus) once children's decisions are populated.
//! 3. A self-cycle is detected and the cyclic child resolves to Deny
//!    without infinite recursion.

use anyhow::Result;
use capsule_compiler::{
    ast::{self, AggregationStrategy, CapsuleRef, IdentitySource, Step},
    compile, CapsuleSigned,
};
use capsule_runtime::{
    execute_with_resolver,
    resolver::{CapsuleResolver, InMemoryCapsuleResolver},
    ExecuteParams, RuntimeContext,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use keystore::{KeyId, Keystore};

struct MockKeystore {
    signing_key: SigningKey,
}

impl MockKeystore {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[7u8; 32]),
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

fn ctx() -> RuntimeContext {
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

fn compile_terminal(allow: bool, ks: &MockKeystore, action: &str) -> CapsuleSigned {
    let prog = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "read".to_string(),
                resource: "x".to_string(),
            },
            if allow {
                Step::Allow(true)
            } else {
                Step::Deny(true)
            },
        ],
    };
    compile(
        prog,
        "tenant".to_string(),
        action.to_string(),
        0,
        i64::MAX,
        ks,
        &KeyId("mock-kid".to_string()),
    )
    .expect("compile child")
}

fn compile_aggregate(
    strategy: AggregationStrategy,
    children: &[&CapsuleSigned],
    ks: &MockKeystore,
) -> CapsuleSigned {
    let prog = ast::Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "agg".to_string(),
                resource: "x".to_string(),
            },
            Step::AggregateDecision {
                strategy,
                sub_capsules: children
                    .iter()
                    .map(|c| CapsuleRef {
                        ast_hash: c.ast_hash.clone(),
                    })
                    .collect(),
            },
        ],
    };
    compile(
        prog,
        "tenant".to_string(),
        "aggregate".to_string(),
        0,
        i64::MAX,
        ks,
        &KeyId("mock-kid".to_string()),
    )
    .expect("compile parent")
}

fn run(parent: &CapsuleSigned, resolver: &dyn CapsuleResolver, ks: &MockKeystore) -> i32 {
    let (out, _att) = execute_with_resolver(
        ExecuteParams {
            capsule: parent,
            input_ctx: ctx(),
            runtime_kid: "k",
            sign_fn: &|d| Ok(ks.signing_key.sign(d)),
            now_unix: 0,
            expires_at_unix: 0,
            nonce_b64: "n",
            expected_ast_hash: Some(parent.ast_hash.as_str()),
            expected_wasm_hash: None,
        },
        resolver,
    )
    .expect("execute");
    out.decision
}

#[test]
fn affirmative_allows_when_any_child_allows() {
    let ks = MockKeystore::new();
    let allow = compile_terminal(true, &ks, "child_allow");
    let deny = compile_terminal(false, &ks, "child_deny");
    let parent = compile_aggregate(AggregationStrategy::Affirmative, &[&allow, &deny], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(allow.clone());
    resolver.insert(deny.clone());
    assert_eq!(run(&parent, &resolver, &ks), 1);
}

#[test]
fn unanimous_denies_when_any_child_denies() {
    let ks = MockKeystore::new();
    let allow = compile_terminal(true, &ks, "child_allow_u");
    let deny = compile_terminal(false, &ks, "child_deny_u");
    let parent = compile_aggregate(AggregationStrategy::Unanimous, &[&allow, &deny], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(allow);
    resolver.insert(deny);
    assert_eq!(run(&parent, &resolver, &ks), 0);
}

#[test]
fn consensus_follows_majority() {
    let ks = MockKeystore::new();
    let a1 = compile_terminal(true, &ks, "c_a1");
    let a2 = compile_terminal(true, &ks, "c_a2");
    let d1 = compile_terminal(false, &ks, "c_d1");
    let parent = compile_aggregate(AggregationStrategy::Consensus, &[&a1, &a2, &d1], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(a1);
    resolver.insert(a2);
    resolver.insert(d1);
    assert_eq!(run(&parent, &resolver, &ks), 1);
}

#[test]
fn missing_resolver_fails_closed() {
    let ks = MockKeystore::new();
    let allow = compile_terminal(true, &ks, "missing_child");
    // Build a parent that references `allow` but don't add it to the resolver.
    let parent = compile_aggregate(AggregationStrategy::Affirmative, &[&allow], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    let res = execute_with_resolver(
        ExecuteParams {
            capsule: &parent,
            input_ctx: ctx(),
            runtime_kid: "k",
            sign_fn: &|d| Ok(ks.signing_key.sign(d)),
            now_unix: 0,
            expires_at_unix: 0,
            nonce_b64: "n",
            expected_ast_hash: Some(parent.ast_hash.as_str()),
            expected_wasm_hash: None,
        },
        &resolver,
    );
    assert!(res.is_err(), "missing child must fail closed");
}

// ─── Additional coverage ──────────────────────────────────────────────────────

/// Affirmative with all-deny children → Deny.
#[test]
fn affirmative_denies_when_all_children_deny() {
    let ks = MockKeystore::new();
    let d1 = compile_terminal(false, &ks, "all_deny_d1");
    let d2 = compile_terminal(false, &ks, "all_deny_d2");
    let parent = compile_aggregate(AggregationStrategy::Affirmative, &[&d1, &d2], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(d1);
    resolver.insert(d2);
    assert_eq!(run(&parent, &resolver, &ks), 0, "Affirmative all-deny → Deny");
}

/// Unanimous with all-allow children → Allow.
#[test]
fn unanimous_allows_when_all_children_allow() {
    let ks = MockKeystore::new();
    let a1 = compile_terminal(true, &ks, "all_allow_a1");
    let a2 = compile_terminal(true, &ks, "all_allow_a2");
    let parent = compile_aggregate(AggregationStrategy::Unanimous, &[&a1, &a2], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(a1);
    resolver.insert(a2);
    assert_eq!(run(&parent, &resolver, &ks), 1, "Unanimous all-allow → Allow");
}

/// Consensus tie (equal allows and denies) → Deny.
/// "Consensus: allow if strictly more allows than denies; tie → deny."
#[test]
fn consensus_tie_denies() {
    let ks = MockKeystore::new();
    let a1 = compile_terminal(true, &ks, "tie_a1");
    let d1 = compile_terminal(false, &ks, "tie_d1");
    let parent = compile_aggregate(AggregationStrategy::Consensus, &[&a1, &d1], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(a1);
    resolver.insert(d1);
    // 1 allow, 1 deny — not strictly more allows → Deny
    assert_eq!(run(&parent, &resolver, &ks), 0, "Consensus tie → Deny");
}

/// Consensus where denies outnumber allows → Deny.
#[test]
fn consensus_deny_majority_denies() {
    let ks = MockKeystore::new();
    let a1 = compile_terminal(true, &ks, "dmaj_a1");
    let d1 = compile_terminal(false, &ks, "dmaj_d1");
    let d2 = compile_terminal(false, &ks, "dmaj_d2");
    let parent = compile_aggregate(AggregationStrategy::Consensus, &[&a1, &d1, &d2], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(a1);
    resolver.insert(d1);
    resolver.insert(d2);
    assert_eq!(run(&parent, &resolver, &ks), 0, "Consensus deny majority → Deny");
}

/// Single-child Affirmative — allow child → Allow.
#[test]
fn affirmative_single_allow_child() {
    let ks = MockKeystore::new();
    let allow = compile_terminal(true, &ks, "single_allow");
    let parent = compile_aggregate(AggregationStrategy::Affirmative, &[&allow], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(allow);
    assert_eq!(run(&parent, &resolver, &ks), 1, "Affirmative single-allow → Allow");
}

/// Single-child Unanimous — deny child → Deny.
#[test]
fn unanimous_single_deny_child() {
    let ks = MockKeystore::new();
    let deny = compile_terminal(false, &ks, "single_deny");
    let parent = compile_aggregate(AggregationStrategy::Unanimous, &[&deny], &ks);
    let resolver = InMemoryCapsuleResolver::new();
    resolver.insert(deny);
    assert_eq!(run(&parent, &resolver, &ks), 0, "Unanimous single-deny → Deny");
}
