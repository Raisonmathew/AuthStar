use anyhow::Result;
use capsule_runtime::{execute, DecisionOutput, RuntimeContext, encode_runtime_pk};
use capsule_compiler::{CapsuleSigned, CapsuleMeta}; // Mocking/Using struct directly
use ed25519_dalek::{SigningKey, Signer};
use keystore::{Keystore, KeyId};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// Helper: Create a signed capsule manually to allow tampering
fn create_test_capsule(
    wasm_bytes: Vec<u8>, 
    not_before: i64, 
    not_after: i64, 
    signer: &SigningKey
) -> CapsuleSigned {
    let mut hasher = Sha256::new();
    hasher.update(&wasm_bytes);
    let wasm_hash = hex::encode(hasher.finalize());

    let ast_hash = "mock_ast_hash".to_string(); 
    let ast_bytes = vec![]; // Not used by runtime, only verifiers

    let meta = CapsuleMeta {
        tenant_id: "test_tenant".to_string(),
        action: "test_action".to_string(),
        not_before_unix: not_before,
        not_after_unix: not_after,
        ast_hash_b64: URL_SAFE_NO_PAD.encode(ast_hash.as_bytes()),
    };

    let to_sign_struct = (&meta, &ast_hash, &wasm_hash, &wasm_bytes);
    let to_sign_bytes = bincode::serialize(&to_sign_struct).unwrap();
    
    let sig = signer.sign(&to_sign_bytes);
    let compiler_sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    
    // Key ID is arbitrary here, runtime just passes it through to attestation
    let compiler_kid = "test_key_id".to_string();

    CapsuleSigned {
        meta,
        ast_bytes,
        ast_hash,
        lowering_version: "1.0".to_string(),
        wasm_bytes,
        wasm_hash,
        compiler_kid,
        compiler_sig_b64,
    }
}

fn create_dummy_context() -> RuntimeContext {
    RuntimeContext {
        subject_id: 1,
        risk_score: 0,
        factors_satisfied: vec![],
        verifications_satisfied: vec![],
        auth_evidence: None,
        authz_decision: 1,
    }
}

// Dummy runtime signer
fn runtime_signer() -> (String, Box<dyn Fn(&[u8]) -> Result<ed25519_dalek::Signature>>) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key();
    let kid = encode_runtime_pk(&pk);
    
    let sign_fn = Box::new(move |msg: &[u8]| {
        Ok(sk.sign(msg))
    });
    
    (kid, sign_fn)
}

#[test]
fn test_integrity_hash_mismatch() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    
    // 1. Create valid capsule
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    let mut capsule = create_test_capsule(wasm.clone(), 0, 9999999999, &sk);

    // 2. Tamper with WASM bytes AFTER signing/hashing
    capsule.wasm_bytes.push(0x00); 

    // 3. Execute
    let (kid, sign_fn) = runtime_signer();
    let res = execute(
        &capsule, 
        create_dummy_context(), 
        &kid, 
        &sign_fn, 
        1000, 
        2000, 
        "nonce", 
        None, 
        None
    );

    // 4. Expect Error
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("WASM hash mismatch"));
}

#[test]
fn test_time_validity_future() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    
    // Valid from 2000 to 3000
    let capsule = create_test_capsule(wasm, 2000, 3000, &sk);

    let (kid, sign_fn) = runtime_signer();
    
    // Current time 1000 (Too early)
    let res = execute(
        &capsule, 
        create_dummy_context(), 
        &kid, 
        &sign_fn, 
        1000, 
        2000, 
        "nonce", 
        None, 
        None
    );

    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not valid at this time"));
}

#[test]
fn test_time_validity_expired() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    
    // Valid from 2000 to 3000
    let capsule = create_test_capsule(wasm, 2000, 3000, &sk);

    let (kid, sign_fn) = runtime_signer();
    
    // Current time 4000 (Too late)
    let res = execute(
        &capsule, 
        create_dummy_context(), 
        &kid, 
        &sign_fn, 
        4000, 
        5000, 
        "nonce", 
        None, 
        None
    );

    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not valid at this time"));
}

#[test]
#[ignore] // TODO: Investigate runtime crash on Windows with infinite loop
fn test_fuel_exhaustion() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    
    // Infinite loop WASM
    let wasm = wat::parse_str(r#"
        (module 
            (func (export "run") 
                (loop (br 0))
            )
        )
    "#).unwrap();
    
    let capsule = create_test_capsule(wasm, 0, 9999999999, &sk);
    let (kid, sign_fn) = runtime_signer();
    
    let res = execute(
        &capsule, 
        create_dummy_context(), 
        &kid, 
        &sign_fn, 
        1000, 
        2000, 
        "nonce", 
        None, 
        None
    );

    assert!(res.is_err());
    // Wasmtime returns specific error for fuel/traps usually
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("fuel") || err_msg.contains("limit"), "Expected fuel exhaustion, got: {}", err_msg);
}

#[test]
fn test_successful_execution() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    
    // Valid WASM that writes Output to memory
    // Structure: Decision(4) | Subject(8) | Risk(4) | Authz(4)
    // 0x2000: 1 (Allow)
    // 0x2008: 123 (Subject)
    // 0x2010: 50 (Risk)
    // 0x2014: 1 (AuthzResult)
    let wasm = wat::parse_str(r#"
        (module
            (memory (export "memory") 1)
            (func (export "run")
                (i32.store (i32.const 8192) (i32.const 1))      ;; 0x2000 Decision = 1
                (i64.store (i32.const 8200) (i64.const 123))    ;; 0x2008 SubjectID = 123
                (i32.store (i32.const 8208) (i32.const 50))     ;; 0x2010 Risk = 50
                (i32.store (i32.const 8212) (i32.const 1))      ;; 0x2014 Authz = 1
            )
        )
    "#).unwrap();
    
    let capsule = create_test_capsule(wasm, 0, 9999999999, &sk);
    let (kid, sign_fn) = runtime_signer();
    
    let (output, _att) = execute(
        &capsule, 
        create_dummy_context(), 
        &kid, 
        &sign_fn, 
        1000, 
        2000, 
        "nonce", 
        None, 
        None
    ).expect("Execution failed");

    assert_eq!(output.decision, 1);
    assert_eq!(output.subject_id, 123);
    assert_eq!(output.risk_score, 50);
}
