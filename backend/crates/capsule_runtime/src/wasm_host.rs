use anyhow::{anyhow, Result};
use wasmtime::*;
use serde::{Serialize, Deserialize};

/// EIAA Runtime Context (Inputs from the Broker/Simulation)
///
/// ## HIGH-EIAA-2 FIX: Add `assurance_level` and `verified_capabilities`
///
/// These fields carry the session's NIST SP 800-63B Authentication Assurance Level
/// and the list of capabilities verified during the login flow. They are populated
/// by `eiaa_authz.rs` from the `sessions` table (columns added by migration 032)
/// and passed to the capsule runtime so WASM policies can enforce AAL requirements.
///
/// The `assurance_level` is an integer (0–3) matching the `aal_level` column:
///   0 = AAL0 (unauthenticated / guest)
///   1 = AAL1 (single factor: password or passkey)
///   2 = AAL2 (multi-factor: password + OTP, or passkey + biometric)
///   3 = AAL3 (hardware-bound: FIDO2 hardware key)
///
/// The `verified_capabilities` is a list of capability strings (e.g. ["mfa:totp",
/// "passkey", "email_verified"]) that were satisfied during the login flow.
///
/// Both fields are `#[serde(default)]` for backward compatibility with callers that
/// do not yet populate them (they default to 0 / empty vec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeContext {
    pub subject_id: i64,
    pub risk_score: i32,
    pub factors_satisfied: Vec<i32>, // List of factor types satisfied
    #[serde(default)]
    pub verifications_satisfied: Vec<String>, // List of verification types satisfied (e.g. "email")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_evidence: Option<serde_json::Value>, // Optional IdP evidence for SSO policies
    pub authz_decision: i32, // 1 = Allow, 0 = Deny (from policy engine)
    /// NIST SP 800-63B Authentication Assurance Level (0–3).
    /// Populated from sessions.aal_level by eiaa_authz.rs (migration 032).
    ///
    /// HIGH-EIAA-2 FIX: The `alias = "achieved_aal"` bridges the field name mismatch
    /// between `AuthorizationContext` (which serializes this as `"achieved_aal"`) and
    /// `RuntimeContext` (which uses `"assurance_level"`). Without the alias, serde would
    /// silently default to 0 when deserializing an `AuthorizationContext` JSON payload,
    /// making AAL-aware policies always see AAL0 regardless of the session's actual level.
    #[serde(default, alias = "achieved_aal")]
    pub assurance_level: u8,
    /// Capability strings verified during the login flow.
    /// Populated from sessions.verified_capabilities by eiaa_authz.rs (migration 032).
    #[serde(default)]
    pub verified_capabilities: Vec<String>,
}

/// EIAA Decision Output (from Memory)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionOutput {
    pub decision: i32,      // 1 = Allow, 0 = Deny
    pub subject_id: i64,
    pub risk_score: i32,
    pub authz_result: i32,
    pub reason: Option<String>,
}

pub struct EiaaRuntime {
    engine: Engine,
}

impl EiaaRuntime {
    pub fn new() -> Result<Self> {
        static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
        
        let engine = ENGINE.get_or_init(|| {
            let mut config = Config::new();
            config.consume_fuel(true); // Deterministic execution limits
            // config.epoch_interruption(true); // For timeouts
            Engine::new(&config).expect("Failed to initialize WASM engine")
        });
        
        Ok(Self { engine: engine.clone() })
    }

    pub fn execute(
        &self,
        wasm_bytes: &[u8],
        input_ctx: RuntimeContext,
    ) -> Result<DecisionOutput> {
        let module = Module::new(&self.engine, wasm_bytes)?;
        let mut store = Store::new(&self.engine, input_ctx);
        
        // Add fuel (Limit execution)
        store.set_fuel(100_000)?; 

        let mut linker = Linker::new(&self.engine);
        
        // 0: verify_identity(src: i32) -> subject_id: i64
        linker.func_wrap("host", "verify_identity", |caller: Caller<'_, RuntimeContext>, _src: i32| -> i64 {
            // In real system, we might check _src vs allowed sources.
            // For now, return the context's subject_id
            caller.data().subject_id
        })?;

        // 1: evaluate_risk(profile: i32) -> score: i32
        linker.func_wrap("host", "evaluate_risk", |caller: Caller<'_, RuntimeContext>, _profile: i32| -> i32 {
            caller.data().risk_score
        })?;

        // 2: require_factor(type: i32) -> satisfied: i32
        linker.func_wrap("host", "require_factor", |caller: Caller<'_, RuntimeContext>, factor_type: i32| -> i32 {
            if caller.data().factors_satisfied.contains(&factor_type) { 1 } else { 0 }
        })?;

        // 3: authorize(act: i32, res: i32) -> result: i32
        linker.func_wrap("host", "authorize", |caller: Caller<'_, RuntimeContext>, _act: i32, _res: i32| -> i32 {
            caller.data().authz_decision
        })?;

        // 4: verify_verification(type_ptr: i32, type_len: i32) -> satisfied: i32
        linker.func_wrap("host", "verify_verification", |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
            let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
            let data = memory.data(&caller);
            let slice = &data[ptr as usize..(ptr + len) as usize];
            let v_type = String::from_utf8_lossy(slice).to_string();
            
            if caller.data().verifications_satisfied.contains(&v_type) { 1 } else { 0 }
        })?;

        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
        
        // Execute
        run.call(&mut store, ())?;

        // Read Memory
        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("Memory export missing"))?;

        let data = memory.data(&store);
        
        // Spec 6. Decision Output Contract
        // 0x2000 = decision (i32)
        // 0x2008 = subject_id (i64)
        // 0x2010 = risk_score (i32)
        // 0x2014 = authz_result (i32)

        let decision = read_i32(data, 0x2000)?;
        let subject_id = read_i64(data, 0x2008)?;
        let risk_score = read_i32(data, 0x2010)?;
        let authz_result = read_i32(data, 0x2014)?;

        // 0x2020 = Reason Ptr
        // 0x2024 = Reason Len
        let reason_ptr = read_i32(data, 0x2020).unwrap_or(0) as usize;
        let reason_len = read_i32(data, 0x2024).unwrap_or(0) as usize;
        
        let reason = if reason_len > 0 && reason_ptr + reason_len <= data.len() {
             let r_str = String::from_utf8_lossy(&data[reason_ptr..reason_ptr+reason_len]).to_string();
             Some(r_str)
        } else {
             None
        };

        Ok(DecisionOutput {
            decision,
            subject_id,
            risk_score,
            authz_result,
            reason,
        })
    }
}

fn read_i32(mem: &[u8], offset: usize) -> Result<i32> {
    if offset + 4 > mem.len() {
        return Err(anyhow!("Memory OOB read at {}", offset));
    }
    let slice = &mem[offset..offset+4];
    Ok(i32::from_le_bytes(slice.try_into()?))
}

fn read_i64(mem: &[u8], offset: usize) -> Result<i64> {
    if offset + 8 > mem.len() {
        return Err(anyhow!("Memory OOB read at {}", offset));
    }
    let slice = &mem[offset..offset+8];
    Ok(i64::from_le_bytes(slice.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_context_serialization() {
        let ctx = RuntimeContext {
            subject_id: 12345,
            risk_score: 75,
            factors_satisfied: vec![1, 2],
            verifications_satisfied: vec![],
            auth_evidence: None,
            authz_decision: 1,
        };
        
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: RuntimeContext = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.subject_id, 12345);
        assert_eq!(parsed.risk_score, 75);
        assert_eq!(parsed.factors_satisfied, vec![1, 2]);
        assert_eq!(parsed.authz_decision, 1);
    }

    #[test]
    fn test_decision_output_serialization() {
        let output = DecisionOutput {
            decision: 1,
            subject_id: 67890,
            risk_score: 50,
            authz_result: 1,
            reason: None,
        };
        
        let json = serde_json::to_string(&output).unwrap();
        let parsed: DecisionOutput = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed, output);
    }

    #[test]
    fn test_decision_output_equality() {
        let output1 = DecisionOutput {
            decision: 1,
            subject_id: 123,
            risk_score: 50,
            authz_result: 1,
            reason: None,
        };
        let output2 = DecisionOutput {
            decision: 1,
            subject_id: 123,
            risk_score: 50,
            authz_result: 1,
            reason: None,
        };
        let output3 = DecisionOutput {
            decision: 0, // Different
            subject_id: 123,
            risk_score: 50,
            authz_result: 1,
            reason: None,
        };
        
        assert_eq!(output1, output2);
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_read_i32_valid() {
        // Little-endian bytes for i32 value 0x12345678
        let mem: [u8; 8] = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        
        let result = read_i32(&mem, 0).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_read_i32_negative() {
        // Little-endian bytes for i32 value -1 (0xFFFFFFFF)
        let mem: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        
        let result = read_i32(&mem, 0).unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn test_read_i32_oob() {
        let mem: [u8; 3] = [0x00, 0x00, 0x00]; // Only 3 bytes, need 4
        
        let result = read_i32(&mem, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_i32_offset() {
        let mem: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12];
        
        let result = read_i32(&mem, 4).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_read_i64_valid() {
        // Little-endian bytes for i64 value 0x123456789ABCDEF0
        let mem: [u8; 8] = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        
        let result = read_i64(&mem, 0).unwrap();
        assert_eq!(result, 0x123456789ABCDEF0u64 as i64);
    }

    #[test]
    fn test_read_i64_negative() {
        // Little-endian bytes for i64 value -1 (0xFFFFFFFFFFFFFFFF)
        let mem: [u8; 8] = [0xFF; 8];
        
        let result = read_i64(&mem, 0).unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn test_read_i64_oob() {
        let mem: [u8; 7] = [0x00; 7]; // Only 7 bytes, need 8
        
        let result = read_i64(&mem, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_eiaa_runtime_creation() {
        // Test that EiaaRuntime can be created without error
        let result = EiaaRuntime::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_runtime_context_clone() {
        let ctx = RuntimeContext {
            subject_id: 999,
            risk_score: 80,
            factors_satisfied: vec![1, 3, 5],
            verifications_satisfied: vec![],
            auth_evidence: None,
            authz_decision: 0,
        };
        
        let cloned = ctx.clone();
        
        assert_eq!(cloned.subject_id, 999);
        assert_eq!(cloned.risk_score, 80);
        assert_eq!(cloned.factors_satisfied, vec![1, 3, 5]);
        assert_eq!(cloned.authz_decision, 0);
    }

    #[test]
    fn test_runtime_context_deserialization_from_json() {
        let json = r#"{
            "subject_id": 42,
            "risk_score": 100,
            "factors_satisfied": [1, 2, 3],
            "authz_decision": 1
        }"#;
        
        let ctx: RuntimeContext = serde_json::from_str(json).unwrap();
        
        assert_eq!(ctx.subject_id, 42);
        assert_eq!(ctx.risk_score, 100);
        assert_eq!(ctx.factors_satisfied, vec![1, 2, 3]);
        assert_eq!(ctx.authz_decision, 1);
    }
}
