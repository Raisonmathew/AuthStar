use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasmtime::*;

/// Deserialize risk_score as i32, accepting both integer and floating-point JSON values.
/// The AuthorizationContext serializes risk_score as f64, but RuntimeContext needs i32.
fn deserialize_risk_score_lenient<'de, D>(deserializer: D) -> std::result::Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct RiskScoreVisitor;
    impl<'de> de::Visitor<'de> for RiskScoreVisitor {
        type Value = i32;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer or float")
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<i32, E> {
            Ok(v as i32)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<i32, E> {
            Ok(v as i32)
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<i32, E> {
            Ok(v as i32)
        }
    }
    deserializer.deserialize_any(RiskScoreVisitor)
}

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
    #[serde(default)]
    pub subject_id: i64,
    #[serde(default, deserialize_with = "deserialize_risk_score_lenient")]
    pub risk_score: i32,
    #[serde(default)]
    pub factors_satisfied: Vec<i32>, // List of factor types satisfied
    #[serde(default)]
    pub verifications_satisfied: Vec<String>, // List of verification types satisfied (e.g. "email")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_evidence: Option<serde_json::Value>, // Optional IdP evidence for SSO policies
    #[serde(default)]
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
    /// Named context values for WASM policy condition evaluation.
    /// Keys are context field names (e.g. "department", "clearance_level"),
    /// values are stable i32 IDs (strings are FNV-1a hashed by the caller).
    /// Used by the `get_context_value` host import.
    #[serde(default)]
    pub context_values: HashMap<String, i32>,
    /// Number of times the user's password appears in known data breaches (HIBP).
    /// 0 = not breached or HIBP unavailable. Populated after password verification.
    #[serde(default)]
    pub password_breach_count: u64,
    /// T1.2 — per-factor failed-attempt counters for the current user.
    /// Keys are stable factor names (`password`, `totp`, `webauthn`, ...),
    /// values are recent failure counts (currently 1h window from API server).
    #[serde(default)]
    pub credential_attempts: HashMap<String, i32>,
    /// T1.1 — required action codes still pending for the current subject.
    /// `require_user_action(code)` returns 0 when `code` is present here.
    #[serde(default)]
    pub required_actions: Vec<String>,
    /// T4.3 — pre-resolved sub-capsule decisions keyed by child AST hash.
    /// The runtime host import aggregates these values fail-closed. API/runtime
    /// service layers can populate this after resolving and executing children.
    #[serde(default)]
    pub sub_decisions: HashMap<String, i32>,

    // ── Sprint B — Agent context (all optional, backward-compatible) ──────────

    /// "agent" | "human" | "service" — matches Claims.session_type.
    /// Empty string / absent = treat as human (fail-open for existing sessions).
    #[serde(default)]
    pub principal_type: String,

    /// Stable agent identifier from the JWT `agent_id` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// LLM model identifier from the JWT `model_id` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,

    /// Task identifier from the JWT `task_id` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,

    /// Delegation chain from the JWT (ordered newest-first).
    #[serde(default)]
    pub delegation_chain: Vec<String>,

    /// Tool call context — populated by eiaa_authz from X-Tool-Name header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// SHA-256 of the JSON-serialised tool arguments (hex).
    /// Populated from X-Tool-Args-Hash header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_args_hash: Option<String>,

    /// Tools this agent token is permitted to call (from JWT `allowed_tools` claim).
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    // ── Sprint G — SPIFFE workload identity ──────────────────────────────────

    /// How this principal's identity was established.  Values:
    ///   `""` or absent — normal human/agent JWT (no override)
    ///   `"spiffe"` — validated SPIFFE JWT-SVID from `X-SPIFFE-SVID` header
    ///
    /// Populated by `eiaa_authz.rs` before the capsule executes.  Used by
    /// `verify_identity(src=4)` to confirm the workload presented a valid SVID.
    #[serde(default)]
    pub principal_source: String,
}

/// EIAA Decision Output (from Memory)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionOutput {
    pub decision: i32, // 1 = Allow, 0 = Deny
    pub subject_id: i64,
    pub risk_score: i32,
    pub authz_result: i32,
    pub reason: Option<String>,
}

pub struct EiaaRuntime {
    engine: Engine,
}

// LOW-4 FIX: Replace the unbounded global HashMap with a bounded LRU cache.
// The previous HashMap grew forever — every distinct wasm_hash key inserted was
// retained for the lifetime of the process. With per-agent, per-tool, per-tenant
// capsules, a large multi-tenant deployment would accumulate thousands of compiled
// Wasmtime `Module` objects. Cap at 512 entries; LRU eviction drops the
// least-recently-used compiled module when the limit is reached.
//
// 512 entries × ~200 KiB average compiled module ≈ ~100 MiB max footprint.
// Adjust `MODULE_CACHE_CAPACITY` via the env var `WASM_MODULE_CACHE_CAP` if needed.
const MODULE_CACHE_CAPACITY: usize = 512;

struct LruModuleCache {
    map: std::collections::HashMap<String, Module>,
    order: std::collections::VecDeque<String>,
    capacity: usize,
}

impl LruModuleCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: std::collections::HashMap::with_capacity(capacity + 1),
            order: std::collections::VecDeque::with_capacity(capacity + 1),
            capacity,
        }
    }

    fn get(&mut self, key: &str) -> Option<Module> {
        if self.map.contains_key(key) {
            // Move to back (most recently used)
            self.order.retain(|k| k != key);
            self.order.push_back(key.to_string());
            self.map.get(key).cloned()
        } else {
            None
        }
    }

    fn insert(&mut self, key: String, module: Module) {
        if self.map.contains_key(&key) {
            self.order.retain(|k| k != &key);
        } else if self.map.len() >= self.capacity {
            // Evict least recently used entry
            if let Some(lru_key) = self.order.pop_front() {
                self.map.remove(&lru_key);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, module);
    }
}

static MODULE_CACHE: std::sync::OnceLock<std::sync::RwLock<LruModuleCache>> =
    std::sync::OnceLock::new();

fn get_module_cache() -> &'static std::sync::RwLock<LruModuleCache> {
    let cap = std::env::var("WASM_MODULE_CACHE_CAP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MODULE_CACHE_CAPACITY);
    MODULE_CACHE.get_or_init(|| std::sync::RwLock::new(LruModuleCache::new(cap)))
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

        Ok(Self {
            engine: engine.clone(),
        })
    }

    pub fn execute(
        &self,
        wasm_bytes: &[u8],
        wasm_hash: &str,
        input_ctx: RuntimeContext,
    ) -> Result<DecisionOutput> {
        let module = {
            let mut cache = get_module_cache()
                .write()
                .map_err(|_| anyhow!("Module cache RwLock poisoned"))?;
            cache.get(wasm_hash)
        };

        let module = match module {
            Some(m) => m,
            None => {
                let m = Module::new(&self.engine, wasm_bytes)?;
                let mut cache = get_module_cache()
                    .write()
                    .map_err(|_| anyhow!("Module cache RwLock poisoned (write)"))?;
                cache.insert(wasm_hash.to_string(), m.clone());
                m
            }
        };

        let mut store = Store::new(&self.engine, input_ctx);

        // Add fuel (Limit execution)
        store.set_fuel(100_000)?;

        let mut linker = Linker::new(&self.engine);

        // 0: verify_identity(src: i32) -> subject_id: i64
        // src values: 0=Primary 1=Federated 2=Device 3=Biometric 4=Spiffe
        // Sprint G: src=4 requires principal_source == "spiffe"; returns 0 otherwise.
        linker.func_wrap(
            "host",
            "verify_identity",
            |caller: Caller<'_, RuntimeContext>, src: i32| -> i64 {
                if src == 4 {
                    // Spiffe: the middleware must have validated the JWT-SVID and
                    // set principal_source = "spiffe" before capsule execution.
                    if caller.data().principal_source == "spiffe" {
                        caller.data().subject_id
                    } else {
                        0 // SVID not validated — deny
                    }
                } else {
                    caller.data().subject_id
                }
            },
        )?;

        // 1: evaluate_risk(profile: i32) -> score: i32
        linker.func_wrap(
            "host",
            "evaluate_risk",
            |caller: Caller<'_, RuntimeContext>, _profile: i32| -> i32 { caller.data().risk_score },
        )?;

        // 2: require_factor(type: i32) -> satisfied: i32
        linker.func_wrap(
            "host",
            "require_factor",
            |caller: Caller<'_, RuntimeContext>, factor_type: i32| -> i32 {
                if caller.data().factors_satisfied.contains(&factor_type) {
                    1
                } else {
                    0
                }
            },
        )?;

        // 3: authorize(act: i32, res: i32) -> result: i32
        linker.func_wrap(
            "host",
            "authorize",
            |caller: Caller<'_, RuntimeContext>, _act: i32, _res: i32| -> i32 {
                caller.data().authz_decision
            },
        )?;

        // 4: verify_verification(type_ptr: i32, type_len: i32) -> satisfied: i32
        linker.func_wrap(
            "host",
            "verify_verification",
            |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0, // fail closed: verification not satisfied
                };
                let data = memory.data(&caller);
                let slice = &data[ptr as usize..(ptr + len) as usize];
                let v_type = String::from_utf8_lossy(slice).to_string();

                if caller.data().verifications_satisfied.contains(&v_type) {
                    1
                } else {
                    0
                }
            },
        )?;

        // 5: get_assurance_level() -> level: i32
        // Returns the session's NIST SP 800-63B AAL (0–3) so WASM policies
        // can enforce IdentityLevel conditions against the actual AAL rather
        // than inferring it from the subject_id.
        linker.func_wrap(
            "host",
            "get_assurance_level",
            |caller: Caller<'_, RuntimeContext>| -> i32 { caller.data().assurance_level as i32 },
        )?;

        // 6: get_context_value(key_ptr: i32, key_len: i32) -> value: i32
        // Reads a context field name from WASM memory and returns its i32 value
        // from the context_values map. Returns 0 if the key is not found.
        linker.func_wrap(
            "host",
            "get_context_value",
            |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                let data = memory.data(&caller);
                let end = (ptr + len) as usize;
                if end > data.len() {
                    return 0;
                }
                let slice = &data[ptr as usize..end];
                let key = String::from_utf8_lossy(slice).to_string();
                caller.data().context_values.get(&key).copied().unwrap_or(0)
            },
        )?;

        // 7: require_user_action(code_ptr: i32, code_len: i32) -> satisfied: i32
        // Returns 1 when the action is not pending; 0 means the capsule should
        // block the flow until the user completes it.
        linker.func_wrap(
            "host",
            "require_user_action",
            |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                let data = memory.data(&caller);
                let end = (ptr + len) as usize;
                if end > data.len() {
                    return 0;
                }
                let slice = &data[ptr as usize..end];
                let code = String::from_utf8_lossy(slice).to_string();
                if caller.data().required_actions.iter().any(|c| c == &code) {
                    0
                } else {
                    1
                }
            },
        )?;

        // 8: aggregate_decision(strategy, hashes_ptr, hashes_len) -> decision
        // strategy: 0=affirmative, 1=unanimous, 2=consensus. The hash payload
        // is newline-delimited. Missing child decisions fail closed.
        linker.func_wrap(
            "host",
            "aggregate_decision",
            |mut caller: Caller<'_, RuntimeContext>, strategy: i32, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                let data = memory.data(&caller);
                let end = (ptr + len) as usize;
                if end > data.len() {
                    return 0;
                }
                let slice = &data[ptr as usize..end];
                let hashes = String::from_utf8_lossy(slice);
                let mut allow = 0;
                let mut deny = 0;
                let mut total = 0;
                for hash in hashes.lines().filter(|h| !h.trim().is_empty()) {
                    total += 1;
                    match caller.data().sub_decisions.get(hash).copied() {
                        Some(1) => allow += 1,
                        Some(0) => deny += 1,
                        _ => return 0,
                    }
                }
                if total == 0 {
                    return 0;
                }
                match strategy {
                    0 => (allow > 0) as i32,
                    1 => (allow == total) as i32,
                    2 => (allow > deny) as i32,
                    _ => 0,
                }
            },
        )?;

        // Extra import kept for older/larger capsules that use the HIBP host
        // helper. Current lowerer does not emit this call, but retaining it is
        // harmless and preserves compatibility with previously generated WASM.
        // 9: get_password_breach_count() -> count: i64
        // Returns the number of times the user's password appears in known data
        // breaches (HIBP k-anonymity API). 0 = not breached or unavailable.
        linker.func_wrap(
            "host",
            "get_password_breach_count",
            |caller: Caller<'_, RuntimeContext>| -> i64 {
                caller.data().password_breach_count as i64
            },
        )?;

        // ── Sprint B — Agent host functions ──────────────────────────────────

        // 10: verify_agent_identity(model_id_ptr, model_id_len) -> i32
        // Returns 1 if context.model_id matches the expected model string; 0 otherwise.
        // Special case: if the expected model_id is empty ("") the capsule was compiled
        // without a model restriction — any model_id (including None) is accepted.
        linker.func_wrap(
            "host",
            "verify_agent_identity",
            |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                let data = memory.data(&caller);
                let end = (ptr + len) as usize;
                if end > data.len() {
                    return 0;
                }
                let expected = String::from_utf8_lossy(&data[ptr as usize..end]).to_string();
                // Empty expected = no model restriction (wildcard) — always pass.
                if expected.is_empty() {
                    return 1;
                }
                match caller.data().model_id.as_deref() {
                    Some(actual) => (actual == expected) as i32,
                    None => 0,
                }
            },
        )?;

        // 11: check_delegation_depth(max_depth: i32) -> i32
        // Returns 1 if delegation_chain.len() <= max_depth; 0 otherwise.
        linker.func_wrap(
            "host",
            "check_delegation_depth",
            |caller: Caller<'_, RuntimeContext>, max_depth: i32| -> i32 {
                let depth = caller.data().delegation_chain.len() as i32;
                (depth <= max_depth) as i32
            },
        )?;

        // 12: check_tool_permission(tool_ptr, tool_len) -> i32
        // Returns 1 if the tool name is present in context.allowed_tools (or
        // allowed_tools is empty = unrestricted); 0 otherwise.
        linker.func_wrap(
            "host",
            "check_tool_permission",
            |mut caller: Caller<'_, RuntimeContext>, ptr: i32, len: i32| -> i32 {
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                let data = memory.data(&caller);
                let end = (ptr + len) as usize;
                if end > data.len() {
                    return 0;
                }
                let tool = String::from_utf8_lossy(&data[ptr as usize..end]).to_string();
                let allowed = &caller.data().allowed_tools;
                if allowed.is_empty() {
                    // Empty list = no restriction (inherit from capsule policy)
                    1
                } else {
                    allowed.iter().any(|t| t == &tool) as i32
                }
            },
        )?;

        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

        // Execute
        run.call(&mut store, ())?;

        // Read Memory
        let memory = instance
            .get_memory(&mut store, "memory")
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
            let r_str =
                String::from_utf8_lossy(&data[reason_ptr..reason_ptr + reason_len]).to_string();
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
        return Err(anyhow!("Memory OOB read at {offset}"));
    }
    let slice = &mem[offset..offset + 4];
    Ok(i32::from_le_bytes(slice.try_into()?))
}

fn read_i64(mem: &[u8], offset: usize) -> Result<i64> {
    if offset + 8 > mem.len() {
        return Err(anyhow!("Memory OOB read at {offset}"));
    }
    let slice = &mem[offset..offset + 8];
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
            assurance_level: 0,
            verified_capabilities: vec![],
            context_values: HashMap::new(),
            password_breach_count: 0,
            credential_attempts: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            sub_decisions: std::collections::HashMap::new(),
            principal_type: String::new(),
            agent_id: None,
            model_id: None,
            task_id: None,
            delegation_chain: vec![],
            tool_name: None,
            tool_args_hash: None,
            allowed_tools: vec![],
            principal_source: String::new(),
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
            assurance_level: 0,
            verified_capabilities: vec![],
            context_values: HashMap::new(),
            password_breach_count: 0,
            credential_attempts: std::collections::HashMap::new(),
            required_actions: Vec::new(),
            sub_decisions: std::collections::HashMap::new(),
            principal_type: "agent".to_string(),
            agent_id: Some("agt_abc123".to_string()),
            model_id: Some("claude-3-5-sonnet-20241022".to_string()),
            task_id: Some("task_xyz".to_string()),
            delegation_chain: vec!["user_123".to_string()],
            tool_name: Some("send_email".to_string()),
            tool_args_hash: None,
            allowed_tools: vec!["send_email".to_string(), "read_calendar".to_string()],
            principal_source: String::new(),
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
