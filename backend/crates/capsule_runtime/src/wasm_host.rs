use anyhow::{anyhow, Result};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
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

    // ── Sprint G — SPIFFE workload identity ──────────────────────────────────

    /// How this principal's identity was established.  Values:
    ///   `""` or absent — normal session JWT (no override)
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

/// Per-execution WASM memory limiter.
///
/// Caps the total linear memory a single capsule execution may grow to.
/// Without this a malformed capsule could `memory.grow` up to Wasmtime's
/// default 4 GiB limit under concurrent load, OOM-killing the runtime pod.
///
/// 8 MiB is generous for any realistic policy capsule (typical capsules use
/// < 64 KiB). Adjust via `WASM_MEMORY_LIMIT_BYTES` env var.
struct MemoryLimiter {
    remaining: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        let delta = desired.saturating_sub(current);
        if delta > self.remaining {
            Ok(false) // deny the grow
        } else {
            self.remaining -= delta;
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// Default per-execution WASM heap cap: 8 MiB.
const DEFAULT_MEMORY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

fn memory_limit() -> usize {
    std::env::var("WASM_MEMORY_LIMIT_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_LIMIT_BYTES)
}

/// Shared runtime state: singleton engine, concurrent module cache, and a
/// pre-built linker that is cloned cheaply for each execution.
///
/// # Fix 1 — Concurrent module cache (replaces RwLock<LruModuleCache>)
///
/// The previous implementation used a hand-rolled LRU wrapped in a global
/// `RwLock`. Every cache *hit* took a *write* lock to update LRU order,
/// serialising all concurrent executions through one mutex. Under load this
/// became the dominant bottleneck.
///
/// `moka::sync::Cache` is a concurrent bounded LRU/LFU cache backed by
/// per-shard atomics. Reads never block writers and multiple threads can
/// look up different entries simultaneously. Eviction is amortised across
/// insertions — no per-hit write lock.
///
/// 512 entries × ~200 KiB average compiled module ≈ ~100 MiB max footprint.
/// Adjust via `WASM_MODULE_CACHE_CAP` env var.
///
/// # Fix 2 — Shared pre-built Linker
///
/// Previously a new `Linker` was constructed and all 12 host functions were
/// re-registered on every call to `execute()`. `Linker` construction is not
/// free — it allocates internal tables and copies function pointers on each
/// call. A `Linker` is designed to be built once and reused: `Linker::clone()`
/// is an `Arc` bump that shares the underlying function table.
///
/// The linker is built once in `EiaaRuntime::new()`, stored in an `Arc`, and
/// cloned (O(1)) per execution.
///
/// # Fix 4 — Epoch-based interruption (replaces consume_fuel)
///
/// `consume_fuel(true)` decrements a counter on *every WASM instruction* —
/// this adds measurable overhead per instruction for the sole purpose of
/// bounding execution time.
///
/// `epoch_interruption(true)` checks a shared atomic only at *safe points*
/// (loop back-edges and function calls) — far lower per-instruction overhead.
/// A background thread increments the epoch counter every
/// `WASM_EPOCH_TICK_MS` milliseconds; if the counter advances by
/// `WASM_EPOCH_DEADLINE` ticks during an execution the store is interrupted
/// with a trap. This is Wasmtime's recommended production timeout mechanism.
///
/// Defaults: tick every 1 ms, interrupt after 1 tick = 1 ms max per capsule.
/// Adjust via `WASM_EPOCH_TICK_MS` / `WASM_EPOCH_DEADLINE` env vars.
struct RuntimeState {
    engine: Engine,
    module_cache: Cache<String, Arc<Module>>,
    linker: Arc<Linker<RuntimeContext>>,
}

fn build_linker(engine: &Engine) -> Result<Linker<RuntimeContext>> {
    let mut linker = Linker::new(engine);

    // 0: verify_identity(src: i32) -> subject_id: i64
    linker.func_wrap(
        "host",
        "verify_identity",
        |caller: Caller<'_, RuntimeContext>, src: i32| -> i64 {
            if src == 4 {
                if caller.data().principal_source == "spiffe" {
                    caller.data().subject_id
                } else {
                    0
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
                None => return 0,
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
    linker.func_wrap(
        "host",
        "get_assurance_level",
        |caller: Caller<'_, RuntimeContext>| -> i32 { caller.data().assurance_level as i32 },
    )?;

    // 6: get_context_value(key_ptr: i32, key_len: i32) -> value: i32
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
            let key = String::from_utf8_lossy(&data[ptr as usize..end]).to_string();
            caller.data().context_values.get(&key).copied().unwrap_or(0)
        },
    )?;

    // 7: require_user_action(code_ptr: i32, code_len: i32) -> satisfied: i32
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
            let code = String::from_utf8_lossy(&data[ptr as usize..end]).to_string();
            if caller.data().required_actions.iter().any(|c| c == &code) {
                0
            } else {
                1
            }
        },
    )?;

    // 8: aggregate_decision(strategy, hashes_ptr, hashes_len) -> decision
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
            let hashes = String::from_utf8_lossy(&data[ptr as usize..end]);
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

    // 9: get_password_breach_count() -> count: i64
    linker.func_wrap(
        "host",
        "get_password_breach_count",
        |caller: Caller<'_, RuntimeContext>| -> i64 {
            caller.data().password_breach_count as i64
        },
    )?;

    Ok(linker)
}

/// Global singleton holding the engine, concurrent module cache, and pre-built linker.
static RUNTIME_STATE: std::sync::OnceLock<RuntimeState> = std::sync::OnceLock::new();

fn get_runtime_state() -> Result<&'static RuntimeState> {
    // OnceLock::get_or_try_init is unstable; use get_or_init with a Result
    // stored inside. Any initialisation error is surfaced on first use.
    static ERR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    if let Some(state) = RUNTIME_STATE.get() {
        return Ok(state);
    }

    // Build the engine with epoch interruption.
    let cap = std::env::var("WASM_MODULE_CACHE_CAP")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(512);

    let mut config = Config::new();
    // Fix 4: epoch_interruption has lower per-instruction overhead than
    // consume_fuel. A background thread ticks the epoch counter; each Store
    // sets a deadline of WASM_EPOCH_DEADLINE ticks (default 1).
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(|e| anyhow!("engine init: {e}"))?;

    // Start the epoch ticker background thread.
    // The thread runs for the lifetime of the process — it only holds an
    // Engine clone (cheap Arc bump) and sleeps between ticks.
    let tick_ms = std::env::var("WASM_EPOCH_TICK_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1);
    {
        let engine_tick = engine.clone();
        std::thread::Builder::new()
            .name("wasm-epoch-ticker".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(tick_ms));
                engine_tick.increment_epoch();
            })
            .map_err(|e| anyhow!("epoch ticker spawn: {e}"))?;
    }

    let linker = build_linker(&engine)?;

    let state = RuntimeState {
        module_cache: Cache::new(cap),
        linker: Arc::new(linker),
        engine,
    };

    // If two threads race here the second initialisation is discarded; the
    // winner's value is what get() returns for all future callers.
    let _ = RUNTIME_STATE.set(state);

    if let Some(err) = ERR.get() {
        return Err(anyhow!("{err}"));
    }

    RUNTIME_STATE.get().ok_or_else(|| anyhow!("runtime state init failed"))
}

pub struct EiaaRuntime;

impl EiaaRuntime {
    pub fn new() -> Result<Self> {
        // Eagerly initialise the global state (engine + cache + linker + epoch ticker).
        get_runtime_state()?;
        Ok(Self)
    }

    /// Returns true if the compiled module for `wasm_hash` is already in the
    /// concurrent cache. Used by `execute_inner` (lib.rs) to skip the SHA-256
    /// integrity check on cache hits — the hash was verified at first insertion.
    pub fn module_is_cached(&self, wasm_hash: &str) -> bool {
        get_runtime_state()
            .map(|s| s.module_cache.contains_key(wasm_hash))
            .unwrap_or(false)
    }

    pub fn execute(
        &self,
        wasm_bytes: &[u8],
        wasm_hash: &str,
        input_ctx: RuntimeContext,
    ) -> Result<DecisionOutput> {
        let state = get_runtime_state()?;

        // Fix 1: moka::sync::Cache concurrent lookup — no write lock on hit.
        let module: Arc<Module> = match state.module_cache.get(wasm_hash) {
            Some(m) => m,
            None => {
                let m = Arc::new(Module::new(&state.engine, wasm_bytes)?);
                state.module_cache.insert(wasm_hash.to_string(), m.clone());
                m
            }
        };

        // Fix 5: Embed the MemoryLimiter in the Store data via a newtype so
        // `store.limiter()` can return `&mut dyn ResourceLimiter` from Store data.
        // The linker was pre-built for `RuntimeContext`; we wrap the context in
        // `StoreData` which holds both the context and the limiter. The linker
        // closures access `caller.data().ctx` instead of `caller.data()` directly.
        // Because the linker was built for `RuntimeContext` (not `StoreData`),
        // we keep the execute Store typed as `RuntimeContext` — the limiter is
        // managed separately via a thread-local reset pattern that is safe because
        // `Store` is single-threaded and dropped within this function.
        //
        // The correct approach: store typed as RuntimeContext, limiter tracked via
        // a per-thread cell that is reset at the top of each execute() call.
        // This avoids changing the Linker type parameter (which is fixed at init).
        thread_local! {
            static EXEC_LIMITER: std::cell::RefCell<MemoryLimiter> =
                std::cell::RefCell::new(MemoryLimiter { remaining: DEFAULT_MEMORY_LIMIT_BYTES });
        }
        EXEC_LIMITER.with(|l| l.borrow_mut().remaining = memory_limit());

        let mut store = Store::new(&state.engine, input_ctx);
        store.limiter(|_ctx| {
            EXEC_LIMITER.with(|l| {
                // SAFETY: the ResourceLimiter callback is invoked synchronously
                // within the WASM execution on this same thread. The RefCell
                // borrow is released before any await point (there are none —
                // execute() is synchronous).
                unsafe { &mut *l.as_ptr() as &mut dyn ResourceLimiter }
            })
        });

        // Fix 4: epoch deadline — interrupt if epoch advances by this many ticks.
        //
        // Default: 50 ticks × 1ms tick = 50ms hard cap per capsule execution.
        // Generous enough for debug builds (unoptimised capsules take 2–5ms)
        // while still killing genuine infinite loops promptly. In production
        // (--release) capsules execute in <1ms so this is never reached in
        // normal operation. Override via WASM_EPOCH_DEADLINE env var.
        let deadline = std::env::var("WASM_EPOCH_DEADLINE")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(50);
        store.set_epoch_deadline(deadline);

        // Fix 2: clone the pre-built linker (O(1) Arc bump, no re-registration).
        let linker = (*state.linker).clone();

        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

        run.call(&mut store, ())?;

        // Read decision output from fixed memory offsets (EIAA memory contract).
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("Memory export missing"))?;

        let data = memory.data(&store);

        // 0x2000 = decision (i32)
        // 0x2008 = subject_id (i64)
        // 0x2010 = risk_score (i32)
        // 0x2014 = authz_result (i32)
        // 0x2020 = reason ptr (i32)
        // 0x2024 = reason len (i32)
        let decision = read_i32(data, 0x2000)?;
        let subject_id = read_i64(data, 0x2008)?;
        let risk_score = read_i32(data, 0x2010)?;
        let authz_result = read_i32(data, 0x2014)?;
        let reason_ptr = read_i32(data, 0x2020).unwrap_or(0) as usize;
        let reason_len = read_i32(data, 0x2024).unwrap_or(0) as usize;

        let reason = if reason_len > 0 && reason_ptr + reason_len <= data.len() {
            Some(String::from_utf8_lossy(&data[reason_ptr..reason_ptr + reason_len]).to_string())
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
