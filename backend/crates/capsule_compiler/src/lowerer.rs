use crate::ast::{
    Comparator, Condition, ContextValue, FactorType, IdentityLevel, IdentitySource, Program, Step,
};
use anyhow::Result;
use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection, ImportSection,
    Instruction, MemArg, MemorySection, MemoryType, Module, TypeSection, ValType,
};

/// Normative Lowering Version
pub const LOWERING_VERSION: &str = "ei-aa-lower-wasm-v2";

/// Memory Offsets (Fixed Layout)
/// These constants define the WASM memory layout for EIAA capsules.
const MEM_OFFSET_INPUT: i32 = 0x0000;
const MEM_OFFSET_STATE: i32 = 0x1000;
const MEM_OFFSET_DECISION: i32 = 0x2000;
const MEM_OFFSET_SCRATCH: i32 = 0x3000;

/// Scratch-space allocator that hands out monotonically increasing offsets
/// starting at `MEM_OFFSET_SCRATCH`. Each string written to memory gets its
/// own non-overlapping region, preventing data clobber when multiple strings
/// are emitted in a single capsule (e.g. reason strings, verification types,
/// context keys across different steps).
struct ScratchAlloc {
    next: i32,
}

impl ScratchAlloc {
    fn new() -> Self {
        Self {
            next: MEM_OFFSET_SCRATCH,
        }
    }

    /// Reserve `size` bytes and return the start offset.
    fn alloc(&mut self, size: i32) -> i32 {
        let ptr = self.next;
        self.next += size;
        ptr
    }
}

pub fn lower(program: &Program) -> Result<Vec<u8>> {
    let mut module = Module::new();
    let mut scratch = ScratchAlloc::new();

    // 1. Types
    let mut types = TypeSection::new();
    // 0: verify_identity (i32) -> i64
    types.function([ValType::I32], [ValType::I64]);
    // 1: evaluate_risk (i32) -> i32
    types.function([ValType::I32], [ValType::I32]);
    // 2: require_factor (i32) -> i32
    types.function([ValType::I32], [ValType::I32]);
    // 3: authorize (i32, i32) -> i32
    types.function([ValType::I32, ValType::I32], [ValType::I32]);
    // 4: verify_verification (ptr, len) -> i32
    types.function([ValType::I32, ValType::I32], [ValType::I32]);
    // 5: get_assurance_level () -> i32
    types.function([], [ValType::I32]);
    // 6: get_context_value (ptr, len) -> i32
    types.function([ValType::I32, ValType::I32], [ValType::I32]);
    // 7: run() -> void (Entry point)
    types.function([], []);
    module.section(&types);

    // 2. Imports
    let mut imports = ImportSection::new();
    imports.import("host", "verify_identity", EntityType::Function(0));
    imports.import("host", "evaluate_risk", EntityType::Function(1));
    imports.import("host", "require_factor", EntityType::Function(2));
    imports.import("host", "authorize", EntityType::Function(3));
    imports.import("host", "verify_verification", EntityType::Function(4));
    imports.import("host", "get_assurance_level", EntityType::Function(5));
    imports.import("host", "get_context_value", EntityType::Function(6));
    module.section(&imports);

    // 3. Functions (Defines 'run')
    let mut functions = FunctionSection::new();
    functions.function(7); // Type index 7 is run() -> void
    module.section(&functions);

    // 4. Memory (1 page = 64KB, fixed)
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(1),
        memory64: false,
        shared: false,
    });
    module.section(&memories);

    // 5. Exports
    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 7); // Function index 7 (0-6 are imports)
    exports.export("memory", ExportKind::Memory, 0);
    module.section(&exports);

    // 6. Code (The Body of 'run')
    let mut codes = CodeSection::new();
    let mut func_body = Function::new(vec![
        (1, ValType::I64), // local 0: $subject_id
        (1, ValType::I32), // local 1: $risk_score
        (1, ValType::I32), // local 2: $authz_result
        (1, ValType::I32), // local 3: $halted
    ]);

    // Construct the logic
    // We wrap everything in a block $end so we can 'br $end' to exit
    func_body.instruction(&Instruction::Block(wasm_encoder::BlockType::Empty));

    // Initialize runtime state: Read input length from MEM_OFFSET_INPUT
    // This validates 入力 data was provided by the host
    func_body.instruction(&Instruction::I32Const(MEM_OFFSET_INPUT));
    func_body.instruction(&Instruction::I32Load(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));
    func_body.instruction(&Instruction::Drop); // Input length read but not used in basic flow

    // Initialize state region: Write marker to MEM_OFFSET_STATE to indicate execution started
    func_body.instruction(&Instruction::I32Const(MEM_OFFSET_STATE));
    func_body.instruction(&Instruction::I32Const(1)); // Execution started marker
    func_body.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));

    for step in &program.sequence {
        lower_step(step, &mut func_body, &mut scratch)?;

        // After each step, check if halted
        func_body.instruction(&Instruction::LocalGet(3)); // $halted
        func_body.instruction(&Instruction::I32Const(1));
        func_body.instruction(&Instruction::I32Eq);
        func_body.instruction(&Instruction::BrIf(0)); // br to $end
    }

    func_body.instruction(&Instruction::End); // End of main block

    // Decision output is written to memory by Allow/Deny/NeedInput steps
    // (via write_decision / write_decision_with_reason) before they set halted=1.
    // If we reach here without halting, no decision was written (implicit deny).

    func_body.instruction(&Instruction::End); // End function
    codes.function(&func_body);
    module.section(&codes);

    Ok(module.finish())
}

/// MEDIUM-EIAA-1 FIX: Encode IdentitySource as a stable integer ID.
///
/// The EIAA spec requires `verify_identity(src: i32)` where `src` identifies the
/// identity source. Previously this was always 0 (ignoring the source field).
/// Now we encode each variant as a stable, spec-defined integer:
///   Primary   = 0  (local credential store)
///   Federated = 1  (SSO/OIDC/SAML provider)
///   Device    = 2  (device-bound credential)
///   Biometric = 3  (biometric sensor)
fn identity_source_to_id(source: &IdentitySource) -> i32 {
    match source {
        IdentitySource::Primary => 0,
        IdentitySource::Federated => 1,
        IdentitySource::Device => 2,
        IdentitySource::Biometric => 3,
    }
}

/// MEDIUM-EIAA-2 FIX: Hash action/resource/context-key strings to stable i32 IDs.
///
/// Uses FNV-1a 32-bit (same algorithm as `profile_to_id`) for consistency.
/// The hash is masked to positive i32 range to avoid WASM sign issues.
fn string_to_stable_id(s: &str) -> i32 {
    if s.is_empty() {
        return 0;
    }
    // FNV-1a 32-bit
    let mut hash: u32 = 2166136261;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16777619);
    }
    // Mask to positive i32 range
    let id = (hash & 0x7fff_ffff) as i32;
    if id == 0 {
        1
    } else {
        id
    }
}

fn lower_step(step: &Step, func: &mut Function, scratch: &mut ScratchAlloc) -> anyhow::Result<()> {
    match step {
        Step::VerifyIdentity { source } => {
            // MEDIUM-EIAA-1 FIX: Pass the encoded identity source to verify_identity.
            // Previously always passed 0; now encodes the actual source variant.
            let src_id = identity_source_to_id(source);
            func.instruction(&Instruction::I32Const(src_id));
            func.instruction(&Instruction::Call(0)); // $verify_identity

            // Store subject in local 0 and leave on stack for check
            func.instruction(&Instruction::LocalTee(0)); // $subject_id

            // Check if subject_id == 0 (Guest)
            func.instruction(&Instruction::I64Const(0));
            func.instruction(&Instruction::I64Eq);

            // If Guest, return NeedInput("identity")
            func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            // Write Decision = 2 (NeedInput)
            // Write Context = "identity"
            write_decision_with_reason(func, 2, "identity", scratch);

            // Set halted to 1
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3)); // halted = 1

            // Return from the function
            func.instruction(&Instruction::Return);
            func.instruction(&Instruction::End);

            // Continue if Known Subject
        }
        Step::EvaluateRisk { profile } => {
            let profile_id = profile_to_id(profile);
            func.instruction(&Instruction::I32Const(profile_id));
            func.instruction(&Instruction::Call(1)); // $evaluate_risk
            func.instruction(&Instruction::LocalSet(1)); // $risk_score
        }
        Step::RequireFactor { factor_type } => {
            match factor_type {
                FactorType::Any(factors) => {
                    if factors.is_empty() {
                        func.instruction(&Instruction::I32Const(0)); // Fail closed
                    } else {
                        // Push first factor check onto stack
                        let f_id = match &factors[0] {
                            FactorType::Otp => 0,
                            FactorType::Passkey => 1,
                            FactorType::Biometric => 2,
                            FactorType::HardwareKey => 3,
                            FactorType::Password => 4,
                            _ => 0,
                        };
                        func.instruction(&Instruction::I32Const(f_id));
                        func.instruction(&Instruction::Call(2)); // $require_factor

                        // Push remaining factors and OR them
                        for f in &factors[1..] {
                            let f_id = match f {
                                FactorType::Otp => 0,
                                FactorType::Passkey => 1,
                                FactorType::Biometric => 2,
                                FactorType::HardwareKey => 3,
                                FactorType::Password => 4,
                                _ => 0,
                            };
                            func.instruction(&Instruction::I32Const(f_id));
                            func.instruction(&Instruction::Call(2)); // $require_factor
                            func.instruction(&Instruction::I32Or);
                        }
                    }
                }
                _ => {
                    let f_val = match factor_type {
                        FactorType::Otp => 0,
                        FactorType::Passkey => 1,
                        FactorType::Biometric => 2,
                        FactorType::HardwareKey => 3,
                        FactorType::Password => 4,
                        _ => 0,
                    };
                    func.instruction(&Instruction::I32Const(f_val));
                    func.instruction(&Instruction::Call(2)); // $require_factor
                }
            }

            // The stack now contains a value indicating satisfaction (1 or 0/multiple bits from OR)
            // Comparison with 1 is still valid as long as 1 is a bit in satisfied types
            // OR we just check if it's > 0.
            func.instruction(&Instruction::I32Const(0));
            func.instruction(&Instruction::I32GtS);

            func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            // Success: Do nothing (continue)
            func.instruction(&Instruction::Else);
            // Failure: Deny with specific reason
            let reason = match factor_type {
                FactorType::Password => "NEED_PASSWORD",
                FactorType::Otp => "NEED_OTP",
                FactorType::Passkey => "NEED_PASSKEY",
                FactorType::Biometric => "NEED_BIOMETRIC",
                FactorType::HardwareKey => "NEED_HARDWARE_KEY",
                FactorType::Any(_) => "NEED_MFA",
            };
            write_decision_with_reason(func, 0, reason, scratch);
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3));
            func.instruction(&Instruction::End);
        }
        Step::Conditional {
            condition,
            then_branch,
            else_branch,
        } => {
            lower_condition(condition, func, scratch); // Pushes i32 (0 or 1)
            func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            for s in then_branch {
                lower_step(s, func, scratch)?;
                check_halt(func);
            }
            if let Some(else_b) = else_branch {
                func.instruction(&Instruction::Else);
                for s in else_b {
                    lower_step(s, func, scratch)?;
                    check_halt(func);
                }
            }
            func.instruction(&Instruction::End);
        }
        Step::AuthorizeAction { action, resource } => {
            // MEDIUM-EIAA-2 FIX: Hash action and resource strings to stable i32 IDs.
            // This makes each AuthorizeAction step distinguishable by the runtime.
            let act_id = string_to_stable_id(action);
            let res_id = string_to_stable_id(resource);
            func.instruction(&Instruction::I32Const(act_id));
            func.instruction(&Instruction::I32Const(res_id));
            func.instruction(&Instruction::Call(3)); // $authorize
            func.instruction(&Instruction::LocalSet(2)); // $authz_result
        }
        Step::Allow(val) => {
            let decision = if *val { 1 } else { 0 }; // Should always be true for Allow node
            write_decision(func, decision);
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3)); // halted = 1
        }
        Step::Deny(_val) => {
            // Deny node? val is usually true.
            write_decision(func, 0);
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3)); // halted = 1
        }
        Step::CollectCredentials => {
            // MEDIUM-EIAA-4 FIX: Emit NeedInput (decision = 2) with reason
            // "collect_credentials" so the host knows to prompt for credential
            // collection during signup flows.
            //
            // Decision values: 1=Allow, 0=Deny, 2=NeedInput
            //
            // The capsule writes decision=2 to memory at 0x2000 and sets the
            // reason string to "collect_credentials" at 0x2020/0x2024.
            // The runtime reads this and returns NeedInput to the caller,
            // which triggers the signup credential collection UI.
            //
            // We also set halted=1 so the capsule stops executing after this
            // step — the flow will resume once credentials are collected.
            write_decision_with_reason(func, 2, "collect_credentials", scratch);
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3)); // halted = 1
        }
        Step::RequireVerification { verification_type } => {
            // EIAA: Check if verification is satisfied in context
            let (v_ptr, v_len) = write_string_data(func, verification_type, scratch);

            func.instruction(&Instruction::I32Const(v_ptr));
            func.instruction(&Instruction::I32Const(v_len));
            func.instruction(&Instruction::Call(4)); // $verify_verification
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::I32Eq);

            func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            // Success: Continue
            func.instruction(&Instruction::Else);
            write_decision(func, 0);
            func.instruction(&Instruction::I32Const(1));
            func.instruction(&Instruction::LocalSet(3));
            func.instruction(&Instruction::End);
        }
    }
    Ok(())
}

fn profile_to_id(profile: &str) -> i32 {
    if profile.eq_ignore_ascii_case("default") {
        return 0;
    }

    // FNV-1a 32-bit
    let mut hash: u32 = 2166136261;
    for b in profile.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16777619);
    }

    let id = (hash & 0x7fff_ffff) as i32;
    if id == 0 {
        1
    } else {
        id
    }
}

fn check_halt(func: &mut Function) {
    func.instruction(&Instruction::LocalGet(3));
    func.instruction(&Instruction::I32Const(1));
    func.instruction(&Instruction::I32Eq);
    // If halted, return from function immediately
    func.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
    func.instruction(&Instruction::Return);
    func.instruction(&Instruction::End);
}

fn lower_condition(cond: &Condition, func: &mut Function, scratch: &mut ScratchAlloc) {
    match cond {
        Condition::RiskScore { comparator, value } => {
            func.instruction(&Instruction::LocalGet(1)); // $risk_score
            if let Some(v) = value {
                func.instruction(&Instruction::I32Const(*v as i32));
            } else {
                func.instruction(&Instruction::I32Const(0));
            }
            apply_comparator(comparator, func);
        }
        Condition::AuthzResult { comparator, value } => {
            func.instruction(&Instruction::LocalGet(2)); // $authz_result
            if let Some(v) = value {
                func.instruction(&Instruction::I32Const(*v as i32));
            } else {
                func.instruction(&Instruction::I32Const(0));
            }
            apply_comparator(comparator, func);
        }
        Condition::IdentityLevel { comparator, level } => {
            // Call the dedicated get_assurance_level() host import (import 5)
            // which returns the session's actual NIST SP 800-63B AAL (0–3).
            //
            // Level encoding:
            //   Low    = 1  (AAL1: any verified identity)
            //   Medium = 2  (AAL2: multi-factor)
            //   High   = 3  (AAL3: hardware-bound)
            let level_val: i32 = match level {
                IdentityLevel::Low => 1,
                IdentityLevel::Medium => 2,
                IdentityLevel::High => 3,
            };
            func.instruction(&Instruction::Call(5)); // $get_assurance_level -> i32
            func.instruction(&Instruction::I32Const(level_val));
            apply_comparator(comparator, func);
        }
        Condition::Context {
            key,
            comparator,
            value,
        } => {
            // Call the dedicated get_context_value(key_ptr, key_len) host import
            // (import 6) which reads the key string from WASM memory and returns
            // its i32 value from the RuntimeContext.context_values map.
            let (key_ptr, key_len) = write_string_data(func, key, scratch);
            func.instruction(&Instruction::I32Const(key_ptr));
            func.instruction(&Instruction::I32Const(key_len));
            func.instruction(&Instruction::Call(6)); // $get_context_value -> i32
            let value_i32: i32 = match value {
                ContextValue::Integer(n) => *n as i32,
                ContextValue::String(s) => string_to_stable_id(s),
            };
            func.instruction(&Instruction::I32Const(value_i32));
            apply_comparator(comparator, func);
        }
    }
}

fn apply_comparator(comp: &Comparator, func: &mut Function) {
    match comp {
        Comparator::Gt => func.instruction(&Instruction::I32GtS),
        Comparator::Gte => func.instruction(&Instruction::I32GeS),
        Comparator::Lt => func.instruction(&Instruction::I32LtS),
        Comparator::Lte => func.instruction(&Instruction::I32LeS),
        Comparator::Eq => func.instruction(&Instruction::I32Eq),
    };
}

/// Helper to write decision AND reason
fn write_decision_with_reason(func: &mut Function, decision: i32, reason: &str, scratch: &mut ScratchAlloc) {
    write_decision(func, decision);

    // Write reason string to scratch space (unique offset per string)
    let (ptr, len) = write_string_data(func, reason, scratch);

    // Write Ptr/Len to 0x2020 / 0x2024
    // 0x2020 = Reason Ptr
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION + 32));
    func.instruction(&Instruction::I32Const(ptr));
    func.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));

    // 0x2024 = Reason Len
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION + 36));
    func.instruction(&Instruction::I32Const(len));
    func.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));
}

/// Writes current state to Memory (0x2000+)
fn write_decision(func: &mut Function, decision: i32) {
    // 0x2000 = decision
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION));
    func.instruction(&Instruction::I32Const(decision));
    func.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));

    // 0x2008 = subject_id (i64)
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION + 8));
    func.instruction(&Instruction::LocalGet(0));
    func.instruction(&Instruction::I64Store(wasm_encoder::MemArg {
        offset: 0,
        align: 3,
        memory_index: 0,
    }));

    // 0x2010 = risk_score
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION + 16));
    func.instruction(&Instruction::LocalGet(1));
    func.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));

    // 0x2014 = authz_result
    func.instruction(&Instruction::I32Const(MEM_OFFSET_DECISION + 20));
    func.instruction(&Instruction::LocalGet(2));
    func.instruction(&Instruction::I32Store(MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));
}

/// Helper to write string data to memory via instructions.
/// Uses the scratch allocator to assign a unique, non-overlapping offset for each
/// string, preventing data clobber when multiple strings are emitted in one capsule.
fn write_string_data(func: &mut Function, data: &str, scratch: &mut ScratchAlloc) -> (i32, i32) {
    let bytes = data.as_bytes();
    let offset = scratch.alloc(bytes.len() as i32);
    for (i, b) in bytes.iter().enumerate() {
        func.instruction(&Instruction::I32Const(offset + i as i32));
        func.instruction(&Instruction::I32Const(*b as i32));
        func.instruction(&Instruction::I32Store8(MemArg {
            offset: 0,
            align: 0,
            memory_index: 0,
        }));
    }
    (offset, bytes.len() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{IdentitySource, Step};

    #[test]
    fn test_lower_minimal_program() {
        let program = Program {
            version: "1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::Allow(true),
            ],
        };

        let wasm_bytes = lower(&program).expect("Failed to lower minimal program");

        // precise validation is complex without wasmparser, but we can check header
        assert!(wasm_bytes.len() > 8);
        assert_eq!(&wasm_bytes[0..4], b"\0asm"); // WASM Magic
        assert_eq!(&wasm_bytes[4..8], b"\x01\x00\x00\x00"); // Version 1
    }

    #[test]
    fn test_lower_conditional_program() {
        let program = Program {
            version: "1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
                    then_branch: vec![Step::Deny(true)],
                    else_branch: Some(vec![Step::Allow(true)]),
                },
            ],
        };

        let wasm_bytes = lower(&program).expect("Failed to lower conditional program");
        assert!(wasm_bytes.len() > 8);
        assert_eq!(&wasm_bytes[0..4], b"\0asm");
    }
}
