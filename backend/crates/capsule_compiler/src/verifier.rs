use crate::ast::{Step, Program};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("R1: Program sequence is empty")]
    EmptySequence,
    #[error("R4: Missing terminal Allow/Deny node")]
    MissingTerminal,
    #[error("R5: Terminal Allow/Deny must be the last node")]
    TerminalNotLast,
    #[error("R10: VerifyIdentity is missing")]
    MissingIdentityVerification,
    #[error("R11: VerifyIdentity must be the first node")]
    IdentityNotFirst,
    #[error("R12: Multiple VerifyIdentity nodes found")]
    MultipleIdentityVerifications,
    #[error("R13: EvaluateRisk appearing multiple times")]
    MultipleRiskEvaluations,
    #[error("R15: RequireFactor appearing before VerifyIdentity")]
    FactorBeforeIdentity,
    #[error("R17: AuthorizeAction is missing")]
    MissingAuthorization,
    #[error("R18: AuthorizeAction must be after VerifyIdentity/EvaluateRisk and before Terminal")]
    InvalidAuthorizationPosition,
    #[error("R20: AuthorizeAction found inside Conditional (Non-deterministic)")]
    AuthorizationInConditional,
    #[error("R26: Max step count exceeded")]
    MaxStepsExceeded,
    #[error("R9: Max conditional depth exceeded")]
    MaxDepthExceeded,
}

pub struct VerifierConfig {
    pub max_steps: usize,
    pub max_depth: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_steps: 128,
            max_depth: 8,
        }
    }
}

pub fn verify(program: &Program, config: &VerifierConfig) -> Result<(), VerificationError> {
    let mut ctx = VerificationContext::new(config);
    let root_terminates = ctx.visit_sequence(&program.sequence, 0)?;

    // Global checks after traversal
    if !root_terminates {
        return Err(VerificationError::MissingTerminal);
    }
    // Signup flows use CollectCredentials instead of VerifyIdentity
    if !ctx.has_identity && !ctx.has_collect_credentials {
        return Err(VerificationError::MissingIdentityVerification);
    }
    // Signup flows may not need AuthorizeAction if they just allow on credentials
    if !ctx.has_authz && !ctx.has_collect_credentials {
        return Err(VerificationError::MissingAuthorization);
    }

    Ok(())
}

struct VerificationContext<'a> {
    config: &'a VerifierConfig,
    step_count: usize,
    has_identity: bool,
    has_risk: bool,
    has_authz: bool,
    has_collect_credentials: bool,
}

impl<'a> VerificationContext<'a> {
    fn new(config: &'a VerifierConfig) -> Self {
        Self {
            config,
            step_count: 0,
            has_identity: false,
            has_risk: false,
            has_authz: false,
            has_collect_credentials: false,
        }
    }

    /// Returns true if the sequence unconditionally terminates (ends with Allow/Deny or all branches terminate)
    fn visit_sequence(&mut self, steps: &[Step], depth: usize) -> Result<bool, VerificationError> {
        if depth > self.config.max_depth {
            return Err(VerificationError::MaxDepthExceeded);
        }

        if steps.is_empty() {
             if depth == 0 {
                 return Err(VerificationError::EmptySequence);
             }
             return Ok(false);
        }

        let mut terminates = false;

        for (i, step) in steps.iter().enumerate() {
            self.step_count += 1;
            if self.step_count > self.config.max_steps {
                return Err(VerificationError::MaxStepsExceeded);
            }

            // R5: If previous step terminated, we shouldn't be here
            if terminates {
                return Err(VerificationError::TerminalNotLast);
            }

            match step {
                Step::VerifyIdentity { .. } => {
                    if self.has_identity { return Err(VerificationError::MultipleIdentityVerifications); }
                    if depth > 0 || i > 0 { return Err(VerificationError::IdentityNotFirst); }
                    self.has_identity = true;
                }
                Step::EvaluateRisk { .. } => {
                    if self.has_risk { return Err(VerificationError::MultipleRiskEvaluations); }
                    if !self.has_identity { return Err(VerificationError::IdentityNotFirst); }
                    self.has_risk = true;
                }
                Step::RequireFactor { .. } => {
                    if !self.has_identity { return Err(VerificationError::FactorBeforeIdentity); }
                }
                Step::Conditional { then_branch, else_branch, .. } => {
                    let then_terms = self.visit_sequence(then_branch, depth + 1)?;
                    let else_terms = if let Some(else_cmds) = else_branch {
                        self.visit_sequence(else_cmds, depth + 1)?
                    } else {
                        false
                    };
                    
                    // If both branches terminate, the Conditional step terminates.
                    if then_terms && else_terms {
                        terminates = true;
                    }
                }
                Step::AuthorizeAction { .. } => {
                    if depth > 0 { return Err(VerificationError::AuthorizationInConditional); }
                    // Signup flows with CollectCredentials don't need VerifyIdentity first
                    if !self.has_identity && !self.has_collect_credentials { return Err(VerificationError::InvalidAuthorizationPosition); }
                    self.has_authz = true;
                }
                Step::Allow(_) | Step::Deny(_) => {
                    terminates = true;
                }
                // Signup flow steps - valid without identity verification
                Step::CollectCredentials => {
                    self.has_collect_credentials = true;
                }
                Step::RequireVerification { .. } => {
                    // These are valid in signup flows, no special validation needed
                }
            }

            // R19: Post-AuthZ Logic Check
            if self.has_authz {
                match step {
                     Step::Allow(_) | Step::Deny(_) | Step::Conditional { .. } => {}, // OK
                     Step::AuthorizeAction { .. } => {}, // Self OK
                     _ => return Err(VerificationError::InvalidAuthorizationPosition),
                }
            }
        }
        
        Ok(terminates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{IdentitySource, FactorType, Condition, Comparator};

    fn valid_minimal_program() -> Program {
        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        }
    }

    #[test]
    fn test_valid_minimal_policy() {
        let program = valid_minimal_program();
        let config = VerifierConfig::default();
        assert!(verify(&program, &config).is_ok());
    }

    #[test]
    fn test_r1_empty_sequence() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::EmptySequence)));
    }

    #[test]
    fn test_r4_missing_terminal() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                // Missing Allow/Deny
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MissingTerminal)));
    }

    #[test]
    fn test_r5_terminal_not_last() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
                Step::RequireFactor { factor_type: FactorType::Otp }, // After terminal
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::TerminalNotLast)));
    }

    #[test]
    fn test_r9_max_depth_exceeded() {
        // Create deeply nested conditionals
        fn create_nested(depth: usize) -> Vec<Step> {
            if depth == 0 {
                vec![Step::Allow(true)]
            } else {
                vec![Step::Conditional {
                    condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(50) },
                    then_branch: create_nested(depth - 1),
                    else_branch: Some(create_nested(depth - 1)),
                }]
            }
        }

        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Conditional {
                    condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(50) },
                    then_branch: create_nested(10), // Exceeds max_depth of 8
                    else_branch: Some(vec![Step::Allow(true)]),
                },
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MaxDepthExceeded)));
    }

    #[test]
    fn test_r10_missing_identity() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        // AuthorizeAction before identity will trigger InvalidAuthorizationPosition
        assert!(result.is_err());
    }

    #[test]
    fn test_r11_identity_not_first() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::RequireFactor { factor_type: FactorType::Otp },
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        // RequireFactor before identity triggers FactorBeforeIdentity
        assert!(result.is_err());
    }

    #[test]
    fn test_r12_multiple_identity_verifications() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::VerifyIdentity { source: IdentitySource::Federated }, // Second identity
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MultipleIdentityVerifications)));
    }

    #[test]
    fn test_r13_multiple_risk_evaluations() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::EvaluateRisk { profile: "default".to_string() },
                Step::EvaluateRisk { profile: "strict".to_string() }, // Second risk eval
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MultipleRiskEvaluations)));
    }

    #[test]
    fn test_r15_factor_before_identity() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::RequireFactor { factor_type: FactorType::Otp },
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::FactorBeforeIdentity)));
    }

    #[test]
    fn test_r17_missing_authorization() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                // Missing AuthorizeAction
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MissingAuthorization)));
    }

    #[test]
    fn test_r20_authorization_in_conditional() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::Conditional {
                    condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(50) },
                    then_branch: vec![
                        Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                        Step::Allow(true),
                    ],
                    else_branch: Some(vec![Step::Deny(true)]),
                },
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::AuthorizationInConditional)));
    }

    #[test]
    fn test_r26_max_steps_exceeded() {
        let config = VerifierConfig { max_steps: 3, max_depth: 8 };
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::RequireFactor { factor_type: FactorType::Otp },
                Step::RequireFactor { factor_type: FactorType::Password },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let result = verify(&program, &config);
        assert!(matches!(result, Err(VerificationError::MaxStepsExceeded)));
    }

    #[test]
    fn test_valid_complex_policy_with_conditionals() {
        // Valid policy: RequireFactor must be BEFORE AuthorizeAction (R19)
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity { source: IdentitySource::Primary },
                Step::EvaluateRisk { profile: "default".to_string() },
                Step::Conditional {
                    condition: Condition::RiskScore { comparator: Comparator::Gt, value: Some(70) },
                    then_branch: vec![
                        Step::RequireFactor { factor_type: FactorType::Otp },
                    ],
                    else_branch: None,
                },
                Step::AuthorizeAction { action: "login".to_string(), resource: "app".to_string() },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        assert!(verify(&program, &config).is_ok());
    }
}
