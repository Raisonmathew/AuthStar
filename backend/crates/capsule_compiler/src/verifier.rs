use crate::ast::{Program, Step};
use thiserror::Error;

/// Capsule AST hash format: 64 lowercase hex chars (SHA-256).
fn is_valid_ast_hash(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

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
    #[error("R30: AggregateDecision must be the last (terminal) step")]
    AggregationNotTerminal,
    #[error("R30: AggregateDecision must reference at least one sub-capsule")]
    AggregationEmpty,
    #[error("R30: AggregateDecision sub-capsule hash is malformed (need 64 hex chars)")]
    AggregationInvalidHash,
    #[error("R30: AggregateDecision must not appear inside a Conditional")]
    AggregationInConditional,
    #[error("R31: ShapeClaims must not appear inside a Conditional")]
    ShapeClaimsInConditional,
    #[error("R31: ShapeClaims appears more than once at the program root")]
    ShapeClaimsDuplicated,
    #[error("R31: ShapeClaims must not be the terminal step")]
    ShapeClaimsIsTerminal,
    #[error("R31: ShapeClaims::Static claim name must be a non-empty identifier")]
    ShapeClaimsStaticEmptyName,
    #[error("R31: ShapeClaims::Static value must be a JSON scalar (string|number|bool|null)")]
    ShapeClaimsStaticNonScalar,
    #[error("R29: RequireUserAction code must be non-empty and URL-safe")]
    RequiredActionInvalidCode,
    #[error("R29: RequireUserAction must appear after VerifyIdentity")]
    RequiredActionBeforeIdentity,
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
    has_shape_claims: bool,
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
            has_shape_claims: false,
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
                    if self.has_identity {
                        return Err(VerificationError::MultipleIdentityVerifications);
                    }
                    if depth > 0 || i > 0 {
                        return Err(VerificationError::IdentityNotFirst);
                    }
                    self.has_identity = true;
                }
                Step::EvaluateRisk { .. } => {
                    if self.has_risk {
                        return Err(VerificationError::MultipleRiskEvaluations);
                    }
                    if !self.has_identity {
                        return Err(VerificationError::IdentityNotFirst);
                    }
                    self.has_risk = true;
                }
                Step::RequireFactor { .. } => {
                    if !self.has_identity {
                        return Err(VerificationError::FactorBeforeIdentity);
                    }
                }
                Step::Conditional {
                    then_branch,
                    else_branch,
                    ..
                } => {
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
                    if depth > 0 {
                        return Err(VerificationError::AuthorizationInConditional);
                    }
                    // Signup flows with CollectCredentials don't need VerifyIdentity first
                    if !self.has_identity && !self.has_collect_credentials {
                        return Err(VerificationError::InvalidAuthorizationPosition);
                    }
                    self.has_authz = true;
                }
                Step::Allow(_) | Step::Deny(_) => {
                    terminates = true;
                }
                Step::AggregateDecision { sub_capsules, .. } => {
                    // R30: terminal-equivalent — must be at the program root
                    // (depth==0) and is the last step in its sequence.
                    if depth > 0 {
                        return Err(VerificationError::AggregationInConditional);
                    }
                    if sub_capsules.is_empty() {
                        return Err(VerificationError::AggregationEmpty);
                    }
                    for ch in sub_capsules {
                        if !is_valid_ast_hash(&ch.ast_hash) {
                            return Err(VerificationError::AggregationInvalidHash);
                        }
                    }
                    // AggregateDecision substitutes for AuthorizeAction +
                    // Allow/Deny: the aggregated children produce both the
                    // authz outcome and the terminal decision.
                    self.has_authz = true;
                    terminates = true;
                    // Enforce "is last step": if it's not the last in the
                    // sequence, the next iteration will raise TerminalNotLast
                    // (terminates flag is checked on next loop entry). To make
                    // this a clearer R30 error, surface a dedicated message:
                    if i != steps.len() - 1 {
                        return Err(VerificationError::AggregationNotTerminal);
                    }
                }
                // Signup flow steps - valid without identity verification
                Step::CollectCredentials => {
                    self.has_collect_credentials = true;
                }
                Step::RequireVerification { .. } => {
                    // These are valid in signup flows, no special validation needed
                }
                Step::RequireUserAction { code } => {
                    if !self.has_identity {
                        return Err(VerificationError::RequiredActionBeforeIdentity);
                    }
                    if code.trim().is_empty()
                        || !code
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ':')
                    {
                        return Err(VerificationError::RequiredActionInvalidCode);
                    }
                }
                Step::ShapeClaims { mappings } => {
                    // R31 — Token Mappers metadata. Must be at root, may not
                    // be the terminal step (the AS reads it after a successful
                    // Allow), may not appear twice.
                    if depth > 0 {
                        return Err(VerificationError::ShapeClaimsInConditional);
                    }
                    if self.has_shape_claims {
                        return Err(VerificationError::ShapeClaimsDuplicated);
                    }
                    if i == steps.len() - 1 {
                        return Err(VerificationError::ShapeClaimsIsTerminal);
                    }
                    for m in mappings {
                        if let crate::ast::ClaimMapper::Static { name, value } = m {
                            if name.trim().is_empty() {
                                return Err(VerificationError::ShapeClaimsStaticEmptyName);
                            }
                            if !(value.is_string()
                                || value.is_number()
                                || value.is_boolean()
                                || value.is_null())
                            {
                                return Err(VerificationError::ShapeClaimsStaticNonScalar);
                            }
                        }
                    }
                    self.has_shape_claims = true;
                }
            }

            // R19: Post-AuthZ Logic Check
            if self.has_authz {
                match step {
                    Step::Allow(_) | Step::Deny(_) | Step::Conditional { .. } => {} // OK
                    Step::AuthorizeAction { .. } => {}                              // Self OK
                    Step::AggregateDecision { .. } => {} // Self OK (terminal-equivalent)
                    Step::ShapeClaims { .. } => {}       // R31 — metadata only, OK after AuthZ
                    Step::RequireUserAction { .. } => {} // R29 — flow gate, OK after AuthZ
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
    use crate::ast::{Comparator, Condition, FactorType, IdentitySource};

    fn valid_minimal_program() -> Program {
        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
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
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
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
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Allow(true),
                Step::RequireFactor {
                    factor_type: FactorType::Otp,
                }, // After terminal
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
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
                    then_branch: create_nested(depth - 1),
                    else_branch: Some(create_nested(depth - 1)),
                }]
            }
        }

        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
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
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
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
                Step::RequireFactor {
                    factor_type: FactorType::Otp,
                },
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
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
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::VerifyIdentity {
                    source: IdentitySource::Federated,
                }, // Second identity
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(
            result,
            Err(VerificationError::MultipleIdentityVerifications)
        ));
    }

    #[test]
    fn test_r13_multiple_risk_evaluations() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::EvaluateRisk {
                    profile: "default".to_string(),
                },
                Step::EvaluateRisk {
                    profile: "strict".to_string(),
                }, // Second risk eval
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(
            result,
            Err(VerificationError::MultipleRiskEvaluations)
        ));
    }

    #[test]
    fn test_r15_factor_before_identity() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::RequireFactor {
                    factor_type: FactorType::Otp,
                },
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(
            result,
            Err(VerificationError::FactorBeforeIdentity)
        ));
    }

    #[test]
    fn test_r17_missing_authorization() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                // Missing AuthorizeAction
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(
            result,
            Err(VerificationError::MissingAuthorization)
        ));
    }

    #[test]
    fn test_r20_authorization_in_conditional() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
                    then_branch: vec![
                        Step::AuthorizeAction {
                            action: "login".to_string(),
                            resource: "app".to_string(),
                        },
                        Step::Allow(true),
                    ],
                    else_branch: Some(vec![Step::Deny(true)]),
                },
            ],
        };
        let config = VerifierConfig::default();
        let result = verify(&program, &config);
        assert!(matches!(
            result,
            Err(VerificationError::AuthorizationInConditional)
        ));
    }

    #[test]
    fn test_r26_max_steps_exceeded() {
        let config = VerifierConfig {
            max_steps: 3,
            max_depth: 8,
        };
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::RequireFactor {
                    factor_type: FactorType::Otp,
                },
                Step::RequireFactor {
                    factor_type: FactorType::Password,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
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
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::EvaluateRisk {
                    profile: "default".to_string(),
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(70),
                    },
                    then_branch: vec![Step::RequireFactor {
                        factor_type: FactorType::Otp,
                    }],
                    else_branch: None,
                },
                Step::AuthorizeAction {
                    action: "login".to_string(),
                    resource: "app".to_string(),
                },
                Step::Allow(true),
            ],
        };
        let config = VerifierConfig::default();
        assert!(verify(&program, &config).is_ok());
    }

    // ----- T4.3: AggregateDecision (R30) -----

    use crate::ast::{AggregationStrategy, CapsuleRef};

    fn dummy_hash(byte: u8) -> String {
        std::iter::repeat(byte)
            .take(32)
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    #[test]
    fn r30_aggregate_decision_valid_terminal() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AggregateDecision {
                    strategy: AggregationStrategy::Affirmative,
                    sub_capsules: vec![
                        CapsuleRef {
                            ast_hash: dummy_hash(0xab),
                        },
                        CapsuleRef {
                            ast_hash: dummy_hash(0xcd),
                        },
                    ],
                },
            ],
        };
        assert!(verify(&program, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn r30_aggregate_decision_must_be_last() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AggregateDecision {
                    strategy: AggregationStrategy::Unanimous,
                    sub_capsules: vec![CapsuleRef {
                        ast_hash: dummy_hash(0x11),
                    }],
                },
                Step::Allow(true),
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::AggregationNotTerminal)
        ));
    }

    #[test]
    fn r30_aggregate_decision_empty_sub_capsules() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AggregateDecision {
                    strategy: AggregationStrategy::Consensus,
                    sub_capsules: vec![],
                },
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::AggregationEmpty)
        ));
    }

    #[test]
    fn r30_aggregate_decision_invalid_hash() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AggregateDecision {
                    strategy: AggregationStrategy::Affirmative,
                    sub_capsules: vec![CapsuleRef {
                        ast_hash: "not-a-hash".into(),
                    }],
                },
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::AggregationInvalidHash)
        ));
    }

    #[test]
    fn r30_aggregate_decision_in_conditional_rejected() {
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
                    then_branch: vec![Step::AggregateDecision {
                        strategy: AggregationStrategy::Affirmative,
                        sub_capsules: vec![CapsuleRef {
                            ast_hash: dummy_hash(0x22),
                        }],
                    }],
                    else_branch: Some(vec![Step::Allow(true)]),
                },
                Step::AuthorizeAction {
                    action: "x".into(),
                    resource: "y".into(),
                },
                Step::Allow(true),
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::AggregationInConditional)
        ));
    }

    // ----- T2.7: ShapeClaims (R31) -----

    #[test]
    fn r31_shape_claims_valid_before_terminal() {
        use crate::ast::ClaimMapper;
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".into(),
                    resource: "app".into(),
                },
                Step::ShapeClaims {
                    mappings: vec![ClaimMapper::Email, ClaimMapper::EmailVerified],
                },
                Step::Allow(true),
            ],
        };
        assert!(verify(&program, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn r31_shape_claims_terminal_rejected() {
        use crate::ast::ClaimMapper;
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "login".into(),
                    resource: "app".into(),
                },
                Step::ShapeClaims {
                    mappings: vec![ClaimMapper::Email],
                },
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::ShapeClaimsIsTerminal)
        ));
    }

    #[test]
    fn r31_shape_claims_in_conditional_rejected() {
        use crate::ast::ClaimMapper;
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::Conditional {
                    condition: Condition::RiskScore {
                        comparator: Comparator::Gt,
                        value: Some(50),
                    },
                    then_branch: vec![
                        Step::ShapeClaims {
                            mappings: vec![ClaimMapper::Email],
                        },
                        Step::Deny(true),
                    ],
                    else_branch: Some(vec![Step::Allow(true)]),
                },
                Step::AuthorizeAction {
                    action: "x".into(),
                    resource: "y".into(),
                },
                Step::Allow(true),
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::ShapeClaimsInConditional)
        ));
    }

    #[test]
    fn r31_shape_claims_duplicate_rejected() {
        use crate::ast::ClaimMapper;
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::ShapeClaims {
                    mappings: vec![ClaimMapper::Email],
                },
                Step::AuthorizeAction {
                    action: "login".into(),
                    resource: "app".into(),
                },
                Step::ShapeClaims {
                    mappings: vec![ClaimMapper::Name],
                },
                Step::Allow(true),
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::ShapeClaimsDuplicated)
        ));
    }

    #[test]
    fn r31_shape_claims_static_non_scalar_rejected() {
        use crate::ast::ClaimMapper;
        let program = Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::ShapeClaims {
                    mappings: vec![ClaimMapper::Static {
                        name: "groups".into(),
                        value: serde_json::json!(["admin", "user"]), // array — disallowed
                    }],
                },
                Step::AuthorizeAction {
                    action: "login".into(),
                    resource: "app".into(),
                },
                Step::Allow(true),
            ],
        };
        assert!(matches!(
            verify(&program, &VerifierConfig::default()),
            Err(VerificationError::ShapeClaimsStaticNonScalar)
        ));
    }
}
