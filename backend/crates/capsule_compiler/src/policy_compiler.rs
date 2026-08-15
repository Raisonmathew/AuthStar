//! Policy Compiler Module
//!
//! EIAA Single Authority: Login methods configuration is COMPILED into AST.
//! The flow engine only reads the compiled AST, never the raw config.

use crate::ast::{
    Comparator, Condition, FactorType, IdentitySource, Program, Step,
};
use serde::{Deserialize, Serialize};

/// Login methods configuration from Admin Console
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginMethodsConfig {
    pub email_password: bool,
    pub passkey: bool,
    pub sso: bool,
    pub mfa: MfaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub required: bool,
    pub methods: Vec<String>, // ["totp", "passkey"]
}

impl Default for LoginMethodsConfig {
    fn default() -> Self {
        Self {
            email_password: true,
            passkey: false,
            sso: false,
            mfa: MfaConfig {
                required: false,
                methods: vec!["totp".to_string()],
            },
        }
    }
}

/// EIAA Policy Compiler - Single Authority
///
/// Compiles login methods configuration into a canonical policy AST.
/// This is the ONLY source of truth for the flow engine.
pub struct PolicyCompiler;

impl PolicyCompiler {
    /// Compile login methods into authentication policy AST
    ///
    /// This function is called when:
    /// 1. Admin updates login methods in Admin Console
    /// 2. Org is first created (default policy)
    ///
    /// ## HIGH-EIAA-1 FIX: VerifyIdentity must always be the first step
    ///
    /// EIAA verifier rule R11 requires `VerifyIdentity` to be the first node in any
    /// authentication policy. Rule R15 requires `RequireFactor` to appear AFTER
    /// `VerifyIdentity`. The previous implementation omitted `VerifyIdentity` for
    /// passkey-only and passkey+password flows, causing the verifier to reject the
    /// compiled AST with `FactorBeforeIdentity`.
    ///
    /// Fix: Always emit `VerifyIdentity { source: Primary }` as the first step.
    /// For passkey flows, the identity source is still `Primary` — the passkey IS
    /// the identity verification mechanism (it proves possession of the registered
    /// credential bound to the user's identity). The `RequireFactor { Passkey }`
    /// step then verifies the cryptographic assertion.
    pub fn compile_auth_policy(config: &LoginMethodsConfig) -> Program {
        let mut steps = vec![];

        // Step 1: VerifyIdentity MUST always be first (EIAA R11).
        // For all login methods, identity is verified against the primary source.
        // The specific authentication mechanism is enforced by RequireFactor below.
        steps.push(Step::VerifyIdentity {
            source: IdentitySource::Primary,
        });

        // Step 2: Determine primary authentication factor
        if config.passkey && config.email_password {
            // Allow choice between passkey and password
            steps.push(Step::RequireFactor {
                factor_type: FactorType::Any(vec![FactorType::Passkey, FactorType::Password]),
            });
        } else if config.passkey {
            // Passkey-only (passwordless)
            steps.push(Step::RequireFactor {
                factor_type: FactorType::Passkey,
            });
        } else {
            // Password (default)
            steps.push(Step::RequireFactor {
                factor_type: FactorType::Password,
            });
        }

        // Step 2: MFA if required
        if config.mfa.required {
            let mfa_factors: Vec<FactorType> = config
                .mfa
                .methods
                .iter()
                .filter_map(|m| match m.as_str() {
                    "totp" => Some(FactorType::Otp),
                    "passkey" => Some(FactorType::Passkey),
                    _ => None,
                })
                .collect();

            if !mfa_factors.is_empty() {
                steps.push(Step::RequireFactor {
                    factor_type: FactorType::Any(mfa_factors),
                });
            }
        }

        // Step 3: Authorize Action
        steps.push(Step::AuthorizeAction {
            action: "auth:login".to_string(),
            resource: "app".to_string(),
        });

        // Step 4: Allow if all factors satisfied
        steps.push(Step::Allow(true));

        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: steps,
        }
    }

    /// Compile signup policy AST
    pub fn compile_signup_policy(require_email_verification: bool) -> Program {
        let mut steps = vec![];

        // Collect credentials
        steps.push(Step::CollectCredentials);

        // Optional email verification
        if require_email_verification {
            steps.push(Step::RequireVerification {
                verification_type: "email".to_string(),
            });
        }

        // Allow identity creation
        steps.push(Step::AuthorizeAction {
            action: "auth:signup".to_string(),
            resource: "app".to_string(),
        });
        steps.push(Step::Allow(true));

        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: steps,
        }
    }
}

/// Sprint B.5 — Agent scope policy template configuration.
///
/// Controls the parameters baked into the `agent_scope_default` compiled AST.
/// A tenant admin provides this when provisioning an agent principal so that
/// the compiled capsule reflects that agent's risk tolerance and tool list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentScopeConfig {
    /// The LLM model ID the capsule will enforce (e.g. `"claude-3-5-sonnet-20241022"`).
    pub model_id: String,
    /// Maximum delegation chain depth (default 2).
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,
    /// Risk score (0–100) above which the agent action is automatically denied.
    /// Default 60 — matches the `agent_default` risk profile gate in the plan.
    #[serde(default = "default_risk_deny_threshold")]
    pub risk_deny_threshold: i64,
    /// EIAA action string authorised by this capsule (e.g. `"agent:billing:read"`).
    pub action: String,
    /// Resource the action is authorised against (e.g. `"billing"`).
    #[serde(default = "default_resource")]
    pub resource: String,
}

fn default_max_depth() -> u8 {
    2
}

fn default_risk_deny_threshold() -> i64 {
    60
}

fn default_resource() -> String {
    "agent_resource".to_string()
}

impl PolicyCompiler {
    /// Compile the `agent_scope_default` built-in policy template (Sprint B.5).
    ///
    /// This is the canonical AST that gets compiled to WASM for agent tool-call
    /// authorization. It encodes the plan's `agent_scope_default` JSON template
    /// directly in Rust so it cannot drift from the verifier rules.
    ///
    /// Generated sequence:
    /// 1. `verify_agent_identity(model_id)` — reject wrong model
    /// 2. `check_delegation_chain(max_depth, require_human_origin=true)` — cap depth
    /// 3. `evaluate_risk("agent_default")` — populate risk score
    /// 4. `if risk > threshold → deny; else → check_tool_permission + if authz → allow`
    ///
    /// The produced `Program` passes all EIAA verifier rules and can be passed
    /// directly to `capsule_compiler::compile()`.
    pub fn compile_agent_scope_policy(config: &AgentScopeConfig) -> Program {
        // Inner allow/deny after tool permission check
        let inner_allow_branch = vec![Step::Allow(true)];
        let inner_deny_branch = vec![Step::Deny(true)];

        // check_tool_permission succeeded → if authz_result == 1 → allow else deny
        let post_tool_check = vec![
            Step::AuthorizeToolCall {
                tool_name: config.action.clone(),
                resource_pattern: None,
                require_user_confirmation: false,
            },
            Step::Conditional {
                condition: Condition::AuthzResult {
                    comparator: Comparator::Eq,
                    value: Some(1),
                },
                then_branch: inner_allow_branch,
                else_branch: Some(inner_deny_branch),
            },
        ];

        // risk > threshold → deny; else → tool path
        let risk_gate = Step::Conditional {
            condition: Condition::RiskScore {
                comparator: Comparator::Gt,
                value: Some(config.risk_deny_threshold),
            },
            then_branch: vec![Step::Deny(true)],
            else_branch: Some(post_tool_check),
        };

        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                // Step 1: Verify registered AI agent identity
                Step::VerifyAgentIdentity {
                    model_id: config.model_id.clone(),
                    model_version: None,
                },
                // Step 2: Enforce delegation chain depth + human origin
                Step::CheckDelegationChain {
                    max_depth: config.max_depth,
                    require_human_origin: true,
                },
                // Step 3: Evaluate risk against the agent_default profile
                Step::EvaluateRisk {
                    profile: "agent_default".to_string(),
                },
                // Step 4: Risk gate → tool permission → allow/deny
                risk_gate,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{verify, VerifierConfig};

    #[test]
    fn test_compile_agent_scope_policy_passes_verifier() {
        let config = AgentScopeConfig {
            model_id: "claude-3-5-sonnet-20241022".to_string(),
            max_depth: 2,
            risk_deny_threshold: 60,
            action: "agent:billing:read".to_string(),
            resource: "billing".to_string(),
        };
        let policy = PolicyCompiler::compile_agent_scope_policy(&config);
        assert_eq!(policy.version, "EIAA-AST-1.0");
        // VerifyAgentIdentity + CheckDelegationChain + EvaluateRisk + Conditional
        assert_eq!(policy.sequence.len(), 4);
        assert!(matches!(
            &policy.sequence[0],
            Step::VerifyAgentIdentity { model_id, .. } if model_id == "claude-3-5-sonnet-20241022"
        ));
        assert!(matches!(
            &policy.sequence[1],
            Step::CheckDelegationChain { max_depth: 2, require_human_origin: true }
        ));
        assert!(matches!(&policy.sequence[2], Step::EvaluateRisk { .. }));
        let result = verify(&policy, &VerifierConfig::default());
        assert!(
            result.is_ok(),
            "agent_scope_default policy failed verifier: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_compile_agent_scope_policy_custom_threshold() {
        let config = AgentScopeConfig {
            model_id: "gpt-4o".to_string(),
            max_depth: 1,
            risk_deny_threshold: 80,
            action: "agent:send_email".to_string(),
            resource: "email".to_string(),
        };
        let policy = PolicyCompiler::compile_agent_scope_policy(&config);
        assert!(verify(&policy, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn test_compile_password_only() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: false,
            sso: false,
            mfa: MfaConfig {
                required: false,
                methods: vec![],
            },
        };

        let policy = PolicyCompiler::compile_auth_policy(&config);
        assert_eq!(policy.version, "EIAA-AST-1.0");
        // VerifyIdentity + RequireFactor(Password) + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 4);
        assert!(matches!(&policy.sequence[0], Step::VerifyIdentity { .. }));
        // Must pass EIAA verifier
        assert!(verify(&policy, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn test_compile_with_mfa() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: false,
            sso: false,
            mfa: MfaConfig {
                required: true,
                methods: vec!["totp".to_string()],
            },
        };

        let policy = PolicyCompiler::compile_auth_policy(&config);
        // VerifyIdentity + RequireFactor(Password) + RequireFactor(MFA) + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 5);
        assert!(matches!(&policy.sequence[0], Step::VerifyIdentity { .. }));
        assert!(verify(&policy, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn test_compile_passkey_and_password() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: true,
            sso: false,
            mfa: MfaConfig {
                required: false,
                methods: vec![],
            },
        };

        let policy = PolicyCompiler::compile_auth_policy(&config);
        // HIGH-EIAA-1 FIX: VerifyIdentity must be first, not RequireFactor
        assert!(matches!(&policy.sequence[0], Step::VerifyIdentity { .. }));
        assert!(matches!(
            &policy.sequence[1],
            Step::RequireFactor {
                factor_type: FactorType::Any(_)
            }
        ));
        // Must pass EIAA verifier
        assert!(verify(&policy, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn test_compile_passkey_only() {
        let config = LoginMethodsConfig {
            email_password: false,
            passkey: true,
            sso: false,
            mfa: MfaConfig {
                required: false,
                methods: vec![],
            },
        };

        let policy = PolicyCompiler::compile_auth_policy(&config);
        // VerifyIdentity + RequireFactor(Passkey) + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 4);
        assert!(matches!(&policy.sequence[0], Step::VerifyIdentity { .. }));
        assert!(matches!(
            &policy.sequence[1],
            Step::RequireFactor {
                factor_type: FactorType::Passkey
            }
        ));
        // Must pass EIAA verifier
        assert!(verify(&policy, &VerifierConfig::default()).is_ok());
    }

    #[test]
    fn test_compile_signup_with_verification() {
        let policy = PolicyCompiler::compile_signup_policy(true);
        // CollectCredentials + RequireVerification + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 4);
    }

    #[test]
    fn test_compile_signup_without_verification() {
        let policy = PolicyCompiler::compile_signup_policy(false);
        // CollectCredentials + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 3);
    }

    #[test]
    fn test_all_compiled_policies_pass_verifier() {
        // Exhaustive test: all combinations of login methods must produce valid ASTs
        let configs = vec![
            LoginMethodsConfig {
                email_password: true,
                passkey: false,
                sso: false,
                mfa: MfaConfig {
                    required: false,
                    methods: vec![],
                },
            },
            LoginMethodsConfig {
                email_password: false,
                passkey: true,
                sso: false,
                mfa: MfaConfig {
                    required: false,
                    methods: vec![],
                },
            },
            LoginMethodsConfig {
                email_password: true,
                passkey: true,
                sso: false,
                mfa: MfaConfig {
                    required: false,
                    methods: vec![],
                },
            },
            LoginMethodsConfig {
                email_password: true,
                passkey: false,
                sso: false,
                mfa: MfaConfig {
                    required: true,
                    methods: vec!["totp".to_string()],
                },
            },
            LoginMethodsConfig {
                email_password: false,
                passkey: true,
                sso: false,
                mfa: MfaConfig {
                    required: true,
                    methods: vec!["totp".to_string()],
                },
            },
            LoginMethodsConfig {
                email_password: true,
                passkey: true,
                sso: false,
                mfa: MfaConfig {
                    required: true,
                    methods: vec!["totp".to_string(), "passkey".to_string()],
                },
            },
        ];

        for config in &configs {
            let policy = PolicyCompiler::compile_auth_policy(config);
            let result = verify(&policy, &VerifierConfig::default());
            assert!(
                result.is_ok(),
                "Policy failed verifier for config {:?}: {:?}",
                config,
                result.err()
            );
        }
    }
}
