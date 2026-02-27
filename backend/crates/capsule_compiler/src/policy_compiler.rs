//! Policy Compiler Module
//!
//! EIAA Single Authority: Login methods configuration is COMPILED into AST.
//! The flow engine only reads the compiled AST, never the raw config.

use crate::ast::{Program, Step, IdentitySource, FactorType};
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
    pub fn compile_auth_policy(config: &LoginMethodsConfig) -> Program {
        let mut steps = vec![];
        
        // Step 1: Determine primary authentication factor
        if config.passkey && config.email_password {
            // Allow choice between passkey and password
            steps.push(Step::RequireFactor { 
                factor_type: FactorType::Any(vec![
                    FactorType::Passkey,
                    FactorType::Password,
                ]) 
            });
        } else if config.passkey {
            // Passkey-only (passwordless)
            steps.push(Step::RequireFactor { 
                factor_type: FactorType::Passkey 
            });
        } else {
            // Password (default)
            steps.push(Step::VerifyIdentity { 
                source: IdentitySource::Primary 
            });
            steps.push(Step::RequireFactor { 
                factor_type: FactorType::Password 
            });
        }
        
        // Step 2: MFA if required
        if config.mfa.required {
            let mfa_factors: Vec<FactorType> = config.mfa.methods.iter()
                .filter_map(|m| match m.as_str() {
                    "totp" => Some(FactorType::Otp),
                    "passkey" => Some(FactorType::Passkey),
                    _ => None,
                })
                .collect();
            
            if !mfa_factors.is_empty() {
                steps.push(Step::RequireFactor { 
                    factor_type: FactorType::Any(mfa_factors) 
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
                verification_type: "email".to_string() 
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compile_password_only() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: false,
            sso: false,
            mfa: MfaConfig { required: false, methods: vec![] },
        };
        
        let policy = PolicyCompiler::compile_auth_policy(&config);
        assert_eq!(policy.version, "EIAA-AST-1.0");
        // VerifyIdentity + RequireFactor(Password) + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 4);
    }
    
    #[test]
    fn test_compile_with_mfa() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: false,
            sso: false,
            mfa: MfaConfig { required: true, methods: vec!["totp".to_string()] },
        };
        
        let policy = PolicyCompiler::compile_auth_policy(&config);
        // VerifyIdentity + RequireFactor(Password) + RequireFactor(MFA) + AuthorizeAction + Allow
        assert_eq!(policy.sequence.len(), 5);
    }
    
    #[test]
    fn test_compile_passkey_and_password() {
        let config = LoginMethodsConfig {
            email_password: true,
            passkey: true,
            sso: false,
            mfa: MfaConfig { required: false, methods: vec![] },
        };
        
        let policy = PolicyCompiler::compile_auth_policy(&config);
        assert!(matches!(
            &policy.sequence[0],
            Step::RequireFactor { factor_type: FactorType::Any(_) }
        ));
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
}
