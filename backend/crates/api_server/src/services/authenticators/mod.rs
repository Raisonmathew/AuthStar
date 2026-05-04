use crate::services::credential_lockout::{CredentialLockoutService, FactorKind};
use async_trait::async_trait;
use identity_engine::models::User;
use identity_engine::services::UserService;
use serde::{Deserialize, Serialize};
use shared_types::{AppError, AssuranceLevel, Result};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEvidence {
    pub factor: FactorKind,
    pub capability: String,
    pub aal: AssuranceLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub authenticator_id: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthResult {
    Success { evidence: FactorEvidence },
    Challenge { challenge: AuthChallenge },
    Failed { reason: String },
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Required,
    Alternative,
    Conditional,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub authenticator_id: String,
    pub requirement: Requirement,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub id: String,
    pub executions: Vec<Execution>,
}

pub struct AuthContext<'a> {
    pub tenant_id: &'a str,
    pub user: &'a User,
    pub password: Option<&'a str>,
    pub user_service: &'a UserService,
    pub credential_lockout: &'a CredentialLockoutService,
    pub evidence: Vec<FactorEvidence>,
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    fn id(&self) -> &'static str;
    async fn authenticate(&self, ctx: &mut AuthContext<'_>) -> Result<AuthResult>;
}

#[derive(Clone)]
pub struct AuthenticatorRegistry {
    authenticators: Arc<HashMap<&'static str, Arc<dyn Authenticator>>>,
}

impl AuthenticatorRegistry {
    pub fn new(authenticators: Vec<Arc<dyn Authenticator>>) -> Self {
        Self {
            authenticators: Arc::new(authenticators.into_iter().map(|a| (a.id(), a)).collect()),
        }
    }

    pub fn default_authenticators() -> Self {
        Self::new(vec![Arc::new(PasswordAuthenticator)])
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Authenticator>> {
        self.authenticators.get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.authenticators.len()
    }
}

pub struct PasswordAuthenticator;

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    fn id(&self) -> &'static str {
        "password"
    }

    async fn authenticate(&self, ctx: &mut AuthContext<'_>) -> Result<AuthResult> {
        let password = match ctx.password {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(AuthResult::Failed {
                    reason: "missing_password".to_string(),
                })
            }
        };

        let verified = ctx
            .user_service
            .verify_user_password(&ctx.user.id, password)
            .await?;
        if verified {
            ctx.credential_lockout
                .record_success(ctx.tenant_id, &ctx.user.id, FactorKind::Password)
                .await?;
            let evidence = FactorEvidence {
                factor: FactorKind::Password,
                capability: "password".to_string(),
                aal: AssuranceLevel::AAL1,
            };
            ctx.evidence.push(evidence.clone());
            Ok(AuthResult::Success { evidence })
        } else {
            ctx.credential_lockout
                .record_failure(ctx.tenant_id, &ctx.user.id, FactorKind::Password)
                .await?;
            Ok(AuthResult::Failed {
                reason: "invalid_password".to_string(),
            })
        }
    }
}

impl AuthFlow {
    pub fn default_browser_login() -> Self {
        Self {
            id: "browser_login".to_string(),
            executions: vec![Execution {
                authenticator_id: "password".to_string(),
                requirement: Requirement::Required,
                config: serde_json::json!({}),
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlowOutcome {
    pub evidence: Vec<FactorEvidence>,
    pub verified_capabilities: Vec<String>,
    pub assurance_level: AssuranceLevel,
}

#[derive(Clone)]
pub struct AuthFlowEngine {
    registry: AuthenticatorRegistry,
    user_service: UserService,
    credential_lockout: CredentialLockoutService,
}

impl AuthFlowEngine {
    pub fn new(
        registry: AuthenticatorRegistry,
        user_service: UserService,
        credential_lockout: CredentialLockoutService,
    ) -> Self {
        Self {
            registry,
            user_service,
            credential_lockout,
        }
    }

    pub async fn run_password_login(
        &self,
        tenant_id: &str,
        user: &User,
        password: &str,
    ) -> Result<AuthFlowOutcome> {
        let flow = AuthFlow::default_browser_login();
        self.run(flow, tenant_id, user, Some(password)).await
    }

    pub async fn run(
        &self,
        flow: AuthFlow,
        tenant_id: &str,
        user: &User,
        password: Option<&str>,
    ) -> Result<AuthFlowOutcome> {
        let mut ctx = AuthContext {
            tenant_id,
            user,
            password,
            user_service: &self.user_service,
            credential_lockout: &self.credential_lockout,
            evidence: Vec::new(),
        };

        for execution in flow.executions {
            if execution.requirement == Requirement::Disabled {
                continue;
            }
            let auth = self
                .registry
                .get(&execution.authenticator_id)
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "Authenticator not registered: {}",
                        execution.authenticator_id
                    ))
                })?;
            match auth.authenticate(&mut ctx).await? {
                AuthResult::Success { .. } | AuthResult::Skipped => {}
                AuthResult::Challenge { challenge } => {
                    return Err(AppError::Forbidden(format!(
                        "Authentication challenge required: {}",
                        challenge.authenticator_id
                    )))
                }
                AuthResult::Failed { reason } => {
                    if execution.requirement == Requirement::Required {
                        return Err(AppError::Unauthorized(reason));
                    }
                }
            }
        }

        let assurance_level = ctx
            .evidence
            .iter()
            .map(|e| e.aal)
            .max()
            .unwrap_or(AssuranceLevel::AAL0);
        let verified_capabilities = ctx.evidence.iter().map(|e| e.capability.clone()).collect();
        Ok(AuthFlowOutcome {
            evidence: ctx.evidence,
            verified_capabilities,
            assurance_level,
        })
    }

    pub fn registry_len(&self) -> usize {
        self.registry.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthFlow, AuthenticatorRegistry};

    #[test]
    fn default_flow_uses_password_execution() {
        let flow = AuthFlow::default_browser_login();
        assert_eq!(flow.executions.len(), 1);
        assert_eq!(flow.executions[0].authenticator_id, "password");
    }

    #[test]
    fn registry_has_password_authenticator() {
        let registry = AuthenticatorRegistry::default_authenticators();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("password").is_some());
    }
}
