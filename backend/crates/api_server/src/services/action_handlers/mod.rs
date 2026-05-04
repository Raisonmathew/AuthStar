//! Action Handler Registry (T1.4)
//!
//! ## Purpose
//!
//! Dispatches verified `ActionTokenClaims` to the concrete handler for that
//! action code. Decouples token cryptography (in `auth_core::action_token`)
//! from action business logic (in this module's submodules).
//!
//! ## Pattern
//!
//! - **Command pattern**: a verified `ActionTokenClaims` is the command;
//!   `ActionHandler` implementations are the receiver/executor.
//! - **Registry**: handlers are registered at startup (in [`AppState::new`])
//!   keyed by [`ActionCode`]. Lookup is O(1).
//! - **Open–closed**: adding a new action requires (1) a new variant in
//!   `ActionCode` (compile-time), (2) a new `ActionHandler` impl, (3) a
//!   `register()` call in startup. No existing handler is modified.
//!
//! ## EIAA Fit
//!
//! Handlers receive the verified claims plus an `ActionContext` carrying
//! request-scoped IO (db pool, audit writer, …). They MUST emit an
//! `eiaa_executions` row for every state-changing action so the audit
//! trail is complete.

use async_trait::async_trait;
use auth_core::{ActionCode, ActionTokenClaims};
use shared_types::{AppError, Result};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

pub mod verify_email;

pub use verify_email::VerifyEmailHandler;

/// Per-request context handed to every handler. Carries only what handlers
/// legitimately need — nothing tenant-wide that handlers shouldn't touch.
///
/// Add fields here (rather than passing the full AppState) to keep the
/// blast radius of each handler narrow.
#[derive(Clone)]
pub struct ActionContext {
    pub db: PgPool,
    pub request_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Result of a successful handler invocation. Returned to the caller (typically
/// the action route) to render a response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionOutcome {
    /// Stable code for the outcome — e.g. `"email_verified"`, `"password_reset"`.
    pub code: String,
    /// Optional redirect URL the caller should send the user to (e.g. SPA login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// Free-form metadata for the response body.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

/// Action handler — implemented once per [`ActionCode`].
///
/// Implementations MUST:
/// - Validate `claims.payload` shape before acting on it.
/// - Use the provided `ActionContext::db` (do not open new pools).
/// - Emit appropriate audit/eiaa_executions rows.
#[async_trait]
pub trait ActionHandler: Send + Sync {
    /// The action code this handler is registered for.
    fn code(&self) -> ActionCode;

    /// Execute the action. Called *after* the token has been crypto-verified
    /// and replay-checked by the dispatcher.
    async fn execute(
        &self,
        claims: &ActionTokenClaims,
        ctx: &ActionContext,
    ) -> Result<ActionOutcome>;
}

/// Registry of handlers, keyed by [`ActionCode`]. Built once at startup.
#[derive(Default, Clone)]
pub struct ActionHandlerRegistry {
    handlers: Arc<HashMap<ActionCode, Arc<dyn ActionHandler>>>,
}

impl ActionHandlerRegistry {
    /// Build a registry from a list of handlers. Panics if two handlers claim
    /// the same `ActionCode` — this is a startup misconfiguration and the
    /// process must not continue.
    pub fn new(handlers: Vec<Arc<dyn ActionHandler>>) -> Self {
        let mut map: HashMap<ActionCode, Arc<dyn ActionHandler>> = HashMap::new();
        for h in handlers {
            let code = h.code();
            if map.insert(code, h).is_some() {
                panic!(
                    "ActionHandlerRegistry: duplicate handler for action code '{}'",
                    code.as_str()
                );
            }
        }
        Self {
            handlers: Arc::new(map),
        }
    }

    /// Look up a handler by code. Returns `AppError::BadRequest` if no handler
    /// is registered — i.e. the action code is known to `auth_core` but no
    /// runtime executor exists. This is a deployment gap, not a client error,
    /// but we surface it as 400 to avoid leaking config state.
    pub fn get(&self, code: ActionCode) -> Result<Arc<dyn ActionHandler>> {
        self.handlers.get(&code).cloned().ok_or_else(|| {
            AppError::BadRequest(format!("no handler registered for '{}'", code.as_str()))
        })
    }

    /// Number of registered handlers — primarily for startup logging/tests.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyHandler(ActionCode);

    #[async_trait]
    impl ActionHandler for DummyHandler {
        fn code(&self) -> ActionCode {
            self.0
        }
        async fn execute(
            &self,
            _claims: &ActionTokenClaims,
            _ctx: &ActionContext,
        ) -> Result<ActionOutcome> {
            Ok(ActionOutcome {
                code: format!("{}_done", self.0.as_str()),
                redirect_to: None,
                data: serde_json::Value::Null,
            })
        }
    }

    #[test]
    fn registry_lookup_works() {
        let reg = ActionHandlerRegistry::new(vec![
            Arc::new(DummyHandler(ActionCode::VerifyEmail)),
            Arc::new(DummyHandler(ActionCode::ResetPassword)),
        ]);
        assert_eq!(reg.len(), 2);
        assert!(reg.get(ActionCode::VerifyEmail).is_ok());
        assert!(reg.get(ActionCode::ResetPassword).is_ok());

        let Err(err) = reg.get(ActionCode::MagicLink) else {
            panic!("expected Err for unregistered ActionCode::MagicLink");
        };
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    #[should_panic(expected = "duplicate handler")]
    fn duplicate_registration_panics() {
        let _ = ActionHandlerRegistry::new(vec![
            Arc::new(DummyHandler(ActionCode::VerifyEmail)),
            Arc::new(DummyHandler(ActionCode::VerifyEmail)),
        ]);
    }
}
