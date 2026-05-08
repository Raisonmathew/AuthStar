//! T4.3 — Sub-capsule resolution.
//!
//! `CapsuleResolver` is the abstraction the runtime calls to fetch a child
//! `CapsuleSigned` by its canonical AST hash. The default `NoopCapsuleResolver`
//! always errors, which forces every parent that contains an
//! `AggregateDecision` step to be executed via [`crate::execute_with_resolver`]
//! with a real backend (DB, cache, in-memory registry).
//!
//! The resolver trait is sync to keep the runtime free of async runtime
//! coupling. Backends that need async (DB, network) can wrap a small
//! synchronous cache or use `tokio::task::block_in_place` at the call site.
//!
//! Cycle detection is enforced by [`crate::execute_with_resolver`] itself,
//! not by individual resolvers — resolvers should be free of policy.

use anyhow::{anyhow, Result};
use capsule_compiler::CapsuleSigned;

/// Synchronous lookup of a signed capsule by its canonical AST hash
/// (lowercase hex SHA-256, 64 chars).
///
/// Implementations must be cheap to call repeatedly: the runtime invokes the
/// resolver once per unique child hash per parent execution. Caching is the
/// resolver's responsibility.
pub trait CapsuleResolver: Send + Sync {
    fn load(&self, ast_hash: &str) -> Result<CapsuleSigned>;
}

/// Default resolver used by [`crate::execute`]. Always returns an error so
/// that any capsule containing an `AggregateDecision` step fails closed
/// when no real resolver has been wired in.
pub struct NoopCapsuleResolver;

impl CapsuleResolver for NoopCapsuleResolver {
    fn load(&self, ast_hash: &str) -> Result<CapsuleSigned> {
        Err(anyhow!(
            "no capsule resolver configured; cannot load sub-capsule {ast_hash}"
        ))
    }
}

/// In-memory resolver, used by tests and local registries. Stores a map of
/// `ast_hash -> CapsuleSigned` and returns clones on lookup.
#[derive(Default, Clone)]
pub struct InMemoryCapsuleResolver {
    inner: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, CapsuleSigned>>>,
}

impl InMemoryCapsuleResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, capsule: CapsuleSigned) {
        let mut g = self
            .inner
            .write()
            .expect("InMemoryCapsuleResolver poisoned");
        g.insert(capsule.ast_hash.clone(), capsule);
    }
}

impl CapsuleResolver for InMemoryCapsuleResolver {
    fn load(&self, ast_hash: &str) -> Result<CapsuleSigned> {
        let g = self
            .inner
            .read()
            .map_err(|_| anyhow!("InMemoryCapsuleResolver poisoned"))?;
        g.get(ast_hash)
            .cloned()
            .ok_or_else(|| anyhow!("capsule not found: {ast_hash}"))
    }
}
