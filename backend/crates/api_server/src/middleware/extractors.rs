//! Type-safe extractors for authenticated request context.
//!
//! These extractors replace manual `claims.tenant_id` and `Uuid::parse_str(&claims.sub)`
//! patterns with compile-time-enforced types. Handlers that accept `TenantId` or
//! `AuthenticatedUser` can only receive pre-validated, tenant-scoped identifiers.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Before (manual, error-prone):
//! async fn handler(Extension(claims): Extension<Claims>) -> Result<...> {
//!     let tenant_id = &claims.tenant_id;  // string, no type safety
//!     let user_id = Uuid::parse_str(&claims.sub)?;  // can fail at runtime
//!     ...
//! }
//!
//! // After (type-safe, compile-time enforced):
//! async fn handler(tenant: TenantId) -> Result<...> {
//!     state.service.list(&tenant).await?;
//!     ...
//! }
//!
//! // Or when you need both user and tenant:
//! async fn handler(user: AuthenticatedUser) -> Result<...> {
//!     state.service.create(user.user_id, user.tenant_id, ...).await?;
//!     ...
//! }
//! ```

use auth_core::jwt::Claims;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use shared_types::AppError;

/// Tenant ID extracted from authenticated JWT claims.
///
/// Implements Axum's `FromRequestParts` — extracts `claims.tenant_id` from
/// the `Extension<Claims>` injected by the auth middleware.
///
/// Use this as a handler parameter to get compile-time-enforced tenant scoping
/// without manual Claims extraction.
#[derive(Debug, Clone)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for TenantId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or(AppError::Unauthorized("Missing authentication".into()))?;

        if claims.tenant_id.is_empty() {
            return Err(AppError::Unauthorized("Missing tenant context".into()));
        }

        Ok(TenantId(claims.tenant_id.clone()))
    }
}

/// Authenticated user context extracted from JWT claims.
///
/// Bundles the `user_id` and `tenant_id` strings from claims.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub tenant_id: String,
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or(AppError::Unauthorized("Missing authentication".into()))?;

        if claims.sub.is_empty() {
            return Err(AppError::Unauthorized("Invalid user ID in token".into()));
        }
        if claims.tenant_id.is_empty() {
            return Err(AppError::Unauthorized("Invalid tenant ID in token".into()));
        }

        Ok(AuthenticatedUser {
            user_id: claims.sub.clone(),
            tenant_id: claims.tenant_id.clone(),
        })
    }
}

/// Known API key scopes used for scope-based access control.
///
/// JWT-authenticated (human) sessions bypass scope checks entirely — they have
/// full access governed by EIAA policies. API key requests MUST carry the
/// required scope or the request is rejected with 403.
#[allow(dead_code)]
pub mod scopes {
    pub const KEYS_READ: &str = "keys:read";
    pub const KEYS_WRITE: &str = "keys:write";
    pub const USERS_READ: &str = "users:read";
    pub const USERS_WRITE: &str = "users:write";
    pub const ORGS_READ: &str = "orgs:read";
    pub const ORGS_WRITE: &str = "orgs:write";
}
