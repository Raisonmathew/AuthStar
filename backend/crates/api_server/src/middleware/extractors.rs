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

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use auth_core::jwt::Claims;
use shared_types::AppError;
use uuid::Uuid;

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
/// Bundles pre-parsed `user_id` (UUID) and `tenant_id` (UUID) from claims.
/// Use when handlers need both identifiers with UUID type safety.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or(AppError::Unauthorized("Missing authentication".into()))?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized("Invalid user ID in token".into()))?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id)
            .map_err(|_| AppError::Unauthorized("Invalid tenant ID in token".into()))?;

        Ok(AuthenticatedUser {
            user_id,
            tenant_id,
        })
    }
}
