//! Shared route guards for org membership and admin verification.
//!
//! Previously `ensure_org_access` and `ensure_org_admin` were duplicated
//! identically in `roles.rs`, `billing.rs`, and `domains.rs`. This module
//! consolidates them into a single source of truth using `AppError` for
//! consistent error responses across all routes.

use crate::state::AppState;
use auth_core::jwt::Claims;
use shared_types::AppError;

/// Verify the caller is a member of the specified organization.
///
/// Returns `Ok(())` if the caller (identified by `claims.sub`) has any
/// membership in the org. Returns `Err(AppError::Forbidden)` otherwise.
pub async fn ensure_org_access(
    state: &AppState,
    claims: &Claims,
    org_id: &str,
) -> Result<(), AppError> {
    if org_id.is_empty() {
        return Err(AppError::BadRequest("org_id is required".into()));
    }
    let membership = state
        .organization_service
        .get_membership(org_id, &claims.sub)
        .await?;
    if membership.is_none() {
        return Err(AppError::Forbidden(
            "Not a member of the organization".into(),
        ));
    }
    Ok(())
}

/// Verify the caller is an admin of the specified organization.
///
/// Write operations (create/delete roles, manage members, billing changes)
/// require admin role. Returns `Err(AppError::Forbidden)` if the caller
/// has no membership or is not an admin.
pub async fn ensure_org_admin(
    state: &AppState,
    claims: &Claims,
    org_id: &str,
) -> Result<(), AppError> {
    if org_id.is_empty() {
        return Err(AppError::BadRequest("org_id is required".into()));
    }
    let membership = state
        .organization_service
        .get_membership(org_id, &claims.sub)
        .await?;
    match membership {
        Some(m) if m.role == "admin" || m.role == "owner" => Ok(()),
        Some(_) => Err(AppError::Forbidden(
            "Admin role required for this operation".into(),
        )),
        None => Err(AppError::Forbidden(
            "Not a member of the organization".into(),
        )),
    }
}
