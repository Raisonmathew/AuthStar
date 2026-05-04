//! Admin SCIM token management — re-exported from routes/scim.rs.
//!
//! Mounted under `/api/admin/v1/scim` (JWT + EiaaAuthzLayer::AdminManage).
//!
//! Routes:
//! - `GET    /api/admin/v1/scim/tokens`      — list tenant SCIM tokens
//! - `POST   /api/admin/v1/scim/tokens`      — create a SCIM Bearer token
//! - `DELETE /api/admin/v1/scim/tokens/:id`  — revoke a SCIM token

pub use crate::routes::scim::admin_router;
