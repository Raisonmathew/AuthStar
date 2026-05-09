//! Admin access probe endpoint.
//!
//! `GET /api/admin/v1/whoami` is a deliberately tiny endpoint whose only
//! purpose is to let UI shells (e.g. `AdminLayout`) ask the server "does
//! the EIAA `admin:manage` capsule allow this caller?" and act on the
//! answer.
//!
//! EIAA invariant: authorization decisions are made by the capsule, never
//! by the client. The frontend MUST NOT decode a JWT and read
//! `session_type` (or any other field) to gate admin UI. It probes this
//! endpoint instead — `EiaaAuthzLayer::AdminManage` (applied at the
//! `/api/admin/v1` nesting in `router.rs`) executes the capsule and
//! returns 403 if the caller is not authorized.
//!
//! The handler itself returns only the minimum the UI needs to render its
//! shell (subject id, tenant, identity classification). It does NOT return
//! roles, permissions, scopes or any other entitlement-shaped data — those
//! would re-introduce the problem this endpoint exists to solve.

use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{extract::Extension, routing::get, Json, Router};
use serde::Serialize;
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(whoami))
}

#[derive(Serialize)]
struct WhoamiResponse {
    /// Subject id (user id) of the authenticated principal.
    subject_id: String,
    /// Tenant context the request is being evaluated in.
    tenant_id: String,
    /// Identity classification ("admin" | "end_user" | "flow" | "service").
    /// Returned for diagnostic / UX purposes only — NOT an authorization
    /// signal. The capsule has already authorized this request by the
    /// time we get here.
    session_type: String,
}

/// Probe handler. Reaching this point means `EiaaAuthzLayer::AdminManage`
/// has already evaluated the capsule and the decision was Allow — so we
/// just echo back identity context.
async fn whoami(Extension(claims): Extension<Claims>) -> Result<Json<WhoamiResponse>> {
    Ok(Json(WhoamiResponse {
        subject_id: claims.sub,
        tenant_id: claims.tenant_id,
        session_type: claims.session_type,
    }))
}
