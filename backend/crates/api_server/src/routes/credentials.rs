//! `GET /api/v1/credentials` — unified read of every credential the
//! authenticated user has, across every registered `CredentialProvider`
//! (T1.6).
//!
//! This is the first production caller of `CredentialRegistry::list_all`.
//! It exists so the abstraction is *live* (not dead code) and so the
//! security-settings UI has a single endpoint to render the user's full
//! credential inventory without the frontend needing to know which legacy
//! table backs which kind.
//!
//! The route is mounted under the same `Action::UserRead` capsule layer as
//! the existing `read_router()` for user factors — the rationale is the
//! same: the StepUpModal must be able to fetch this list before the user
//! has stepped up to a higher AAL, otherwise we deadlock.

use axum::{
    extract::{Extension, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use auth_core::jwt::Claims;
use shared_types::Result;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/credentials", get(list_credentials))
}

async fn list_credentials(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse> {
    let mut records = state
        .credential_store
        .list_for_user(&claims.sub, &claims.tenant_id)
        .await?;
    if records.is_empty() {
        records = state
            .credentials
            .list_all(&claims.sub, &claims.tenant_id)
            .await?;
    }
    Ok(Json(serde_json::json!({ "credentials": records })))
}
