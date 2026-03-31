use axum::{
    Router,
    routing::{get, post},
    extract::{Path, State, Extension},
    Json,
};
use serde::Serialize;
use crate::state::AppState;
use shared_types::Result;
use auth_core::jwt::Claims;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/:token", get(get_invitation))
        .route("/:token/accept", post(accept_invitation))
}

#[derive(Serialize)]
pub struct InvitationInfo {
    pub id: String,
    pub organization_name: String,
    pub organization_slug: String,
    pub email: String,
    pub role: String,
    pub inviter_name: Option<String>,
    pub expires_at: String,
}

/// GET /api/v1/invitations/:token
///
/// Public-ish endpoint (requires auth but no EIAA) that returns invitation
/// details so the frontend can show "You've been invited to <org> as <role>".
/// Does NOT reveal the token in the response.
async fn get_invitation(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<InvitationInfo>> {
    let invitation = state.invitation_service
        .get_by_token(&token)
        .await?
        .ok_or_else(|| shared_types::AppError::NotFound(
            "Invitation not found, expired, or already used".into(),
        ))?;

    // Fetch org name for display
    let (org_name, org_slug): (String, String) = sqlx::query_as(
        "SELECT name, slug FROM organizations WHERE id = $1"
    )
    .bind(&invitation.organization_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| shared_types::AppError::Internal(format!("Database error: {e}")))?;

    // Optionally fetch inviter name
    let inviter_name: Option<String> = if let Some(ref inviter_id) = invitation.inviter_user_id {
        sqlx::query_scalar("SELECT first_name FROM users WHERE id = $1")
            .bind(inviter_id)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None)
    } else {
        None
    };

    Ok(Json(InvitationInfo {
        id: invitation.id,
        organization_name: org_name,
        organization_slug: org_slug,
        email: invitation.email_address,
        role: invitation.role,
        inviter_name,
        expires_at: invitation.expires_at.to_rfc3339(),
    }))
}

#[derive(Serialize)]
pub struct AcceptResponse {
    pub success: bool,
    pub organization_id: String,
    pub organization_name: String,
    pub role: String,
}

/// POST /api/v1/invitations/:token/accept
///
/// Accepts the invitation for the currently authenticated user.
/// Creates membership and marks the invitation as accepted.
async fn accept_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(token): Path<String>,
) -> Result<Json<AcceptResponse>> {
    let invitation = state.invitation_service
        .accept_invitation(&token, &claims.sub)
        .await?;

    // Fetch org name for response
    let (org_name,): (String,) = sqlx::query_as(
        "SELECT name FROM organizations WHERE id = $1"
    )
    .bind(&invitation.organization_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| shared_types::AppError::Internal(format!("Database error: {e}")))?;

    tracing::info!(
        user_id = %claims.sub,
        org_id = %invitation.organization_id,
        role = %invitation.role,
        "Invitation accepted"
    );

    Ok(Json(AcceptResponse {
        success: true,
        organization_id: invitation.organization_id,
        organization_name: org_name,
        role: invitation.role,
    }))
}
