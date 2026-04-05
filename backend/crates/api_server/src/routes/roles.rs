#![allow(dead_code)]
use crate::routes::guards::{ensure_org_access, ensure_org_admin};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get, patch, post},
    Json, Router,
};
use org_manager::models::{Membership, Role};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        // Roles routes
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:role_id", delete(delete_role))
        // Members routes
        .route("/members", get(list_members).post(add_member_by_email))
        .route(
            "/members/:user_id",
            patch(update_member_role).delete(remove_member),
        )
}

/// Read-only routes for roles and members
pub fn read_routes() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles))
        .route("/members", get(list_members))
}

/// Write routes for roles management
pub fn roles_write_routes() -> Router<AppState> {
    Router::new()
        .route("/roles", post(create_role))
        .route("/roles/:role_id", delete(delete_role))
}

/// Write routes for members management
pub fn members_write_routes() -> Router<AppState> {
    Router::new()
        .route("/members", post(add_member_by_email))
        .route(
            "/members/:user_id",
            patch(update_member_role).delete(remove_member),
        )
}

#[derive(Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct UpdateMemberRoleRequest {
    role: String,
}

#[derive(Serialize)]
struct MemberResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
    email: String,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

// ============= Roles Handlers =============

async fn list_roles(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<Role>>> {
    ensure_org_access(&state, &claims, &org_id).await?;
    let roles = state.organization_service.get_roles(&org_id).await?;
    Ok(Json(roles))
}

async fn create_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<Role>> {
    ensure_org_admin(&state, &claims, &org_id).await?;
    let role = state
        .organization_service
        .create_role(
            &org_id,
            &payload.name,
            payload.description.as_deref(),
            payload.permissions,
        )
        .await?;

    Ok(Json(role))
}

async fn delete_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, role_id)): Path<(String, String)>,
) -> Result<()> {
    ensure_org_admin(&state, &claims, &org_id).await?;
    state
        .organization_service
        .delete_role(&org_id, &role_id)
        .await?;
    Ok(())
}

// ============= Members Handlers =============

async fn list_members(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<MemberResponse>>> {
    ensure_org_access(&state, &claims, &org_id).await?;

    // Single JOIN query replaces the N+1 pattern that previously did:
    //   1 query for list_members + N * (get_user + to_user_response [3 queries])
    // For a 50-member org this reduces 201 queries → 1 query.
    #[derive(sqlx::FromRow)]
    struct MemberRow {
        id: String,
        user_id: String,
        role: String,
        created_at: chrono::DateTime<chrono::Utc>,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
    }

    let rows = sqlx::query_as::<_, MemberRow>(
        r#"
        SELECT m.id, m.user_id, m.role, m.created_at,
               i.identifier AS email,
               u.first_name, u.last_name
        FROM memberships m
        JOIN users u ON m.user_id = u.id
        LEFT JOIN identities i ON u.id = i.user_id AND i.type = 'email'
        WHERE m.organization_id = $1
        ORDER BY m.created_at ASC
        LIMIT 200
        "#,
    )
    .bind(&org_id)
    .fetch_all(&state.db)
    .await?;

    let responses: Vec<MemberResponse> = rows
        .into_iter()
        .map(|r| MemberResponse {
            id: r.id,
            user_id: r.user_id,
            role: r.role,
            email: r.email.unwrap_or_default(),
            first_name: r.first_name,
            last_name: r.last_name,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(responses))
}

async fn update_member_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<Membership>> {
    ensure_org_admin(&state, &claims, &org_id).await?;
    let membership = state
        .organization_service
        .update_member_role(&org_id, &user_id, &payload.role)
        .await?;
    Ok(Json(membership))
}

async fn remove_member(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, user_id)): Path<(String, String)>,
) -> Result<()> {
    ensure_org_admin(&state, &claims, &org_id).await?;
    state
        .organization_service
        .remove_member(&org_id, &user_id)
        .await?;
    Ok(())
}

// ============= Add Member By Email =============

#[derive(Deserialize)]
struct AddMemberRequest {
    email: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "member".to_string()
}

#[derive(Serialize)]
struct AddMemberResponse {
    success: bool,
    message: String,
    membership: Option<MemberResponse>,
}

/// Add an existing user to this organization by email
async fn add_member_by_email(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
    Json(payload): Json<AddMemberRequest>,
) -> Result<Json<AddMemberResponse>> {
    ensure_org_admin(&state, &claims, &org_id).await?;
    let user = match state.user_service.get_user_by_email(&payload.email).await {
        Ok(u) => u,
        Err(_) => {
            // B-5: User doesn't exist yet — create an invitation instead of failing
            match state
                .invitation_service
                .create_invitation(&org_id, &payload.email, &payload.role, &claims.sub)
                .await
            {
                Ok(_inv) => {
                    return Ok(Json(AddMemberResponse {
                        success: true,
                        message: format!(
                            "Invitation sent to '{}'. They can accept it after signing up.",
                            payload.email
                        ),
                        membership: None,
                    }));
                }
                Err(e) => {
                    return Ok(Json(AddMemberResponse {
                        success: false,
                        message: format!("Failed to create invitation: {e}"),
                        membership: None,
                    }));
                }
            }
        }
    };

    // 2. Add membership
    let membership = match state
        .organization_service
        .add_member(&org_id, &user.id, &payload.role)
        .await
    {
        Ok(m) => m,
        Err(shared_types::AppError::Conflict(msg)) => {
            return Ok(Json(AddMemberResponse {
                success: false,
                message: msg,
                membership: None,
            }));
        }
        Err(e) => {
            return Err(AppError::Internal(e.to_string()));
        }
    };

    // 3. Get user details for response
    let user_resp = state.user_service.to_user_response(&user).await.ok();

    Ok(Json(AddMemberResponse {
        success: true,
        message: format!("Successfully added {} to the organization", payload.email),
        membership: Some(MemberResponse {
            id: membership.id,
            user_id: membership.user_id,
            role: membership.role,
            email: payload.email,
            first_name: user_resp.as_ref().and_then(|r| r.first_name.clone()),
            last_name: user_resp.as_ref().and_then(|r| r.last_name.clone()),
            created_at: membership.created_at.to_rfc3339(),
        }),
    }))
}

// Guards consolidated in routes::guards module
