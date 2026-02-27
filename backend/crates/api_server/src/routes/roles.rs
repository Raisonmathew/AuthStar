use axum::{
    extract::{Path, State, Extension},
    routing::{get, delete, patch, post},
    Router, Json,
};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use org_manager::models::{Role, Membership};
use auth_core::jwt::Claims;

pub fn router() -> Router<AppState> {
    Router::new()
        // Roles routes
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:role_id", delete(delete_role))
        // Members routes
        .route("/members", get(list_members).post(add_member_by_email))
        .route("/members/:user_id", patch(update_member_role).delete(remove_member))
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
        .route("/members/:user_id", patch(update_member_role).delete(remove_member))
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
) -> Result<Json<Vec<Role>>, (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    let roles = state.organization_service.get_roles(&org_id).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(roles))
}

async fn create_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<Role>, (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    let role = state.organization_service.create_role(
        &org_id,
        &payload.name,
        payload.description.as_deref(),
        payload.permissions,
    ).await
    .map_err(|e| {
        match e {
            shared_types::AppError::Conflict(msg) => (axum::http::StatusCode::CONFLICT, msg),
            _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;
    
    Ok(Json(role))
}

async fn delete_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, role_id)): Path<(String, String)>,
) -> Result<(), (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    state.organization_service.delete_role(&org_id, &role_id).await
        .map_err(|e| {
            match e {
                shared_types::AppError::NotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg),
                _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;
    
    Ok(())
}

// ============= Members Handlers =============

async fn list_members(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<MemberResponse>>, (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    let members = state.organization_service.list_members(&org_id).await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Convert memberships to member responses with user details
    let mut responses = Vec::new();
    for m in members {
        // Lookup user details via user_service
        let (email, first_name, last_name) = match state.user_service.get_user(&m.user_id).await {
            Ok(user) => {
                // Get user response which includes email
                match state.user_service.to_user_response(&user).await {
                    Ok(resp) => (resp.email.unwrap_or_default(), resp.first_name, resp.last_name),
                    Err(_) => (String::new(), user.first_name, user.last_name),
                }
            }
            Err(_) => (String::new(), None, None),
        };
        
        responses.push(MemberResponse {
            id: m.id.clone(),
            user_id: m.user_id.clone(),
            role: m.role.clone(),
            email,
            first_name,
            last_name,
            created_at: m.created_at.to_rfc3339(),
        });
    }
    
    Ok(Json(responses))
}

async fn update_member_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<Membership>, (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    let membership = state.organization_service.update_member_role(&org_id, &user_id, &payload.role).await
        .map_err(|e| {
            match e {
                shared_types::AppError::NotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg),
                _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;
    
    Ok(Json(membership))
}

async fn remove_member(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((org_id, user_id)): Path<(String, String)>,
) -> Result<(), (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    state.organization_service.remove_member(&org_id, &user_id).await
        .map_err(|e| {
            match e {
                shared_types::AppError::NotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg),
                shared_types::AppError::Conflict(msg) => (axum::http::StatusCode::CONFLICT, msg),
                _ => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;
    
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
) -> Result<Json<AddMemberResponse>, (axum::http::StatusCode, String)> {
    ensure_org_access(&state, &claims, &org_id).await?;
    // 1. Look up user by email
    let user = match state.user_service.get_user_by_email(&payload.email).await {
        Ok(u) => u,
        Err(_) => {
            return Ok(Json(AddMemberResponse {
                success: false,
                message: format!("No user found with email '{}'. They need to sign up first.", payload.email),
                membership: None,
            }));
        }
    };

    // 2. Add membership
    let membership = match state.organization_service.add_member(&org_id, &user.id, &payload.role).await {
        Ok(m) => m,
        Err(shared_types::AppError::Conflict(msg)) => {
            return Ok(Json(AddMemberResponse {
                success: false,
                message: msg,
                membership: None,
            }));
        }
        Err(e) => {
            return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
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

async fn ensure_org_access(
    state: &AppState,
    claims: &Claims,
    org_id: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    if org_id.is_empty() {
        return Err((axum::http::StatusCode::BAD_REQUEST, "org_id is required".into()));
    }
    let membership = state.organization_service
        .get_membership(org_id, &claims.sub)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if membership.is_none() {
        return Err((axum::http::StatusCode::FORBIDDEN, "Not a member of the organization".into()));
    }
    Ok(())
}
