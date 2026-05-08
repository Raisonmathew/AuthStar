use crate::middleware::org_context::set_rls_context_on_conn;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{validation, AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route(
            "/:id",
            get(get_group).patch(update_group).delete(delete_group),
        )
        .route("/:id/members", post(add_group_member))
        .route(
            "/:id/members/:user_id",
            axum::routing::delete(remove_group_member),
        )
        .route("/:id/roles", post(add_group_role))
        .route(
            "/:id/roles/:role_id",
            axum::routing::delete(remove_group_role),
        )
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct GroupResponse {
    id: String,
    tenant_id: String,
    parent_group_id: Option<String>,
    name: String,
    slug: String,
    description: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    member_count: i64,
    role_count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct GroupMemberResponse {
    user_id: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct GroupRoleResponse {
    role_id: String,
    name: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDetailsResponse {
    group: GroupResponse,
    members: Vec<GroupMemberResponse>,
    roles: Vec<GroupRoleResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupRequest {
    name: String,
    slug: Option<String>,
    parent_group_id: Option<String>,
    description: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateGroupRequest {
    name: Option<String>,
    slug: Option<String>,
    parent_group_id: Option<Option<String>>,
    description: Option<Option<String>>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddGroupMemberRequest {
    user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddGroupRoleRequest {
    role_id: String,
}

async fn list_groups(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<GroupResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let sql = group_select_sql("ORDER BY g.name ASC");
    let groups = sqlx::query_as::<_, GroupResponse>(&sql)
        .bind(&claims.tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("List groups: {e}")))?;
    Ok(Json(groups))
}

async fn get_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<GroupDetailsResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let group = fetch_group(&mut conn, &claims.tenant_id, &id).await?;
    let members = fetch_group_members(&mut conn, &claims.tenant_id, &id).await?;
    let roles = fetch_group_roles(&mut conn, &claims.tenant_id, &id).await?;
    Ok(Json(GroupDetailsResponse {
        group,
        members,
        roles,
    }))
}

async fn create_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("Group name is required".to_string()));
    }
    let slug = normalize_slug(req.slug.as_deref(), name)?;
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    if let Some(parent_group_id) = req.parent_group_id.as_deref() {
        ensure_group(&mut conn, &claims.tenant_id, parent_group_id).await?;
    }

    let id: String = sqlx::query_scalar(
        r#"
        INSERT INTO groups (tenant_id, parent_group_id, name, slug, description, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(req.parent_group_id.as_deref())
    .bind(name)
    .bind(&slug)
    .bind(req.description.as_deref())
    .bind(req.metadata.unwrap_or_else(|| serde_json::json!({})))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Create group: {e}")))?;

    Ok(Json(fetch_group(&mut conn, &claims.tenant_id, &id).await?))
}

async fn update_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let current = fetch_group(&mut conn, &claims.tenant_id, &id).await?;
    let slug = match req.slug.as_deref() {
        Some(slug) => Some(normalize_slug(Some(slug), &current.name)?),
        None => None,
    };
    let parent_group_id = req.parent_group_id.clone().flatten();
    if let Some(parent_group_id) = parent_group_id.as_deref() {
        if parent_group_id == id {
            return Err(AppError::Validation(
                "Group cannot be its own parent".to_string(),
            ));
        }
        ensure_group(&mut conn, &claims.tenant_id, parent_group_id).await?;
        ensure_parent_is_not_descendant(&mut conn, &claims.tenant_id, &id, parent_group_id).await?;
    }
    let clear_parent = matches!(req.parent_group_id, Some(None));
    let description = req.description.clone().flatten();
    let clear_description = matches!(req.description, Some(None));

    sqlx::query(
        r#"
        UPDATE groups
        SET name = COALESCE($2, name),
            slug = COALESCE($3, slug),
            parent_group_id = CASE WHEN $5 THEN NULL ELSE COALESCE($4, parent_group_id) END,
            description = CASE WHEN $7 THEN NULL ELSE COALESCE($6, description) END,
            metadata = COALESCE($8, metadata),
            updated_at = NOW()
        WHERE tenant_id = $1 AND id = $9 AND deleted_at IS NULL
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(req.name.as_deref())
    .bind(slug.as_deref())
    .bind(parent_group_id.as_deref())
    .bind(clear_parent)
    .bind(description.as_deref())
    .bind(clear_description)
    .bind(req.metadata)
    .bind(&id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Update group: {e}")))?;

    Ok(Json(fetch_group(&mut conn, &claims.tenant_id, &id).await?))
}

async fn delete_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_group(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query("DELETE FROM group_memberships WHERE tenant_id = $1 AND group_id = $2")
        .bind(&claims.tenant_id)
        .bind(&id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Delete group memberships: {e}")))?;
    sqlx::query("DELETE FROM group_role_bindings WHERE tenant_id = $1 AND group_id = $2")
        .bind(&claims.tenant_id)
        .bind(&id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Delete group role bindings: {e}")))?;
    sqlx::query(
        "UPDATE groups SET deleted_at = NOW(), updated_at = NOW() WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&claims.tenant_id)
    .bind(&id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Delete group: {e}")))?;
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

async fn add_group_member(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<Json<Vec<GroupMemberResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_group(&mut conn, &claims.tenant_id, &id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &req.user_id).await?;
    sqlx::query(
        r#"
        INSERT INTO group_memberships (tenant_id, group_id, user_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id, group_id, user_id) DO NOTHING
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&id)
    .bind(&req.user_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Add group member: {e}")))?;
    Ok(Json(
        fetch_group_members(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn remove_group_member(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((id, user_id)): Path<(String, String)>,
) -> Result<Json<Vec<GroupMemberResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_group(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query(
        "DELETE FROM group_memberships WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3",
    )
    .bind(&claims.tenant_id)
    .bind(&id)
    .bind(&user_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Remove group member: {e}")))?;
    Ok(Json(
        fetch_group_members(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn add_group_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<AddGroupRoleRequest>,
) -> Result<Json<Vec<GroupRoleResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_group(&mut conn, &claims.tenant_id, &id).await?;
    ensure_tenant_role(&mut conn, &claims.tenant_id, &req.role_id).await?;
    sqlx::query(
        r#"
        INSERT INTO group_role_bindings (tenant_id, group_id, role_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id, group_id, role_id) DO NOTHING
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&id)
    .bind(&req.role_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Bind group role: {e}")))?;
    Ok(Json(
        fetch_group_roles(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn remove_group_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((id, role_id)): Path<(String, String)>,
) -> Result<Json<Vec<GroupRoleResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_group(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query(
        "DELETE FROM group_role_bindings WHERE tenant_id = $1 AND group_id = $2 AND role_id = $3",
    )
    .bind(&claims.tenant_id)
    .bind(&id)
    .bind(&role_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Remove group role: {e}")))?;
    Ok(Json(
        fetch_group_roles(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

fn normalize_slug(input: Option<&str>, fallback_name: &str) -> Result<String> {
    let slug = input
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| validation::slugify(fallback_name));
    if !validation::validate_slug(&slug) {
        return Err(AppError::Validation(
            "Slug must be 3-128 lowercase letters, numbers, or hyphens".to_string(),
        ));
    }
    Ok(slug)
}

fn group_select_sql(tail: &str) -> String {
    format!(
        r#"
        SELECT g.id, g.tenant_id, g.parent_group_id, g.name, g.slug, g.description,
               g.metadata, g.created_at, g.updated_at,
               COALESCE(m.member_count, 0)::bigint AS member_count,
               COALESCE(r.role_count, 0)::bigint AS role_count
        FROM groups g
        LEFT JOIN (
            SELECT tenant_id, group_id, COUNT(*) AS member_count
            FROM group_memberships
            GROUP BY tenant_id, group_id
        ) m ON m.tenant_id = g.tenant_id AND m.group_id = g.id
        LEFT JOIN (
            SELECT tenant_id, group_id, COUNT(*) AS role_count
            FROM group_role_bindings
            GROUP BY tenant_id, group_id
        ) r ON r.tenant_id = g.tenant_id AND r.group_id = g.id
        WHERE g.tenant_id = $1 AND g.deleted_at IS NULL
        {tail}
        "#
    )
}

async fn tenant_conn(
    state: &AppState,
    tenant_id: &str,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set admin groups RLS context".into()))?;
    Ok(conn)
}

async fn ensure_group(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    group_id: &str,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL)",
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_one(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Check group: {e}")))?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound("Group not found".to_string()))
    }
}

async fn ensure_tenant_user(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id = $1 AND user_id = $2)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Check tenant user: {e}")))?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound("User not found in tenant".to_string()))
    }
}

async fn ensure_tenant_role(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    role_id: &str,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM roles WHERE organization_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_one(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Check tenant role: {e}")))?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound("Role not found in tenant".to_string()))
    }
}

async fn ensure_parent_is_not_descendant(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    group_id: &str,
    proposed_parent_id: &str,
) -> Result<()> {
    let is_descendant: bool = sqlx::query_scalar(
        r#"
        WITH RECURSIVE descendants AS (
            SELECT id, parent_group_id
            FROM groups
            WHERE tenant_id = $1 AND parent_group_id = $2 AND deleted_at IS NULL
            UNION ALL
            SELECT g.id, g.parent_group_id
            FROM groups g
            JOIN descendants d ON g.parent_group_id = d.id
            WHERE g.tenant_id = $1 AND g.deleted_at IS NULL
        )
        SELECT EXISTS(SELECT 1 FROM descendants WHERE id = $3)
        "#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(proposed_parent_id)
    .fetch_one(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Check group hierarchy cycle: {e}")))?;

    if is_descendant {
        Err(AppError::Validation(
            "Group parent cannot be one of its descendants".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn fetch_group(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    group_id: &str,
) -> Result<GroupResponse> {
    let sql = format!("{} AND g.id = $2", group_select_sql(""));
    sqlx::query_as::<_, GroupResponse>(&sql)
        .bind(tenant_id)
        .bind(group_id)
        .fetch_optional(&mut **conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch group: {e}")))?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))
}

async fn fetch_group_members(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    group_id: &str,
) -> Result<Vec<GroupMemberResponse>> {
    sqlx::query_as::<_, GroupMemberResponse>(
        r#"
        SELECT gm.user_id, i.identifier AS email, u.first_name, u.last_name, gm.created_at
        FROM group_memberships gm
        JOIN users u ON u.id = gm.user_id
        LEFT JOIN identities i ON i.user_id = gm.user_id
            AND i.type = 'email'
            AND i.organization_id = $1
        WHERE gm.tenant_id = $1 AND gm.group_id = $2
        ORDER BY gm.created_at ASC
        "#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_all(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch group members: {e}")))
}

async fn fetch_group_roles(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    group_id: &str,
) -> Result<Vec<GroupRoleResponse>> {
    sqlx::query_as::<_, GroupRoleResponse>(
        r#"
        SELECT grb.role_id, r.name, r.description, grb.created_at
        FROM group_role_bindings grb
        JOIN roles r ON r.id = grb.role_id
        WHERE grb.tenant_id = $1 AND grb.group_id = $2
        ORDER BY r.name ASC
        "#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_all(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch group roles: {e}")))
}
