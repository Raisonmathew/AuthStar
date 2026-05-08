use crate::middleware::org_context::set_rls_context_on_conn;
use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, validation, AppError, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(get_user).patch(update_user).delete(delete_user))
        .route(
            "/:id/attributes",
            get(list_user_attributes)
                .put(replace_user_attributes)
                .patch(patch_user_attributes),
        )
        .route("/:id/lock", post(lock_user))
        .route("/:id/unlock", post(unlock_user))
        .route("/:id/required-actions", post(assign_required_actions))
        .route(
            "/:id/force-password-change",
            post(force_password_change).delete(clear_force_password_change),
        )
        .route("/:id/impersonate", post(impersonate_user))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListUsersQuery {
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct AdminUserResponse {
    id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    first_name: Option<String>,
    last_name: Option<String>,
    profile_image_url: Option<String>,
    banned: bool,
    locked: bool,
    email: Option<String>,
    email_verified: Option<bool>,
    phone: Option<String>,
    phone_verified: Option<bool>,
    role: Option<String>,
    public_metadata: serde_json::Value,
    private_metadata: serde_json::Value,
    unsafe_metadata: serde_json::Value,
    attributes: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAdminUserRequest {
    email: String,
    password: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    phone: Option<String>,
    role: Option<String>,
    email_verified: Option<bool>,
    phone_verified: Option<bool>,
    public_metadata: Option<serde_json::Value>,
    private_metadata: Option<serde_json::Value>,
    unsafe_metadata: Option<serde_json::Value>,
    attributes: Option<serde_json::Value>,
    required_actions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateAdminUserRequest {
    email: Option<String>,
    phone: Option<Option<String>>,
    first_name: Option<String>,
    last_name: Option<String>,
    profile_image_url: Option<String>,
    role: Option<String>,
    banned: Option<bool>,
    locked: Option<bool>,
    email_verified: Option<bool>,
    phone_verified: Option<bool>,
    public_metadata: Option<serde_json::Value>,
    private_metadata: Option<serde_json::Value>,
    unsafe_metadata: Option<serde_json::Value>,
    attributes: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssignRequiredActionsRequest {
    codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttributesRequest {
    attributes: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonateRequest {
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonateResponse {
    jwt: String,
    session_id: String,
    tenant_id: String,
    impersonated_by: String,
    user: identity_engine::models::UserResponse,
}

async fn list_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<Vec<AdminUserResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let q = query.q.unwrap_or_default();
    let pattern = format!("%{}%", q.trim());
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);

    let rows = sqlx::query_as::<_, AdminUserResponse>(
        r#"
        SELECT u.id, u.created_at, u.updated_at, u.first_name, u.last_name,
               u.profile_image_url, u.banned, u.locked,
               email.identifier AS email, email.verified AS email_verified,
               phone.identifier AS phone, phone.verified AS phone_verified,
               m.role,
               u.public_metadata, u.private_metadata, u.unsafe_metadata,
               COALESCE(attrs.attributes, '{}'::jsonb) AS attributes
        FROM memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN identities email ON email.user_id = u.id
            AND email.type = 'email'
            AND email.organization_id = $1
        LEFT JOIN identities phone ON phone.user_id = u.id
            AND phone.type = 'phone'
            AND phone.organization_id = $1
        LEFT JOIN LATERAL (
            SELECT jsonb_object_agg(ua.key, ua.value) AS attributes
            FROM user_attributes ua
            WHERE ua.tenant_id = $1 AND ua.user_id = u.id
        ) attrs ON TRUE
        WHERE m.organization_id = $1
          AND u.deleted_at IS NULL
          AND ($2 = '%%'
            OR email.identifier ILIKE $2
            OR phone.identifier ILIKE $2
            OR u.first_name ILIKE $2
            OR u.last_name ILIKE $2
            OR u.id ILIKE $2)
        ORDER BY u.created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("List admin users: {e}")))?;

    Ok(Json(rows))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<AdminUserResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let user = fetch_admin_user(&mut conn, &claims.tenant_id, &id).await?;
    Ok(Json(user))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateAdminUserRequest>,
) -> Result<Json<AdminUserResponse>> {
    if !validation::validate_email(&req.email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }
    validate_phone(req.phone.as_deref())?;
    let attributes = req.attributes.as_ref().map(attribute_entries).transpose()?;

    if let Some(password) = req.password.as_deref() {
        state
            .password_policy_service
            .validate_password(&claims.tenant_id, None, password)
            .await?;
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin create user transaction: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&claims.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Set user-create RLS context: {e}")))?;

    ensure_identity_available(&mut tx, &claims.tenant_id, "email", &req.email, None).await?;
    if let Some(phone) = req.phone.as_deref() {
        ensure_identity_available(&mut tx, &claims.tenant_id, "phone", phone, None).await?;
    }

    let user_id = generate_id("user");
    sqlx::query(
        r#"
        INSERT INTO users (
            id, first_name, last_name, organization_id,
            public_metadata, private_metadata, unsafe_metadata,
            created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        "#,
    )
    .bind(&user_id)
    .bind(req.first_name.as_deref())
    .bind(req.last_name.as_deref())
    .bind(&claims.tenant_id)
    .bind(req.public_metadata.unwrap_or_else(|| serde_json::json!({})))
    .bind(
        req.private_metadata
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .bind(req.unsafe_metadata.unwrap_or_else(|| serde_json::json!({})))
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Create user: {e}")))?;

    insert_identity(
        &mut tx,
        &claims.tenant_id,
        &user_id,
        "email",
        &req.email,
        req.email_verified.unwrap_or(false),
    )
    .await?;
    if let Some(phone) = req.phone.as_deref() {
        insert_identity(
            &mut tx,
            &claims.tenant_id,
            &user_id,
            "phone",
            phone,
            req.phone_verified.unwrap_or(false),
        )
        .await?;
    }

    if let Some(password) = req.password.as_deref() {
        let password_hash = auth_core::hash_password(password)?;
        sqlx::query(
            r#"
            INSERT INTO passwords (id, user_id, password_hash, created_at)
            VALUES ($1, $2, $3, NOW())
            "#,
        )
        .bind(generate_id("pass"))
        .bind(&user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Create password: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO password_history (id, user_id, password_hash, created_at)
            VALUES ($1, $2, $3, NOW())
            "#,
        )
        .bind(generate_id("hist"))
        .bind(&user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Seed password history: {e}")))?;
    }

    let role = req.role.unwrap_or_else(|| "member".to_string());
    sqlx::query(
        r#"
        INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(generate_id("memb"))
    .bind(&claims.tenant_id)
    .bind(&user_id)
    .bind(&role)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Create membership: {e}")))?;

    if let Some(attributes) = attributes {
        upsert_attributes(&mut tx, &claims.tenant_id, &user_id, attributes).await?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit create user transaction: {e}")))?;

    if let Some(codes) = req.required_actions {
        for code in codes {
            state
                .required_action_service
                .ensure_pending(&claims.tenant_id, &user_id, &code, 50, None)
                .await?;
        }
    }

    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    Ok(Json(
        fetch_admin_user(&mut conn, &claims.tenant_id, &user_id).await?,
    ))
}

async fn update_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAdminUserRequest>,
) -> Result<Json<AdminUserResponse>> {
    if let Some(email) = req.email.as_deref() {
        if !validation::validate_email(email) {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }
    }
    let phone_value = req.phone.clone().flatten();
    validate_phone(phone_value.as_deref())?;
    let clear_phone = matches!(req.phone, Some(None));
    let attributes = req.attributes.as_ref().map(attribute_entries).transpose()?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin update user transaction: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&claims.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Set user-update RLS context: {e}")))?;
    ensure_tenant_user_tx(&mut tx, &claims.tenant_id, &id).await?;

    if let Some(email) = req.email.as_deref() {
        ensure_identity_available(&mut tx, &claims.tenant_id, "email", email, Some(&id)).await?;
    }
    if let Some(phone) = phone_value.as_deref() {
        ensure_identity_available(&mut tx, &claims.tenant_id, "phone", phone, Some(&id)).await?;
    }

    sqlx::query(
        r#"
        UPDATE users
        SET first_name = COALESCE($2, first_name),
            last_name = COALESCE($3, last_name),
            profile_image_url = COALESCE($4, profile_image_url),
            banned = COALESCE($5, banned),
            locked = COALESCE($6, locked),
            public_metadata = COALESCE($7, public_metadata),
            private_metadata = COALESCE($8, private_metadata),
            unsafe_metadata = COALESCE($9, unsafe_metadata),
            updated_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(&id)
    .bind(req.first_name.as_deref())
    .bind(req.last_name.as_deref())
    .bind(req.profile_image_url.as_deref())
    .bind(req.banned)
    .bind(req.locked)
    .bind(req.public_metadata)
    .bind(req.private_metadata)
    .bind(req.unsafe_metadata)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Update admin user: {e}")))?;

    if let Some(role) = req.role.as_deref() {
        sqlx::query(
            r#"
            UPDATE memberships
            SET role = $3, updated_at = NOW()
            WHERE organization_id = $1 AND user_id = $2
            "#,
        )
        .bind(&claims.tenant_id)
        .bind(&id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Update user role: {e}")))?;
    }

    if let Some(email) = req.email.as_deref() {
        upsert_identity(
            &mut tx,
            &claims.tenant_id,
            &id,
            "email",
            email,
            req.email_verified.unwrap_or(false),
        )
        .await?;
    } else if let Some(email_verified) = req.email_verified {
        set_identity_verified(&mut tx, &claims.tenant_id, &id, "email", email_verified).await?;
    }

    if clear_phone {
        sqlx::query(
            "DELETE FROM identities WHERE organization_id = $1 AND user_id = $2 AND type = 'phone'",
        )
        .bind(&claims.tenant_id)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Delete phone identity: {e}")))?;
    } else if let Some(phone) = phone_value.as_deref() {
        upsert_identity(
            &mut tx,
            &claims.tenant_id,
            &id,
            "phone",
            phone,
            req.phone_verified.unwrap_or(false),
        )
        .await?;
    } else if let Some(phone_verified) = req.phone_verified {
        set_identity_verified(&mut tx, &claims.tenant_id, &id, "phone", phone_verified).await?;
    }

    if let Some(attributes) = attributes {
        sqlx::query("DELETE FROM user_attributes WHERE tenant_id = $1 AND user_id = $2")
            .bind(&claims.tenant_id)
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Replace user attributes: {e}")))?;
        upsert_attributes(&mut tx, &claims.tenant_id, &id, attributes).await?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit update user transaction: {e}")))?;

    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    Ok(Json(
        fetch_admin_user(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query("UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(&id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Delete admin user: {e}")))?;
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

async fn lock_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<AdminUserResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query(
        "UPDATE users SET locked = TRUE, locked_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(&id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Lock user: {e}")))?;
    Ok(Json(
        fetch_admin_user(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn unlock_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<AdminUserResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query(
        "UPDATE users SET locked = FALSE, locked_at = NULL, failed_login_attempts = 0, updated_at = NOW() WHERE id = $1",
    )
    .bind(&id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Unlock user: {e}")))?;
    state
        .credential_lockout_service
        .reset_user_factor(
            &claims.tenant_id,
            &id,
            crate::services::credential_lockout::FactorKind::Password,
        )
        .await?;
    Ok(Json(
        fetch_admin_user(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn assign_required_actions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<AssignRequiredActionsRequest>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    for code in req.codes {
        state
            .required_action_service
            .ensure_pending(&claims.tenant_id, &id, &code, 50, None)
            .await?;
    }
    Ok(Json(serde_json::json!({ "status": "assigned" })))
}

/// `POST /admin/users/:id/force-password-change` — set `passwords.must_change`
/// so the next signin surfaces the `update_password` required action.
/// Returns 404 if the user has no local password row (e.g. LDAP-only users).
async fn force_password_change(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    let updated = sqlx::query("UPDATE passwords SET must_change = TRUE WHERE user_id = $1")
        .bind(&id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Force password change: {e}")))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "User has no local password to flag".to_string(),
        ));
    }
    state
        .required_action_service
        .ensure_pending(&claims.tenant_id, &id, "update_password", 30, None)
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: "admin.user_force_password_change",
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("user"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"action": "force_password_change"}),
        })
        .await;
    Ok(Json(serde_json::json!({ "status": "must_change_set" })))
}

/// `DELETE /admin/users/:id/force-password-change` — clear the flag without
/// requiring the user to actually rotate. Useful to undo an accidental call.
async fn clear_force_password_change(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    sqlx::query("UPDATE passwords SET must_change = FALSE WHERE user_id = $1")
        .bind(&id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Clear must_change: {e}")))?;
    Ok(Json(serde_json::json!({ "status": "cleared" })))
}

async fn list_user_attributes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    ensure_tenant_user(&mut conn, &claims.tenant_id, &id).await?;
    Ok(Json(
        fetch_user_attributes(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn replace_user_attributes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<AttributesRequest>,
) -> Result<Json<serde_json::Value>> {
    let attributes = attribute_entries(&req.attributes)?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin replace attributes: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&claims.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Set attributes RLS context: {e}")))?;
    ensure_tenant_user_tx(&mut tx, &claims.tenant_id, &id).await?;
    sqlx::query("DELETE FROM user_attributes WHERE tenant_id = $1 AND user_id = $2")
        .bind(&claims.tenant_id)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Delete user attributes: {e}")))?;
    upsert_attributes(&mut tx, &claims.tenant_id, &id, attributes).await?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit replace attributes: {e}")))?;

    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    Ok(Json(
        fetch_user_attributes(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn patch_user_attributes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<AttributesRequest>,
) -> Result<Json<serde_json::Value>> {
    let attributes = attribute_entries(&req.attributes)?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin patch attributes: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&claims.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Set patch attributes RLS context: {e}")))?;
    ensure_tenant_user_tx(&mut tx, &claims.tenant_id, &id).await?;
    upsert_attributes(&mut tx, &claims.tenant_id, &id, attributes).await?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit patch attributes: {e}")))?;

    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    Ok(Json(
        fetch_user_attributes(&mut conn, &claims.tenant_id, &id).await?,
    ))
}

async fn impersonate_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ImpersonateRequest>,
) -> Result<(CookieJar, Json<ImpersonateResponse>)> {
    if claims.sub == id {
        return Err(AppError::BadRequest(
            "Cannot impersonate your own user".to_string(),
        ));
    }

    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let user = fetch_admin_user(&mut conn, &claims.tenant_id, &id).await?;
    if user.locked || user.banned {
        return Err(AppError::BadRequest(
            "Cannot impersonate a locked or banned user".to_string(),
        ));
    }

    let session_id = generate_id("sess_imp");
    let reason = req.reason.unwrap_or_else(|| "admin_console".to_string());
    let ip = extract_ip(&headers).to_string();
    let user_agent = extract_user_agent(&headers);
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin impersonation session: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(&claims.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Set impersonation RLS context: {e}")))?;
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, expires_at, tenant_id, session_type, decision_ref,
            aal_level, verified_capabilities, is_provisional, ip_address, user_agent,
            impersonated_by, impersonation_reason, impersonation_started_at
        )
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3, 'end_user', $4,
                1, $5, FALSE, $6::inet, $7, $8, $9, NOW())
        "#,
    )
    .bind(&session_id)
    .bind(&id)
    .bind(&claims.tenant_id)
    .bind(generate_id("dec_imp"))
    .bind(serde_json::json!(["admin_impersonation"]))
    .bind(&ip)
    .bind(&user_agent)
    .bind(&claims.sub)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Create impersonation session: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit impersonation session: {e}")))?;

    let jwt = state.jwt_service.generate_token_with_expiry(
        &id,
        &session_id,
        &claims.tenant_id,
        auth_core::jwt::session_types::END_USER,
        60 * 60,
    )?;
    let refresh_token = state.jwt_service.generate_token_with_expiry(
        &id,
        &session_id,
        &claims.tenant_id,
        auth_core::jwt::session_types::END_USER,
        60 * 60,
    )?;

    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let same_site = if is_secure {
        SameSite::Strict
    } else {
        SameSite::Lax
    };
    let jar = jar
        .add(
            Cookie::build(("__session", jwt.clone()))
                .http_only(true)
                .secure(is_secure)
                .path("/")
                .same_site(same_site)
                .build(),
        )
        .add(
            Cookie::build(("refresh_token", refresh_token))
                .http_only(true)
                .secure(is_secure)
                .path("/")
                .same_site(same_site)
                .build(),
        );

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::ADMIN_IMPERSONATION_STARTED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("user"),
            target_id: Some(id.clone()),
            ip_address: Some(extract_ip(&headers)),
            user_agent: Some(user_agent),
            metadata: serde_json::json!({
                "session_id": session_id,
                "reason": reason,
            }),
        })
        .await;

    let user_model = state.user_service.get_user(&id).await?;
    let user_response = state.user_service.to_user_response(&user_model).await?;
    Ok((
        jar,
        Json(ImpersonateResponse {
            jwt,
            session_id,
            tenant_id: claims.tenant_id,
            impersonated_by: claims.sub,
            user: user_response,
        }),
    ))
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
        .map_err(|_| AppError::Internal("Set admin users RLS context".into()))?;
    Ok(conn)
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

async fn ensure_tenant_user_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id = $1 AND user_id = $2)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Check tenant user: {e}")))?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound("User not found in tenant".to_string()))
    }
}

async fn fetch_admin_user(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
) -> Result<AdminUserResponse> {
    sqlx::query_as::<_, AdminUserResponse>(
        r#"
        SELECT u.id, u.created_at, u.updated_at, u.first_name, u.last_name,
               u.profile_image_url, u.banned, u.locked,
               email.identifier AS email, email.verified AS email_verified,
               phone.identifier AS phone, phone.verified AS phone_verified,
               m.role,
               u.public_metadata, u.private_metadata, u.unsafe_metadata,
               COALESCE(attrs.attributes, '{}'::jsonb) AS attributes
        FROM memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN identities email ON email.user_id = u.id
            AND email.type = 'email'
            AND email.organization_id = $1
        LEFT JOIN identities phone ON phone.user_id = u.id
            AND phone.type = 'phone'
            AND phone.organization_id = $1
        LEFT JOIN LATERAL (
            SELECT jsonb_object_agg(ua.key, ua.value) AS attributes
            FROM user_attributes ua
            WHERE ua.tenant_id = $1 AND ua.user_id = u.id
        ) attrs ON TRUE
        WHERE m.organization_id = $1
          AND u.id = $2
          AND u.deleted_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch admin user: {e}")))?
    .ok_or_else(|| AppError::NotFound("User not found in tenant".to_string()))
}

async fn fetch_user_attributes(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
) -> Result<serde_json::Value> {
    let attributes: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(jsonb_object_agg(key, value), '{}'::jsonb)
        FROM user_attributes
        WHERE tenant_id = $1 AND user_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&mut **conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch user attributes: {e}")))?;
    Ok(attributes)
}

async fn ensure_identity_available(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    identity_type: &str,
    identifier: &str,
    current_user_id: Option<&str>,
) -> Result<()> {
    let used_by_other: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM identities
            WHERE organization_id = $1
              AND type = $2
              AND identifier = $3
              AND ($4::text IS NULL OR user_id <> $4)
        )
        "#,
    )
    .bind(tenant_id)
    .bind(identity_type)
    .bind(identifier)
    .bind(current_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Check {identity_type} uniqueness: {e}")))?;
    if used_by_other {
        Err(AppError::Conflict(format!(
            "{identity_type} is already used in tenant"
        )))
    } else {
        Ok(())
    }
}

async fn insert_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
    identity_type: &str,
    identifier: &str,
    verified: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO identities (
            id, user_id, organization_id, type, identifier, verified, verified_at, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $6 THEN NOW() ELSE NULL END, NOW(), NOW())
        "#,
    )
    .bind(generate_id("ident"))
    .bind(user_id)
    .bind(tenant_id)
    .bind(identity_type)
    .bind(identifier)
    .bind(verified)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Create {identity_type} identity: {e}")))?;
    Ok(())
}

async fn upsert_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
    identity_type: &str,
    identifier: &str,
    verified: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO identities (
            id, user_id, organization_id, type, identifier, verified, verified_at, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $6 THEN NOW() ELSE NULL END, NOW(), NOW())
        ON CONFLICT (organization_id, type, identifier)
        DO UPDATE SET user_id = EXCLUDED.user_id,
                      verified = EXCLUDED.verified,
                      verified_at = CASE WHEN EXCLUDED.verified THEN NOW() ELSE NULL END,
                      updated_at = NOW()
        "#,
    )
    .bind(generate_id("ident"))
    .bind(user_id)
    .bind(tenant_id)
    .bind(identity_type)
    .bind(identifier)
    .bind(verified)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Upsert {identity_type} identity: {e}")))?;

    sqlx::query(
        r#"
        DELETE FROM identities
        WHERE organization_id = $1 AND user_id = $2 AND type = $3 AND identifier <> $4
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(identity_type)
    .bind(identifier)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Prune old {identity_type} identities: {e}")))?;
    Ok(())
}

async fn set_identity_verified(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
    identity_type: &str,
    verified: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE identities
        SET verified = $4,
            verified_at = CASE WHEN $4 THEN NOW() ELSE NULL END,
            updated_at = NOW()
        WHERE organization_id = $1 AND user_id = $2 AND type = $3
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(identity_type)
    .bind(verified)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Internal(format!("Set {identity_type} verification: {e}")))?;
    Ok(())
}

async fn upsert_attributes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    user_id: &str,
    attributes: Vec<(String, serde_json::Value)>,
) -> Result<()> {
    for (key, value) in attributes {
        sqlx::query(
            r#"
            INSERT INTO user_attributes (id, tenant_id, user_id, key, value)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, user_id, key)
            DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            "#,
        )
        .bind(generate_id("uattr"))
        .bind(tenant_id)
        .bind(user_id)
        .bind(&key)
        .bind(value)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Internal(format!("Upsert user attribute {key}: {e}")))?;
    }
    Ok(())
}

fn attribute_entries(value: &serde_json::Value) -> Result<Vec<(String, serde_json::Value)>> {
    let object = value
        .as_object()
        .ok_or_else(|| AppError::BadRequest("attributes must be a JSON object".to_string()))?;
    let mut entries = Vec::with_capacity(object.len());
    for (key, value) in object {
        if key.len() > 128
            || !key
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
            || !key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-'))
        {
            return Err(AppError::BadRequest(format!(
                "Invalid attribute key: {key}"
            )));
        }
        entries.push((key.clone(), value.clone()));
    }
    Ok(entries)
}

fn validate_phone(phone: Option<&str>) -> Result<()> {
    if let Some(phone) = phone {
        let phone = phone.trim();
        if phone.is_empty() || phone.len() > 50 {
            return Err(AppError::BadRequest("Invalid phone value".to_string()));
        }
    }
    Ok(())
}

fn extract_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
