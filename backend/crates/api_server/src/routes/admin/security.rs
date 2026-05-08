use crate::middleware::org_context::set_rls_context_on_conn;
use crate::services::credential_lockout::FactorKind;
use crate::services::{UpdateCredentialLockoutPolicyRequest, UpdatePasswordPolicyRequest};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/password-policy",
            get(get_password_policy).put(update_password_policy),
        )
        .route(
            "/lockout-policy",
            get(get_lockout_policy).put(update_lockout_policy),
        )
        .route("/lockout-policies", get(get_lockout_policies))
        .route(
            "/lockout-policy/:factor_kind",
            get(get_factor_lockout_policy).put(update_factor_lockout_policy),
        )
        .route("/locked-users", get(get_locked_users))
        .route("/lockout/:user_id/state", get(get_lockout_state))
        .route("/lockout/:user_id/reset", post(reset_lockout))
}

async fn get_password_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<crate::services::PasswordPolicy>> {
    Ok(Json(
        state
            .password_policy_service
            .get_policy(&claims.tenant_id)
            .await?,
    ))
}

async fn update_password_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdatePasswordPolicyRequest>,
) -> Result<Json<crate::services::PasswordPolicy>> {
    Ok(Json(
        state
            .password_policy_service
            .update_policy(&claims.tenant_id, req)
            .await?,
    ))
}

async fn get_lockout_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<crate::services::CredentialLockoutPolicy>> {
    Ok(Json(
        state
            .credential_lockout_service
            .get_policy(&claims.tenant_id, FactorKind::Password)
            .await?,
    ))
}

async fn update_lockout_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdateCredentialLockoutPolicyRequest>,
) -> Result<Json<crate::services::CredentialLockoutPolicy>> {
    Ok(Json(
        state
            .credential_lockout_service
            .update_policy(&claims.tenant_id, FactorKind::Password, req)
            .await?,
    ))
}

async fn get_lockout_policies(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::services::CredentialLockoutPolicy>>> {
    let mut policies = Vec::with_capacity(FactorKind::ALL.len());
    for factor in FactorKind::ALL {
        policies.push(
            state
                .credential_lockout_service
                .get_policy(&claims.tenant_id, factor)
                .await?,
        );
    }
    Ok(Json(policies))
}

async fn get_factor_lockout_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(factor_kind): Path<String>,
) -> Result<Json<crate::services::CredentialLockoutPolicy>> {
    Ok(Json(
        state
            .credential_lockout_service
            .get_policy(&claims.tenant_id, parse_factor_kind(&factor_kind)?)
            .await?,
    ))
}

async fn update_factor_lockout_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(factor_kind): Path<String>,
    Json(req): Json<UpdateCredentialLockoutPolicyRequest>,
) -> Result<Json<crate::services::CredentialLockoutPolicy>> {
    Ok(Json(
        state
            .credential_lockout_service
            .update_policy(&claims.tenant_id, parse_factor_kind(&factor_kind)?, req)
            .await?,
    ))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct LockoutStateResponse {
    user_id: String,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    account_locked: bool,
    account_locked_at: Option<DateTime<Utc>>,
    last_1h: i32,
    last_24h: i32,
    locked_until: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
}

async fn get_locked_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<LockoutStateResponse>>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;
    let rows = sqlx::query_as::<_, LockoutStateResponse>(
        r#"
        SELECT u.id AS user_id,
               email.identifier AS email,
               u.first_name,
               u.last_name,
               u.locked AS account_locked,
               u.locked_at AS account_locked_at,
               COALESCE(c.last_1h, 0) AS last_1h,
               COALESCE(c.last_24h, 0) AS last_24h,
               c.locked_until,
               c.last_failure_at,
               c.last_success_at
        FROM memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN identities email ON email.user_id = u.id
            AND email.type = 'email'
            AND email.organization_id = $1
        LEFT JOIN credential_attempt_counters c ON c.tenant_id = $1
            AND c.user_id = u.id
            AND c.factor_kind = 'password'
        WHERE m.organization_id = $1
          AND u.deleted_at IS NULL
          AND (u.locked = TRUE OR c.locked_until > NOW())
        ORDER BY COALESCE(c.locked_until, u.locked_at) DESC NULLS LAST
        LIMIT 200
        "#,
    )
    .bind(&claims.tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch locked users: {e}")))?;
    Ok(Json(rows))
}

async fn get_lockout_state(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<LockoutStateResponse>> {
    Ok(Json(
        fetch_lockout_state(&state, &claims.tenant_id, &user_id).await?,
    ))
}

async fn reset_lockout(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<LockoutStateResponse>> {
    let mut conn = tenant_conn(&state, &claims.tenant_id).await?;

    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM memberships
            WHERE organization_id = $1 AND user_id = $2
        )
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Check tenant user: {e}")))?;

    if !exists {
        return Err(AppError::NotFound("User not found in tenant".to_string()));
    }

    // Reset all factor counters so an admin "reset lockout" action truly clears
    // every credential channel — matches the semantics of clearing the
    // account-level `users.locked` flag below.
    for factor in FactorKind::ALL {
        state
            .credential_lockout_service
            .reset_user_factor(&claims.tenant_id, &user_id, factor)
            .await?;
    }

    sqlx::query(
        r#"
        UPDATE users
        SET locked = FALSE,
            locked_at = NULL,
            failed_login_attempts = 0,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&user_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Unlock user after lockout reset: {e}")))?;

    let lockout_state = fetch_lockout_state(&state, &claims.tenant_id, &user_id).await?;

    Ok(Json(lockout_state))
}

async fn fetch_lockout_state(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
) -> Result<LockoutStateResponse> {
    let mut conn = tenant_conn(state, tenant_id).await?;
    sqlx::query_as::<_, LockoutStateResponse>(
        r#"
        SELECT u.id AS user_id,
               email.identifier AS email,
               u.first_name,
               u.last_name,
               u.locked AS account_locked,
               u.locked_at AS account_locked_at,
               COALESCE(c.last_1h, 0) AS last_1h,
               COALESCE(c.last_24h, 0) AS last_24h,
               c.locked_until,
               c.last_failure_at,
               c.last_success_at
        FROM memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN identities email ON email.user_id = u.id
            AND email.type = 'email'
            AND email.organization_id = $1
        LEFT JOIN credential_attempt_counters c ON c.tenant_id = $1
            AND c.user_id = u.id
            AND c.factor_kind = 'password'
        WHERE m.organization_id = $1
          AND m.user_id = $2
          AND u.deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch lockout state: {e}")))?
    .ok_or_else(|| AppError::NotFound("User not found in tenant".to_string()))
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
        .map_err(|_| AppError::Internal("Set security route RLS context".into()))?;
    Ok(conn)
}

fn parse_factor_kind(factor_kind: &str) -> Result<FactorKind> {
    match factor_kind {
        "password" => Ok(FactorKind::Password),
        "totp" => Ok(FactorKind::Totp),
        "hotp" => Ok(FactorKind::Hotp),
        "webauthn" => Ok(FactorKind::WebAuthn),
        "recovery_code" => Ok(FactorKind::RecoveryCode),
        "sms" => Ok(FactorKind::Sms),
        "email" => Ok(FactorKind::Email),
        _ => Err(AppError::Validation(format!(
            "Unsupported lockout factor '{factor_kind}'"
        ))),
    }
}
