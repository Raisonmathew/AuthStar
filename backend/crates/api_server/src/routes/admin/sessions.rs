use crate::db::pool_manager::PoolType;
use crate::middleware::tenant_conn::TenantConn;
use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::Result;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_sessions))
        .route("/:session_id", delete(revoke_session))
        .route("/user/:user_id", delete(revoke_user_sessions))
}

#[derive(Deserialize)]
struct ListQuery {
    user_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(sqlx::FromRow, Serialize)]
struct SessionInfo {
    id: String,
    user_id: String,
    is_provisional: bool,
    revoked: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn list_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<SessionInfo>>> {
    let read_pool = state.db_pools.get_pool(PoolType::Replica);
    let sessions = if let Some(ref uid) = params.user_id {
        sqlx::query_as::<_, SessionInfo>(
            "SELECT id, user_id, is_provisional, revoked, created_at, expires_at, revoked_at \
             FROM sessions WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY created_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(&claims.tenant_id)
        .bind(uid)
        .bind(params.limit)
        .bind(params.offset)
        .fetch_all(read_pool)
        .await?
    } else {
        sqlx::query_as::<_, SessionInfo>(
            "SELECT id, user_id, is_provisional, revoked, created_at, expires_at, revoked_at \
             FROM sessions WHERE tenant_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(&claims.tenant_id)
        .bind(params.limit)
        .bind(params.offset)
        .fetch_all(read_pool)
        .await?
    };
    Ok(Json(sessions))
}

async fn revoke_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // RLS defense-in-depth: TenantConn sets app.current_org_id on the connection
    let mut conn = TenantConn::acquire(&state.db, &claims.tenant_id).await?;
    let result = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW()) \
         WHERE id = $1 AND tenant_id = $2 AND revoked = FALSE",
    )
    .bind(&session_id)
    .bind(&claims.tenant_id)
    .execute(&mut **conn)
    .await?;

    if result.rows_affected() > 0 {
        state
            .audit_event_service
            .record(RecordEventParams {
                tenant_id: claims.tenant_id.clone(),
                event_type: event_types::SESSION_REVOKED,
                actor_id: Some(claims.sub.clone()),
                actor_email: None,
                target_type: Some("session"),
                target_id: Some(session_id.clone()),
                ip_address: None,
                user_agent: None,
                metadata: serde_json::json!({}),
            })
            .await;
    }

    Ok(Json(serde_json::json!({
        "revoked": result.rows_affected() > 0,
        "session_id": session_id
    })))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // RLS defense-in-depth: TenantConn sets app.current_org_id on the connection
    let mut conn = TenantConn::acquire(&state.db, &claims.tenant_id).await?;
    let result = sqlx::query(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW()) \
         WHERE tenant_id = $1 AND user_id = $2 AND revoked = FALSE AND expires_at > NOW()",
    )
    .bind(&claims.tenant_id)
    .bind(&user_id)
    .execute(&mut **conn)
    .await?;

    if result.rows_affected() > 0 {
        state
            .audit_event_service
            .record(RecordEventParams {
                tenant_id: claims.tenant_id.clone(),
                event_type: event_types::SESSION_REVOKED_ALL,
                actor_id: Some(claims.sub.clone()),
                actor_email: None,
                target_type: Some("user"),
                target_id: Some(user_id.clone()),
                ip_address: None,
                user_agent: None,
                metadata: serde_json::json!({"revoked_count": result.rows_affected()}),
            })
            .await;
    }

    Ok(Json(serde_json::json!({
        "revoked_count": result.rows_affected(),
        "user_id": user_id
    })))
}
