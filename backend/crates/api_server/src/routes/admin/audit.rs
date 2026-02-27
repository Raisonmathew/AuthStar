use axum::{
    Router, 
    routing::get, 
    extract::{State, Path}, 
    Json,
    http::HeaderMap,
};
use crate::state::AppState;
use serde::Serialize;
use shared_types::{Result, AppError};
use chrono::{DateTime, Utc};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_executions))
        .route("/:id", get(get_execution))
}

/*
#[derive(Serialize, sqlx::FromRow)]
struct ExecutionLog {
    id: String,
    created_at: DateTime<Utc>,
    capsule_id: Option<String>,
    capsule_hash_b64: String,
    decision: serde_json::Value,
    // attestation: serde_json::Value, // Heavy, maybe load detailed only
    nonce_b64: String,
    client_id: Option<String>,
    #[sqlx(try_from = "ipnetwork::IpNetwork")]
    ip_address: Option<std::net::IpAddr>, 
}
*/

// Custom IpAddr handling if needed, or use simple string cast in query if sqlx-postgres types unavailable
// For simplicity, let's just use JSON or String for IP if types conflict, but sqlx has `ipnetwork`.
// Let's assume we might need to cast IP to text in SQL to avoid type issues for now.

#[derive(Serialize, sqlx::FromRow)]
struct ExecutionLogSimple {
    id: String,
    created_at: DateTime<Utc>,
    capsule_id: Option<String>,
    capsule_hash_b64: String,
    decision: serde_json::Value,
    nonce_b64: String,
    client_id: Option<String>,
    // ip_address handled as text
    ip_text: Option<String>,
}

/// Extract tenant_id from Authorization header
async fn extract_tenant_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".into()))?;

    let claims = state.jwt_service.verify_token(token)?;
    Ok(claims.tenant_id)
}

async fn list_executions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ExecutionLogSimple>>> {
    // Note: eiaa_executions doesn't strictly enforce tenant_id partition in the schema shown earlier (it's global?), 
    // but capsules have tenant_id. We should join.
    // However, schema `eiaa_executions` in `006_eiaa.sql` does NOT have tenant_id. 
    // It is linked via `capsule_id` -> `eiaa_capsules.tenant_id`.
    // We must join to filter by tenant.
    
    let tenant_id = extract_tenant_id(&state, &headers).await?;

    let logs = sqlx::query_as::<_, ExecutionLogSimple>(
        r#"
        SELECT 
            e.id, e.created_at, e.capsule_id, e.capsule_hash_b64, e.decision, e.nonce_b64, e.client_id,
            e.ip_address::text as ip_text
        FROM eiaa_executions e
        LEFT JOIN eiaa_capsules c ON e.capsule_hash_b64 = c.capsule_hash_b64
        WHERE c.tenant_id = $1
        ORDER BY e.created_at DESC
        LIMIT 50
        "#
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(logs))
}

async fn get_execution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let tenant_id = extract_tenant_id(&state, &headers).await?;

    // Return full details including attestation — scoped to tenant
    let log = sqlx::query_as::<_, (serde_json::Value,)>(
        "SELECT to_jsonb(e.*) FROM eiaa_executions e WHERE id = $1 AND tenant_id = $2"
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .map(|r| r.0)
    .ok_or_else(|| shared_types::AppError::NotFound("Log not found".into()))?;

    Ok(Json(log))
}
