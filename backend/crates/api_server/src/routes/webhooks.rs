//! Tenant Webhook routes
//!
//! ## Endpoints
//! - `GET    /api/v1/webhooks`             — List active webhook endpoints for the tenant
//! - `POST   /api/v1/webhooks`             — Register a new webhook endpoint
//! - `PUT    /api/v1/webhooks/:webhook_id` — Update a webhook endpoint
//! - `DELETE /api/v1/webhooks/:webhook_id` — Deactivate a webhook endpoint (soft delete)
//! - `POST   /api/v1/webhooks/:webhook_id/test` — Fire a synthetic test delivery
//!
//! ## Authorization
//! All routes require the `agent:manage` EIAA action (same as agent management routes).
//!
//! ## Security note
//! The `secret` field is stored in plaintext in the `tenant_webhooks` table.
//! On list/get responses the secret is masked so it is never re-transmitted
//! after initial creation. The full secret is only visible once — in the POST 201
//! response. This matches the Stripe / GitHub webhook UX that admins expect.

use crate::middleware::org_context::set_rls_context_on_conn;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

// ---- Request / Response types ------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    /// HTTPS URL to deliver events to.
    pub url: String,
    /// HMAC-SHA256 signing secret (provided by the admin).
    pub secret: String,
    /// Human-readable description (optional).
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    /// New URL (omit to keep existing).
    pub url: Option<String>,
    /// New HMAC secret (omit to keep existing).
    pub secret: Option<String>,
    /// New description (omit to keep existing).
    pub description: Option<String>,
    /// Enable or disable the endpoint.
    pub active: Option<bool>,
}

/// Row returned on list responses. Secret is masked after initial creation.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: String,
    pub url: String,
    /// Always "********" — never re-transmitted after creation.
    pub secret_masked: String,
    pub description: Option<String>,
    pub active: bool,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub last_delivery_status: Option<i32>,
    pub last_delivery_success: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Creation response — includes the full secret once.
#[derive(Debug, Serialize)]
pub struct CreateWebhookResponse {
    pub id: String,
    pub url: String,
    /// Returned in full on creation only. Store it now — it cannot be retrieved later.
    pub secret: String,
    pub description: Option<String>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

// ---- Router ------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/webhooks", get(list_webhooks).post(create_webhook))
        .route(
            "/webhooks/:webhook_id",
            put(update_webhook).delete(delete_webhook),
        )
        .route("/webhooks/:webhook_id/test", post(test_webhook))
}

// ---- Handlers ----------------------------------------------------------------

/// GET /api/v1/webhooks
async fn list_webhooks(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<WebhookRow>>> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set list_webhooks RLS context".into()))?;

    type WebhookTuple = (
        String,
        String,
        String,
        Option<String>,
        bool,
        Option<DateTime<Utc>>,
        Option<i32>,
        Option<bool>,
        DateTime<Utc>,
        DateTime<Utc>,
    );

    let rows: Vec<WebhookTuple> = sqlx::query_as(
        r#"
        SELECT id, url, secret, description, active,
               last_delivery_at, last_delivery_status, last_delivery_success,
               created_at, updated_at
        FROM tenant_webhooks
        WHERE tenant_id = $1 AND active = TRUE
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    let masked = rows
        .into_iter()
        .map(
            |(
                id,
                url,
                _secret,
                description,
                active,
                last_delivery_at,
                last_delivery_status,
                last_delivery_success,
                created_at,
                updated_at,
            )| WebhookRow {
                id,
                url,
                secret_masked: "********".into(),
                description,
                active,
                last_delivery_at,
                last_delivery_status,
                last_delivery_success,
                created_at,
                updated_at,
            },
        )
        .collect();

    Ok(Json(masked))
}

/// POST /api/v1/webhooks
async fn create_webhook(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<CreateWebhookResponse>)> {
    if !req.url.starts_with("https://") {
        return Err(AppError::Validation(
            "Webhook URL must use the https:// scheme".into(),
        ));
    }
    if req.secret.len() < 16 {
        return Err(AppError::Validation(
            "Webhook secret must be at least 16 characters".into(),
        ));
    }

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set create_webhook RLS context".into()))?;

    let (id, created_at): (String, DateTime<Utc>) = sqlx::query_as(
        r#"
        INSERT INTO tenant_webhooks (tenant_id, url, secret, description, event_type)
        VALUES ($1, $2, $3, $4, 'agent')
        RETURNING id, created_at
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&req.url)
    .bind(&req.secret)
    .bind(&req.description)
    .fetch_one(&mut *conn)
    .await?;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        webhook_id = %id,
        url = %req.url,
        "Tenant webhook registered"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateWebhookResponse {
            id,
            url: req.url,
            secret: req.secret,
            description: req.description,
            active: true,
            created_at,
        }),
    ))
}

/// PUT /api/v1/webhooks/:webhook_id
async fn update_webhook(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(webhook_id): Path<String>,
    Json(req): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookRow>> {
    if let Some(ref url) = req.url {
        if !url.starts_with("https://") {
            return Err(AppError::Validation(
                "Webhook URL must use the https:// scheme".into(),
            ));
        }
    }
    if let Some(ref secret) = req.secret {
        if secret.len() < 16 {
            return Err(AppError::Validation(
                "Webhook secret must be at least 16 characters".into(),
            ));
        }
    }

    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set update_webhook RLS context".into()))?;

    type WebhookTuple = (
        String,
        String,
        String,
        Option<String>,
        bool,
        Option<DateTime<Utc>>,
        Option<i32>,
        Option<bool>,
        DateTime<Utc>,
        DateTime<Utc>,
    );

    let row: Option<WebhookTuple> = sqlx::query_as(
        r#"
        UPDATE tenant_webhooks
        SET
            url         = COALESCE($3, url),
            secret      = COALESCE($4, secret),
            description = COALESCE($5, description),
            active      = COALESCE($6, active),
            updated_at  = NOW()
        WHERE tenant_id = $1 AND id = $2
        RETURNING id, url, secret, description, active,
                  last_delivery_at, last_delivery_status, last_delivery_success,
                  created_at, updated_at
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&webhook_id)
    .bind(&req.url)
    .bind(&req.secret)
    .bind(&req.description)
    .bind(req.active)
    .fetch_optional(&mut *conn)
    .await?;

    let (
        id,
        url,
        _secret,
        description,
        active,
        last_delivery_at,
        last_delivery_status,
        last_delivery_success,
        created_at,
        updated_at,
    ) = row.ok_or_else(|| AppError::NotFound(format!("Webhook '{webhook_id}' not found")))?;

    Ok(Json(WebhookRow {
        id,
        url,
        secret_masked: "********".into(),
        description,
        active,
        last_delivery_at,
        last_delivery_status,
        last_delivery_success,
        created_at,
        updated_at,
    }))
}

/// DELETE /api/v1/webhooks/:webhook_id
///
/// Soft-deactivates the webhook (sets active = FALSE). Does not destroy delivery history.
async fn delete_webhook(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(webhook_id): Path<String>,
) -> Result<StatusCode> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set delete_webhook RLS context".into()))?;

    let rows_affected = sqlx::query(
        r#"
        UPDATE tenant_webhooks
        SET active = FALSE, updated_at = NOW()
        WHERE tenant_id = $1 AND id = $2 AND active = TRUE
        "#,
    )
    .bind(&claims.tenant_id)
    .bind(&webhook_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "Webhook '{webhook_id}' not found or already inactive"
        )));
    }

    tracing::info!(
        tenant_id = %claims.tenant_id,
        webhook_id = %webhook_id,
        "Tenant webhook deactivated"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/webhooks/:webhook_id/test
///
/// Fires a synthetic `agent.action.authorized` event to the endpoint so admins
/// can verify their receiver is configured correctly. Uses the AgentWebhookService
/// delivery path (includes retry and HMAC signing).
async fn test_webhook(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(webhook_id): Path<String>,
) -> Result<StatusCode> {
    let mut conn = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, &claims.tenant_id)
        .await
        .map_err(|_| AppError::Internal("Set test_webhook RLS context".into()))?;

    // Verify the webhook exists and is active before dispatching
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM tenant_webhooks WHERE tenant_id = $1 AND id = $2 AND active = TRUE)",
    )
    .bind(&claims.tenant_id)
    .bind(&webhook_id)
    .fetch_one(&mut *conn)
    .await?;

    if !exists {
        return Err(AppError::NotFound(format!(
            "Webhook '{webhook_id}' not found"
        )));
    }

    use crate::services::agent_webhook_service::{AgentEventKind, AgentWebhookPayload};

    let payload = AgentWebhookPayload {
        event: AgentEventKind::AgentActionAuthorized,
        timestamp: Utc::now().to_rfc3339(),
        tenant_id: claims.tenant_id.clone(),
        task_id: Some("test_task_000000000000".into()),
        agent_id: Some("agt_test000000000000000000000000".into()),
        model_id: Some("test-model".into()),
        tool_name: Some("test_tool".into()),
        decision_ref: "test_decision_ref_00000000000000".into(),
        risk_score: Some(0),
        attestation_signature_b64: None,
    };

    // Fire-and-forget via the shared service (handles retry, HMAC signing, logging).
    state.agent_webhook_service.on_authorized(payload);

    tracing::info!(
        tenant_id = %claims.tenant_id,
        webhook_id = %webhook_id,
        "Test webhook delivery dispatched"
    );

    Ok(StatusCode::ACCEPTED)
}
