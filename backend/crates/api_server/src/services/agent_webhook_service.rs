//! Agent Webhook Service
//!
//! Delivers real-time EIAA agent decision events to tenant-configured HTTP
//! endpoints. Matches the Sprint D webhook spec from the AI Agent Authorization
//! feature plan.
//!
//! ## Three event types
//!
//! | Event | When fired |
//! |-------|------------|
//! | `agent.action.authorized` | Tool call capsule returned Allow |
//! | `agent.action.denied`     | Tool call capsule returned Deny  |
//! | `agent.task.completed`    | Final action in a task chain     |
//!
//! ## Reliability
//!
//! - Non-blocking delivery via `tokio::spawn` background task per event.
//! - Exponential back-off retry with jitter (3 attempts: 0 ms, ~1 s, ~4 s).
//! - HMAC-SHA256 signature on every payload (same model as Stripe webhooks).
//!   Signature header: `X-AuthStar-Signature: sha256=<hex>`.
//! - **Persistent DLQ**: after max retries are exhausted, the event is written
//!   to the `webhook_dlq` table so it survives process restarts and can be
//!   re-driven via the operator API.
//!
//! ## Re-delivery
//!
//! Operators call `POST /api/v1/webhooks/dlq/:id/redrive` to re-attempt a
//! dead-lettered event. The `redrive()` method on this service handles that.
//! The route handler lives in `routes/webhooks.rs`.

use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::sleep;

/// Event type discriminant
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentEventKind {
    /// Tool call capsule returned Allow
    #[serde(rename = "agent.action.authorized")]
    AgentActionAuthorized,
    /// Tool call capsule returned Deny
    #[serde(rename = "agent.action.denied")]
    AgentActionDenied,
    /// Final action in a task chain — task is now complete
    #[serde(rename = "agent.task.completed")]
    AgentTaskCompleted,
}

/// Webhook payload for all three agent event types.
///
/// Serialised as JSON and sent as the HTTP request body. Consumers can
/// discriminate on the `event` field before deserialising the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWebhookPayload {
    /// Event type (discriminant).
    pub event: AgentEventKind,
    /// ISO-8601 UTC timestamp of when the event was generated.
    pub timestamp: String,
    /// Tenant that owns the agent.
    pub tenant_id: String,
    /// Task identifier grouping related tool calls.
    pub task_id: Option<String>,
    /// Registered agent principal ID.
    pub agent_id: Option<String>,
    /// LLM model identifier.
    pub model_id: Option<String>,
    /// Tool that was authorized or denied.
    pub tool_name: Option<String>,
    /// Unique EIAA decision reference for audit linkage.
    pub decision_ref: String,
    /// Risk score evaluated during this decision (0–100).
    pub risk_score: Option<i32>,
    /// Base64url-encoded Ed25519 attestation signature.
    pub attestation_signature_b64: Option<String>,
}

/// Tenant webhook endpoint configuration (loaded from DB).
#[derive(Debug, Clone)]
pub struct WebhookEndpoint {
    pub id: String,
    /// HTTPS URL to deliver the event to.
    pub url: String,
    /// Shared secret for HMAC-SHA256 payload signing.
    pub secret: String,
}

/// Agent webhook service.
///
/// Cheap to clone — all fields are `Arc`-backed or `Clone`. Intended to live
/// in `AppState`.
#[derive(Clone)]
pub struct AgentWebhookService {
    client: Client,
    db: PgPool,
}

impl AgentWebhookService {
    /// Create a new service using the process-wide DB pool.
    pub fn new(db: PgPool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("AuthStar-AgentWebhook/1.0")
            .build()
            .expect("failed to build webhook HTTP client");
        Self { client, db }
    }

    /// Fire `agent.action.authorized` (non-blocking).
    pub fn on_authorized(&self, payload: AgentWebhookPayload) {
        self.dispatch(payload);
    }

    /// Fire `agent.action.denied` (non-blocking).
    pub fn on_denied(&self, payload: AgentWebhookPayload) {
        self.dispatch(payload);
    }

    /// Fire `agent.task.completed` (non-blocking).
    pub fn on_task_completed(&self, payload: AgentWebhookPayload) {
        self.dispatch(payload);
    }

    /// Re-drive a single DLQ entry identified by its `dlq_id`.
    ///
    /// Loads the stored payload and endpoint from the DB, attempts delivery
    /// (one attempt, no retry), and updates the DLQ row to `resolved` or
    /// `retrying`.
    ///
    /// Returns `Ok(true)` on successful delivery, `Ok(false)` on failure,
    /// `Err` on DB error.
    pub async fn redrive(
        &self,
        tenant_id: &str,
        dlq_id: &str,
    ) -> Result<bool, sqlx::Error> {
        // Load the DLQ entry
        let row: Option<(String, String, String, serde_json::Value, i32)> =
            sqlx::query_as(
                r#"
                SELECT webhook_id, url, event_type, payload_json, retry_count
                FROM webhook_dlq
                WHERE id = $1 AND tenant_id = $2 AND state IN ('pending', 'retrying')
                LIMIT 1
                "#,
            )
            .bind(dlq_id)
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await?;

        let (webhook_id, url, _event_type, payload_json, retry_count) = match row {
            Some(r) => r,
            None => return Ok(false), // not found or already resolved
        };

        // Load the current webhook secret (may have changed since the failure)
        let secret: Option<String> = sqlx::query_scalar(
            "SELECT secret FROM tenant_webhooks WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&webhook_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?;

        let Some(secret) = secret else {
            // Webhook deregistered — mark abandoned
            sqlx::query(
                "UPDATE webhook_dlq SET state = 'abandoned', updated_at = NOW() WHERE id = $1",
            )
            .bind(dlq_id)
            .execute(&self.db)
            .await?;
            return Ok(false);
        };

        let payload: AgentWebhookPayload =
            serde_json::from_value(payload_json).map_err(|e| {
                sqlx::Error::Decode(Box::new(e))
            })?;

        let endpoint = WebhookEndpoint { id: webhook_id, url, secret };

        // Mark as retrying
        sqlx::query(
            r#"
            UPDATE webhook_dlq
            SET state = 'retrying',
                retry_count = retry_count + 1,
                last_attempt_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(dlq_id)
        .execute(&self.db)
        .await?;

        let success = attempt_delivery(&self.client, &endpoint, &payload).await;

        if success {
            sqlx::query(
                r#"
                UPDATE webhook_dlq
                SET state = 'resolved',
                    resolved_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(dlq_id)
            .execute(&self.db)
            .await?;
            tracing::info!(
                tenant_id = %tenant_id,
                dlq_id = %dlq_id,
                retry_count = retry_count + 1,
                "Webhook DLQ entry redelivered successfully"
            );
        } else {
            sqlx::query(
                r#"
                UPDATE webhook_dlq
                SET state = 'pending',
                    next_retry_at = NOW() + INTERVAL '15 minutes',
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(dlq_id)
            .execute(&self.db)
            .await?;
            tracing::warn!(
                tenant_id = %tenant_id,
                dlq_id = %dlq_id,
                "Webhook DLQ re-drive failed — scheduled for retry in 15 minutes"
            );
        }

        Ok(success)
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    /// Spawn a background task to deliver `payload` to all configured
    /// endpoints. Returns immediately (fire-and-forget).
    fn dispatch(&self, payload: AgentWebhookPayload) {
        let client = self.client.clone();
        let db = self.db.clone();

        tokio::spawn(async move {
            let endpoints = match Self::load_endpoints(&db, &payload.tenant_id).await {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(
                        tenant_id = %payload.tenant_id,
                        event = ?payload.event,
                        error = %err,
                        "AgentWebhook: failed to load endpoints"
                    );
                    return;
                }
            };

            for endpoint in endpoints {
                let client = client.clone();
                let db = db.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    let success =
                        deliver_with_retry(&client, &endpoint, &payload).await;
                    if !success {
                        if let Err(e) =
                            write_dlq(&db, &endpoint, &payload, "max retries exhausted").await
                        {
                            tracing::error!(
                                webhook_id = %endpoint.id,
                                error = %e,
                                "AgentWebhook: failed to write DLQ entry"
                            );
                        }
                    }
                });
            }
        });
    }

    /// Load active webhook endpoints for a tenant, with dev env-var fallback.
    async fn load_endpoints(
        db: &PgPool,
        tenant_id: &str,
    ) -> Result<Vec<WebhookEndpoint>, sqlx::Error> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, url, secret FROM tenant_webhooks \
             WHERE tenant_id = $1 AND event_type = 'agent' AND active = TRUE",
        )
        .bind(tenant_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();

        let mut endpoints: Vec<WebhookEndpoint> = rows
            .into_iter()
            .map(|(id, url, secret)| WebhookEndpoint { id, url, secret })
            .collect();

        // Development fallback — single env-var endpoint
        if endpoints.is_empty() {
            if let (Ok(url), Ok(secret)) = (
                std::env::var("AGENT_WEBHOOK_URL"),
                std::env::var("AGENT_WEBHOOK_SECRET"),
            ) {
                if !url.is_empty() {
                    endpoints.push(WebhookEndpoint {
                        id: "dev_fallback".into(),
                        url,
                        secret,
                    });
                }
            }
        }

        Ok(endpoints)
    }
}

// ---------------------------------------------------------------------------
// Delivery helpers
// ---------------------------------------------------------------------------

/// Attempt a single HTTP delivery. Returns `true` on HTTP 2xx, `false` otherwise.
async fn attempt_delivery(
    client: &Client,
    endpoint: &WebhookEndpoint,
    payload: &AgentWebhookPayload,
) -> bool {
    let body = match serde_json::to_string(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("AgentWebhook: payload serialisation failed: {}", e);
            return false;
        }
    };

    let sig = hmac_sha256_hex(body.as_bytes(), endpoint.secret.as_bytes());
    let event_str = serde_json::to_value(&payload.event)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{:?}", payload.event).to_lowercase());

    match client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .header("X-AuthStar-Signature", format!("sha256={sig}"))
        .header("X-AuthStar-Event", event_str)
        .body(body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            tracing::warn!(
                url = %endpoint.url,
                status = %resp.status(),
                "AgentWebhook: non-success HTTP status"
            );
            false
        }
        Err(e) => {
            tracing::warn!(url = %endpoint.url, error = %e, "AgentWebhook: request failed");
            false
        }
    }
}

/// Attempt delivery up to 3 times with exponential back-off.
/// Returns `true` if any attempt succeeded.
async fn deliver_with_retry(
    client: &Client,
    endpoint: &WebhookEndpoint,
    payload: &AgentWebhookPayload,
) -> bool {
    const MAX_ATTEMPTS: u32 = 3;

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            // Exponential back-off: 1s * 2^(attempt-1) ± 50% jitter
            let base_ms: u64 = 1000 * (1 << (attempt - 1));
            let jitter_ms = (base_ms as f64 * 0.5 * rand_frac()) as u64;
            sleep(Duration::from_millis(base_ms + jitter_ms)).await;
        }

        if attempt_delivery(client, endpoint, payload).await {
            tracing::debug!(
                url = %endpoint.url,
                event = ?payload.event,
                decision_ref = %payload.decision_ref,
                "AgentWebhook: delivered successfully"
            );
            return true;
        }
    }

    tracing::warn!(
        url = %endpoint.url,
        event = ?payload.event,
        decision_ref = %payload.decision_ref,
        "AgentWebhook: max retries exhausted — writing to DLQ"
    );
    false
}

/// Persist a dead-lettered event to the `webhook_dlq` table.
async fn write_dlq(
    db: &PgPool,
    endpoint: &WebhookEndpoint,
    payload: &AgentWebhookPayload,
    last_error: &str,
) -> Result<(), sqlx::Error> {
    let event_type = serde_json::to_value(&payload.event)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());

    let payload_json = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);

    sqlx::query(
        r#"
        INSERT INTO webhook_dlq
            (tenant_id, webhook_id, url, event_type, decision_ref,
             payload_json, last_error, last_attempt_at,
             state, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), 'pending', NOW(), NOW())
        "#,
    )
    .bind(&payload.tenant_id)
    .bind(&endpoint.id)
    .bind(&endpoint.url)
    .bind(&event_type)
    .bind(&payload.decision_ref)
    .bind(&payload_json)
    .bind(last_error)
    .execute(db)
    .await?;

    tracing::info!(
        tenant_id    = %payload.tenant_id,
        webhook_id   = %endpoint.id,
        event_type   = %event_type,
        decision_ref = %payload.decision_ref,
        "AgentWebhook: event written to DLQ"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Crypto + random helpers
// ---------------------------------------------------------------------------

fn hmac_sha256_hex(data: &[u8], key: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn rand_frac() -> f64 {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345);
    (ns % 1000) as f64 / 1000.0
}

// ---------------------------------------------------------------------------
// Builder helper — creates payloads from AuditRecord fields
// ---------------------------------------------------------------------------

impl AgentWebhookPayload {
    /// Build a payload from the fields already captured in an `AuditRecord`.
    #[allow(dead_code)]
    pub fn from_audit(
        event: AgentEventKind,
        tenant_id: String,
        decision_ref: String,
        risk_score: Option<i32>,
        attestation_signature_b64: Option<String>,
        task_id: Option<String>,
        agent_id: Option<String>,
        model_id: Option<String>,
        tool_name: Option<String>,
    ) -> Self {
        Self {
            event,
            timestamp: Utc::now().to_rfc3339(),
            tenant_id,
            task_id,
            agent_id,
            model_id,
            tool_name,
            decision_ref,
            risk_score,
            attestation_signature_b64,
        }
    }
}
