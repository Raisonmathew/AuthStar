//! Agent Webhook Service
//!
//! Delivers real-time EIAA agent decision events to tenant-configured HTTP
//! endpoints. Matches the Sprint D webhook spec from the AI Agent Authorization
//! feature plan (`docs/AI_AGENT_AUTHORIZATION.md`).
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
//! - Non-blocking delivery via a `tokio::spawn` background task per event.
//! - Exponential back-off retry with jitter (3 attempts: 0s, 1±0.5s, 4±1s).
//! - HMAC-SHA256 signature on every payload (same model as Stripe webhooks).
//!   Signature header: `X-AuthStar-Signature: sha256=<hex>`.
//! - Dead-letter tracing warning after max retries exhausted.
//!
//! ## Tenant webhook configuration
//! Endpoints + secrets are stored in the `tenant_webhooks` table (to be
//! added in a follow-up migration). Until then, a static env-var fallback is
//! provided for development: `AGENT_WEBHOOK_URL` and `AGENT_WEBHOOK_SECRET`.

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

/// Tenant webhook endpoint configuration.
#[derive(Debug, Clone)]
pub struct WebhookEndpoint {
    /// HTTPS URL to deliver the event to.
    pub url: String,
    /// Shared secret for HMAC-SHA256 payload signing.
    pub secret: String,
}

/// Agent webhook service.
///
/// Cheap to clone — internally wraps an `Arc<reqwest::Client>` and the DB
/// pool behind an `Arc`. Intended to live in `AppState`.
#[derive(Clone)]
pub struct AgentWebhookService {
    client: Client,
    db: PgPool,
}

impl AgentWebhookService {
    /// Create a new service. `client` should be the process-wide singleton
    /// (built once in `AppState::new`).
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

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Spawn a background task to deliver *payload* to all configured
    /// endpoints. Returns immediately.
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
                        "AgentWebhook: failed to load endpoints: {}",
                        err
                    );
                    return;
                }
            };

            for endpoint in endpoints {
                let client = client.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    deliver_with_retry(&client, &endpoint, &payload).await;
                });
            }
        });
    }

    /// Load webhook endpoints for a tenant from the DB, falling back to the
    /// `AGENT_WEBHOOK_URL` + `AGENT_WEBHOOK_SECRET` env vars for development.
    async fn load_endpoints(
        db: &PgPool,
        tenant_id: &str,
    ) -> Result<Vec<WebhookEndpoint>, sqlx::Error> {
        // Query the tenant_webhooks table if it exists. The table is expected
        // to be added in a follow-up migration. Until then the query will
        // return an empty vec and we fall through to the env-var fallback.
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT url, secret FROM tenant_webhooks \
             WHERE tenant_id = $1 AND event_type = 'agent' AND active = TRUE",
        )
        .bind(tenant_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();

        let mut endpoints: Vec<WebhookEndpoint> = rows
            .into_iter()
            .map(|(url, secret)| WebhookEndpoint { url, secret })
            .collect();

        // Development fallback
        if endpoints.is_empty() {
            if let (Ok(url), Ok(secret)) = (
                std::env::var("AGENT_WEBHOOK_URL"),
                std::env::var("AGENT_WEBHOOK_SECRET"),
            ) {
                if !url.is_empty() {
                    endpoints.push(WebhookEndpoint { url, secret });
                }
            }
        }

        Ok(endpoints)
    }
}

// ---------------------------------------------------------------------------
// Delivery with exponential back-off retry + HMAC signature
// ---------------------------------------------------------------------------

/// Attempt to deliver *payload* to *endpoint* up to 3 times with exponential
/// back-off (0 ms, ~1 s, ~4 s). Logs a warning on final failure.
async fn deliver_with_retry(
    client: &Client,
    endpoint: &WebhookEndpoint,
    payload: &AgentWebhookPayload,
) {
    const MAX_ATTEMPTS: u32 = 3;

    let body = match serde_json::to_string(payload) {
        Ok(b) => b,
        Err(err) => {
            tracing::error!("AgentWebhook: payload serialisation failed: {}", err);
            return;
        }
    };

    let sig = hmac_sha256_hex(body.as_bytes(), endpoint.secret.as_bytes());

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            // Exponential back-off: 1s * 2^(attempt-1) with ±50% jitter
            let base_ms: u64 = 1000 * (1 << (attempt - 1));
            let jitter_ms = (base_ms as f64 * 0.5 * rand_frac()) as u64;
            sleep(Duration::from_millis(base_ms + jitter_ms)).await;
        }

        // MED-5 FIX: Use serde to serialise the event kind so the header value
        // matches the documented dot-separated format ("agent.action.authorized",
        // "agent.action.denied", "agent.task.completed").
        // `{:?}` on the enum variant produces "AgentActionAuthorized" which,
        // after `.to_lowercase()`, becomes "agentactionauthorized" — not
        // dot-separated and impossible to route on in webhook consumers.
        let event_str = serde_json::to_value(&payload.event)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{:?}", payload.event).to_lowercase());
        let result = client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-AuthStar-Signature", format!("sha256={sig}"))
            .header("X-AuthStar-Event", event_str)
            .body(body.clone())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    url = %endpoint.url,
                    event = ?payload.event,
                    decision_ref = %payload.decision_ref,
                    "AgentWebhook: delivered successfully"
                );
                return;
            }
            Ok(resp) => {
                tracing::warn!(
                    url = %endpoint.url,
                    status = %resp.status(),
                    attempt = attempt + 1,
                    "AgentWebhook: non-success HTTP status, will retry"
                );
            }
            Err(err) => {
                tracing::warn!(
                    url = %endpoint.url,
                    attempt = attempt + 1,
                    "AgentWebhook: request failed ({}), will retry",
                    err
                );
            }
        }
    }

    tracing::warn!(
        url = %endpoint.url,
        event = ?payload.event,
        decision_ref = %payload.decision_ref,
        "AgentWebhook: max retries exhausted — dead-lettering event"
    );
}

/// Compute HMAC-SHA256 of `data` with `key`, returning a lowercase hex string.
fn hmac_sha256_hex(data: &[u8], key: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Cheap pseudo-random fraction in [0, 1) using the current nanosecond count.
/// Not cryptographically random — used only for jitter in back-off timing.
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
    /// Build a payload from the fields that are already captured in an
    /// `AuditRecord` (Sprint C). Call this inside the EIAA authz middleware
    /// after the capsule decision is written.
    ///
    /// MED-3: This constructor is currently unused — the middleware constructs
    /// payloads as inline struct literals. It is retained as a convenience API
    /// for callers that already have an AuditRecord.
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
