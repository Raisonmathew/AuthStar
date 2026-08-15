//! EIAA Authorization Middleware (Production-Grade)
//!
//! Tower middleware that executes capsule-based authorization for protected routes.
//!
//! ## Architecture
//! This middleware follows the EIAA mental model:
//! - JWT = Identity (who you are)
//! - Attestation = Authorization (what you can do right now)
//!
//! ## Design Patterns
//! - **Decorator**: Wraps inner service with authorization logic
//! - **Builder**: Uses `AuthorizationContextBuilder` for rich context
//! - **Strategy**: Uses `AttestationVerifier` for signature verification
//! - **Cache-Aside**: Uses `RuntimeKeyCache` for public key caching
//!
//! ## Security Properties
//! 1. Context is enriched with IP, User-Agent, Risk Score from Risk Engine
//! 2. Runtime attestation signatures are cryptographically verified
//! 3. All decisions are audited with full context
//! 4. Fail-closed by default (configurable for dev)

use crate::clients::runtime_client::SharedRuntimeClient;
use crate::middleware::authorization_context::AuthorizationContextBuilder;
use crate::services::eiaa_flow_service::EiaaFlowService;
use crate::services::{
    attestation_verifier::{
        Attestation as VerifierAttestation, AttestationBody as VerifierAttestationBody,
        Decision as VerifierDecision, Requirement,
    },
    AttestationVerifier, AuditDecision, AuditRecord, AuditWriter, CapsuleCacheService, NonceStore,
    RuntimeKeyCache,
};
use auth_core::Claims;
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures_util::future::BoxFuture;
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared_types::{AppError, RiskLevel};
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
// Full Risk Engine integration
use risk_engine::{NetworkInput, RequestContext as RiskRequestContext, RiskEngine, SubjectContext};
use shared_types::auth::RiskContext as SharedRiskContext;
use shared_types::AssuranceLevel;
// Attestation frequency matrix
use crate::middleware::action_risk::ActionRiskLevel;
use crate::services::{AttestationDecisionCache, CacheDecisionParams};
use auth_core::JwtService;
use keystore::{InMemoryKeystore, KeyId};
use risk_engine::rules::{derive_required_aal, AalRequirement};
use redis::aio::ConnectionManager as RedisConnectionManager;
use sqlx::PgPool;
use std::sync::Arc as StdArc;

/// EIAA Authorization Layer (Production-Grade)
///
/// Apply to routes that require capsule-based authorization:
/// ```rust,ignore
/// Router::new()
///     .route("/billing", get(get_billing))
///     .layer(EiaaAuthzLayer::new("billing:read", config.clone()))
/// ```
#[derive(Clone)]
pub struct EiaaAuthzLayer {
    action: String,
    config: Arc<EiaaAuthzConfig>,
}

/// Configuration for the EIAA authorization middleware.
#[derive(Clone)]
pub struct EiaaAuthzConfig {
    /// gRPC address of the EIAA runtime
    #[allow(dead_code)] // config field populated at startup, read when gRPC calls are wired
    pub runtime_addr: String,
    /// Capsule cache service
    pub cache: Option<CapsuleCacheService>,
    /// Audit writer for logging decisions
    pub audit_writer: Option<AuditWriter>,
    /// Runtime key cache for signature verification
    pub key_cache: Option<RuntimeKeyCache>,
    /// Attestation verifier
    pub verifier: Option<AttestationVerifier>,
    /// EIAA flow service for risk evaluation
    #[allow(dead_code)]
    // config field populated at startup, read when flow evaluation is wired
    pub flow_service: Option<EiaaFlowService>,
    /// Risk Engine for real-time risk evaluation
    pub risk_engine: Option<RiskEngine>,
    /// Attestation decision cache for frequency matrix
    pub decision_cache: Option<AttestationDecisionCache>,
    /// If true, allow request when runtime is unavailable (DANGER: dev only)
    pub fail_open: bool,
    /// If true, skip signature verification (DANGER: dev only)
    pub skip_verification: bool,
    /// Risk score threshold for automatic denial (0 = disabled)
    pub risk_threshold: f64,
    /// If true, allow provisional sessions (use for step-up routes)
    pub allow_provisional: bool,
    /// JWT service for token verification (optional - if None, expects Claims in extensions)
    pub jwt_service: Option<StdArc<JwtService>>,
    /// Database pool for session verification AND capsule DB fallback
    ///
    /// CRITICAL-EIAA-3 FIX: When the capsule is not found in Redis cache, we fall back
    /// to loading the active capsule from the `eiaa_capsules` table in the database.
    /// This prevents a cache miss from causing a 500 error on every request after a
    /// Redis restart or cache eviction.
    pub db: Option<PgPool>,
    /// Persistent nonce store for replay protection.
    ///
    /// HIGH-EIAA-3 FIX: Replaces the in-memory HashSet used by the runtime service.
    /// Every capsule execution nonce is checked against and written to this store,
    /// which persists to PostgreSQL (with optional Redis fast path) so replay
    /// protection survives service restarts.
    ///
    /// If None, nonce replay protection is disabled (DANGER: dev only).
    pub nonce_store: Option<NonceStore>,
    /// GAP-1 FIX: Shared singleton gRPC client with a process-wide circuit breaker.
    ///
    /// When set, `execute_authorization` and `verify_attestation` use this client
    /// instead of calling `EiaaRuntimeClient::connect()` per-request. This ensures:
    ///   - The circuit breaker state is shared across all concurrent requests.
    ///   - A single TCP connection is reused (HTTP/2 multiplexing).
    ///
    /// If None (e.g. in unit tests), falls back to the legacy per-request connect.
    pub runtime_client: Option<SharedRuntimeClient>,
    /// Keystore for on-demand capsule compilation when no pre-compiled capsule exists.
    pub keystore: Option<InMemoryKeystore>,
    /// Compiler key ID for on-demand capsule compilation.
    pub compiler_kid: Option<KeyId>,
    /// T1.2 — per-credential failed-attempt counters for capsule decisions.
    pub credential_lockout_service: Option<crate::services::CredentialLockoutService>,
    /// T1.1 — pending required actions for capsule decisions.
    pub required_action_service: Option<crate::services::RequiredActionService>,
    /// Sprint F — Redis connection for agent token blocklist enforcement.
    /// If None, inline blocklist check is skipped (enforcement falls back to
    /// the introspection endpoint which always checks Redis).
    pub redis: Option<RedisConnectionManager>,
    /// Sprint G — SPIFFE trust domain for JWT-SVID workload identity.
    ///
    /// When set, the middleware extracts the `X-SPIFFE-SVID` request header,
    /// decodes the JWT-SVID (without signature verification — the SPIRE agent
    /// on the pod guarantees the token is genuine), and validates that the
    /// `sub` claim follows `spiffe://<trust_domain>/...`. On success,
    /// `principal_source` in the `RuntimeContext` is set to `"spiffe"` and the
    /// claims `sub` is overwritten with the SPIFFE ID so audits carry the
    /// workload identity. On failure the request is rejected (fail-closed).
    ///
    /// If None, `X-SPIFFE-SVID` headers are silently ignored.
    pub spiffe_trust_domain: Option<String>,
    /// Sprint D — Agent webhook delivery service.
    ///
    /// When set, fires `agent.action.authorized` / `agent.action.denied`
    /// events after every capsule decision for an agent JWT.  Non-blocking:
    /// delivery runs in a `tokio::spawn` background task.
    ///
    /// If None, agent webhook delivery is silently skipped.
    pub agent_webhook_service: Option<crate::services::AgentWebhookService>,
}

impl EiaaAuthzConfig {
    /// Build the production EIAA middleware config from application state.
    pub fn from_state(state: &crate::state::AppState) -> Self {
        Self {
            runtime_addr: state.config.eiaa.runtime_grpc_addr.clone(),
            cache: Some(state.capsule_cache.clone()),
            audit_writer: Some(state.audit_writer.clone()),
            key_cache: Some(state.runtime_key_cache.clone()),
            verifier: Some(state.attestation_verifier.clone()),
            flow_service: Some(state.eiaa_flow_service.clone()),
            risk_engine: Some(state.risk_engine.clone()),
            decision_cache: Some(state.decision_cache.clone()),
            fail_open: false,
            skip_verification: false,
            risk_threshold: state.config.eiaa.risk_threshold,
            allow_provisional: false,
            jwt_service: Some(state.jwt_service.clone()),
            db: Some(state.db.clone()),
            nonce_store: Some(state.nonce_store.clone()),
            runtime_client: Some(state.runtime_client.clone()),
            keystore: Some(state.ks.clone()),
            compiler_kid: Some(state.compiler_kid.clone()),
            credential_lockout_service: Some(state.credential_lockout_service.clone()),
            required_action_service: Some(state.required_action_service.clone()),
            redis: Some(state.redis.clone()),
            spiffe_trust_domain: state.config.eiaa.spiffe_trust_domain.clone(),
            agent_webhook_service: Some(state.agent_webhook_service.clone()),
        }
    }
}

/// EIAA decision metadata that downstream route handlers can bind to protocol state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EiaaDecisionArtifact {
    pub decision_ref: String,
    pub action: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<VerifierAttestation>,
}

/// Route-level OAuth/OIDC EIAA evaluation request.
pub struct OAuthEiaaRequest<'a> {
    pub action: &'a str,
    pub subject_id: &'a str,
    pub tenant_id: &'a str,
    pub session_id: Option<&'a str>,
    pub session_type: &'a str,
    pub client_id: &'a str,
    pub scope: Option<&'a str>,
    pub grant_type: Option<&'a str>,
    pub method: &'a str,
    pub path: &'a str,
    /// Owned snapshot of network/identification headers extracted at the
    /// call site. Owning the values (instead of borrowing the full
    /// `HeaderMap`) avoids forcing callers to hold the borrow across awaits.
    pub network: OAuthEiaaNetwork,
    pub confirmation_jkt: Option<&'a str>,
    // ── Agent-specific fields (all optional, default None) ──────────────────
    /// LLM model identifier from the agent JWT — required for VerifyAgentIdentity
    /// capsule steps to match the registered model_id.
    pub agent_model_id: Option<String>,
    /// Agent principal identifier from the JWT `agent_id` claim.
    pub agent_id_claim: Option<String>,
    /// Task identifier from the JWT `task_id` claim.
    pub agent_task_id: Option<String>,
    /// Delegation chain from the JWT (ordered newest-first).
    pub agent_delegation_chain: Option<Vec<String>>,
}

/// Owned subset of request headers required by `evaluate_oauth_action`.
#[derive(Debug, Clone, Default)]
pub struct OAuthEiaaNetwork {
    pub remote_ip: Option<IpAddr>,
    pub forwarded_for: Option<String>,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
}

impl OAuthEiaaNetwork {
    /// Extract the network/identification fields needed for EIAA evaluation
    /// from an Axum `HeaderMap`. The returned struct owns its data so the
    /// original `HeaderMap` need not outlive the evaluation future.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let forwarded_for = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let real_ip = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let remote_ip = forwarded_for
            .as_deref()
            .and_then(|v| v.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .or_else(|| real_ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok()));
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let accept_language = headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Self {
            remote_ip,
            forwarded_for,
            user_agent,
            accept_language,
        }
    }
}

impl Default for EiaaAuthzConfig {
    fn default() -> Self {
        Self {
            runtime_addr: "http://localhost:50051".to_string(),
            cache: None,
            audit_writer: None,
            key_cache: None,
            verifier: None,
            flow_service: None,
            risk_engine: None,
            decision_cache: None,
            fail_open: false,
            skip_verification: false,
            risk_threshold: 80.0, // Block if risk > 80
            allow_provisional: false,
            jwt_service: None,
            db: None,
            nonce_store: None,
            runtime_client: None,
            keystore: None,
            compiler_kid: None,
            credential_lockout_service: None,
            required_action_service: None,
            redis: None,
            spiffe_trust_domain: None,
            agent_webhook_service: None,
        }
    }
}

impl EiaaAuthzLayer {
    pub fn new(action: &str, config: EiaaAuthzConfig) -> Self {
        Self {
            action: action.to_string(),
            config: Arc::new(config),
        }
    }

    /// Type-safe constructor using the `Action` enum.
    pub fn action(
        action: crate::middleware::eiaa_actions::Action,
        config: EiaaAuthzConfig,
    ) -> Self {
        Self::new(action.as_str(), config)
    }
}

impl<S> Layer<S> for EiaaAuthzLayer {
    type Service = EiaaAuthzService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EiaaAuthzService {
            inner,
            action: self.action.clone(),
            config: self.config.clone(),
        }
    }
}

/// EIAA Authorization Service (Tower Service implementation)
#[derive(Clone)]
pub struct EiaaAuthzService<S> {
    inner: S,
    action: String,
    config: Arc<EiaaAuthzConfig>,
}

impl<S> Service<Request<Body>> for EiaaAuthzService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let action = self.action.clone();
        let config = self.config.clone();

        Box::pin(async move {
            // === Step 1: Extract or Verify Claims ===
            let mut req = req;
            let mut claims = if let Some(claims) = req.extensions().get::<Claims>() {
                claims.clone()
            } else {
                // Extract token synchronously before async operations
                let token = match extract_token(&req) {
                    Some(token) => token,
                    None => {
                        tracing::warn!(action = %action, "EIAA authz: No authentication token found");
                        return Ok(unauthorized_response("Missing or invalid authentication"));
                    }
                };

                // Verify token and session (async, but only uses owned data now)
                match verify_token_and_session(&token, &config).await {
                    Ok(claims) => {
                        // Insert claims into extensions for downstream handlers
                        req.extensions_mut().insert(claims.clone());
                        claims
                    }
                    Err(_) => {
                        tracing::warn!(action = %action, "EIAA authz: Authentication failed");
                        return Ok(unauthorized_response("Missing or invalid authentication"));
                    }
                }
            };

            // === Step 1.5 (Sprint F): Agent Token Blocklist Check ===
            //
            // Agent tokens use an empty `sid` so they cannot be revoked through the
            // normal session store.  Instead, `POST /api/v1/agents/:agent_id/revoke`
            // writes a Redis key `agent_blocklist:{agent_id}` that expires after the
            // agent's `token_ttl_seconds`.  Any request bearing a revoked agent's JWT
            // must be denied immediately — before we spend cycles on risk evaluation.
            if claims.session_type == auth_core::jwt::session_types::AGENT {
                if let Some(ref aid) = claims.agent_id {
                    if let Some(mut redis_conn) = config.redis.clone() {
                        let blocklist_key = format!("agent_blocklist:{}", aid);
                        let revoked: bool = redis::cmd("EXISTS")
                            .arg(&blocklist_key)
                            .query_async::<RedisConnectionManager, i64>(&mut redis_conn)
                            .await
                            .map(|n| n > 0)
                            .unwrap_or(false);
                        if revoked {
                            tracing::warn!(
                                agent_id = %aid,
                                action = %action,
                                "EIAA authz: Agent token revoked — denying request"
                            );
                            return Ok(forbidden_response("Agent token has been revoked", None));
                        }
                        tracing::debug!(
                            agent_id = %aid,
                            "EIAA authz: Agent token blocklist check passed"
                        );
                    } else {
                        // Redis not wired into config — revocation enforcement falls back
                        // to the introspection endpoint (fail-open for inline check only).
                        tracing::debug!(
                            agent_id = %aid,
                            "Agent JWT blocklist check (introspection-side enforcement active)"
                        );
                    }
                }
            }

            // === Step 1.6 (Sprint G): SPIFFE JWT-SVID Workload Identity ===
            //
            // When `config.spiffe_trust_domain` is set, inspect the `X-SPIFFE-SVID`
            // header. This is a JWT-SVID issued by the SPIRE agent running on the same
            // pod — we trust the sidecar's delivery and only validate the `sub` format
            // (no signature check needed; the kernel network namespace prevents spoofing
            // in the same way mTLS mutual auth does on the service-mesh layer).
            //
            // On success we mark `spiffe_principal_source = "spiffe"` and carry the
            // validated SPIFFE ID into the RuntimeContext so the capsule can enforce it.
            let mut spiffe_principal_source = String::new();
            if let Some(ref trust_domain) = config.spiffe_trust_domain {
                if let Some(svid_hdr) = req
                    .headers()
                    .get("x-spiffe-svid")
                    .and_then(|v| v.to_str().ok())
                {
                    match validate_spiffe_svid(svid_hdr, trust_domain) {
                        Ok(spiffe_id) => {
                            tracing::debug!(
                                spiffe_id = %spiffe_id,
                                "EIAA authz: SPIFFE JWT-SVID validated"
                            );
                            spiffe_principal_source = "spiffe".to_string();
                            // Overwrite claims.sub with the SPIFFE ID so audit records
                            // carry the workload identity rather than a generic agent id.
                            claims = Claims {
                                sub: spiffe_id.clone(),
                                ..claims
                            };
                        }
                        Err(reason) => {
                            tracing::warn!(
                                reason = %reason,
                                action = %action,
                                "EIAA authz: SPIFFE JWT-SVID validation failed — rejecting"
                            );
                            return Ok(forbidden_response(
                                "SPIFFE identity validation failed",
                                None,
                            ));
                        }
                    }
                }
                // No X-SPIFFE-SVID header present while trust_domain is configured —
                // this is acceptable; non-SPIFFE callers (human sessions, API keys)
                // share the same routes and don't send SVIDs.
            }

            // === Step 1.7 (B.4): Principal-aware capsule dispatch ===
            //
            // Agent principals get a prefixed capsule key so tenant admins can compile
            // agent-specific policies (VerifyAgentIdentity, CheckDelegationChain,
            // AuthorizeToolCall) independently of the human policy for the same action.
            //
            // Key: human  → "billing:read"
            //      agent  → "agent:billing:read"
            //
            // A fallback to the unprefixed key is attempted inside
            // `execute_authorization` when no agent-specific capsule is stored yet,
            // so existing tenants see zero behaviour change until they explicitly
            // compile an agent-prefixed capsule.
            let effective_action = if claims.session_type == auth_core::jwt::session_types::AGENT {
                format!("agent:{}", action)
            } else {
                action.clone()
            };

            // === Step 2: Extract Network Context ===
            let (ip, user_agent) = extract_network_context(&req);

            // === Step 3: Evaluate Risk via Risk Engine ===
            //
            // GAP-3 FIX: Capture the full RiskContext (not just score + level) so that
            // capsule policies can make fine-grained decisions based on individual signals
            // (e.g., impossible travel, compromised device, phishing risk).
            let (risk_score, risk_level, full_risk_context) =
                if let Some(ref risk_engine) = config.risk_engine {
                    // Build request context for Risk Engine
                    let request_ctx = RiskRequestContext {
                        network: NetworkInput {
                            remote_ip: ip,
                            // HIGH-2 FIX: Populate x_forwarded_for from the raw header so the
                            // Risk Engine receives the full proxy chain for impossible-travel
                            // analysis — same as the evaluate_oauth_action path.
                            x_forwarded_for: req
                                .headers()
                                .get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string),
                            user_agent: user_agent.clone(),
                            accept_language: req
                                .headers()
                                .get(header::ACCEPT_LANGUAGE)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string()),
                            timestamp: Utc::now(),
                        },
                        device: None,
                    };

                    // Build subject context from claims
                    let subject_ctx = SubjectContext {
                        subject_id: claims.sub.clone(),
                        org_id: claims.tenant_id.clone(),
                    };

                    // Admin routes use the stricter risk-band mapping
                    // (baseline AAL2, deny ≥60) per EIAA policy.
                    let is_admin = action.starts_with("admin:") || action == "admin_login";

                    // Evaluate risk — capture the full evaluation result
                    let risk_eval = risk_engine
                        .evaluate(&request_ctx, Some(&subject_ctx), None, is_admin)
                        .await;

                    // Extract score and level from the full context
                    let score = risk_eval.risk.total_score();
                    let level = risk_eval.risk.overall;

                    tracing::debug!(
                        user_id = %claims.sub,
                        risk_score = %score,
                        risk_level = ?level,
                        device_trust = ?risk_eval.risk.device_trust,
                        geo_velocity = ?risk_eval.risk.geo_velocity,
                        ip_reputation = ?risk_eval.risk.ip_reputation,
                        phishing_risk = %risk_eval.risk.phishing_risk,
                        "Risk evaluation completed (full context captured)"
                    );

                    // GAP-3 FIX: Preserve the full RiskContext for capsule context assembly
                    (score, level, Some(risk_eval.risk))
                } else {
                    // No risk engine configured - use safe defaults
                    tracing::warn!("RiskEngine not configured, using default low risk");
                    (0.0, RiskLevel::Low, None::<SharedRiskContext>)
                };

            // === Step 3.5: Risk-Adaptive AAL Enforcement (NIST SP 800-63B) ===
            //
            // Translate the risk score into a required AAL using the band table
            // in `risk_engine::rules`. Admin sessions use the stricter band
            // (baseline AAL2, deny ≥60); user sessions use the relaxed band
            // (baseline AAL1, deny ≥90).
            //
            // PERF-FIX: One merged session query replaces two sequential PG reads.
            // Previously Step 3.5 read `aal_level` alone, then Step 5 issued a
            // second identical query for `aal_level, verified_capabilities`.
            // Now we fetch both columns once here and reuse the result at Step 5,
            // saving 1–3 ms per request on the critical path.
            let is_admin_route = action.starts_with("admin:") || action == "admin_login";
            let is_step_up_prerequisite = matches!(action.as_str(), "auth:step_up" | "user:read");

            // Single session read — provides both the AAL gate value (Step 3.5)
            // and the capabilities needed for context assembly (Step 5).
            //
            // M-4 FIX: Agent tokens (session_type = "agent") carry an empty sid and are
            // never stored in the sessions table. Service sessions (API keys / client
            // credentials) likewise have no session row. Short-circuit both cases with
            // safe defaults to avoid an unnecessary DB round-trip on every tool call.
            let (session_aal_for_check, prefetched_capabilities): (i16, Vec<String>) =
                if matches!(
                    claims.session_type.as_str(),
                    auth_core::jwt::session_types::AGENT | auth_core::jwt::session_types::SERVICE
                ) || claims.sid.is_empty()
                {
                    (0i16, vec![])
                } else if let Some(ref db) = config.db {
                    let row: Option<(i16, serde_json::Value)> = sqlx::query_as(
                        "SELECT aal_level, verified_capabilities \
                         FROM sessions \
                         WHERE id = $1 AND tenant_id = $2 \
                               AND expires_at > NOW() AND revoked = FALSE \
                         LIMIT 1",
                    )
                    .bind(&claims.sid)
                    .bind(&claims.tenant_id)
                    .fetch_optional(db)
                    .await
                    .unwrap_or(None);
                    match row {
                        Some((aal, caps_json)) => {
                            let caps: Vec<String> =
                                serde_json::from_value(caps_json).unwrap_or_default();
                            (aal, caps)
                        }
                        None => (0i16, vec![]),
                    }
                } else {
                    (0i16, vec![])
                };

            match derive_required_aal(risk_score, is_admin_route) {
                AalRequirement::Deny if !is_step_up_prerequisite => {
                    tracing::warn!(
                        user_id = %claims.sub,
                        session_id = %claims.sid,
                        risk_score = %risk_score,
                        is_admin = is_admin_route,
                        "Critical risk — revoking session"
                    );
                    if let Some(ref db) = config.db {
                        let _ = sqlx::query(
                            "UPDATE sessions SET revoked = TRUE, updated_at = NOW() WHERE id = $1",
                        )
                        .bind(&claims.sid)
                        .execute(db)
                        .await;
                    }
                    if let Some(ref writer) = config.audit_writer {
                        writer.record(AuditRecord {
                                decision_ref: format!(
                                    "dec_{}",
                                    uuid::Uuid::new_v4().to_string().replace("-", "")
                                ),
                                capsule_hash_b64: String::new(),
                                capsule_version: String::new(),
                                action: action.clone(),
                                tenant_id: claims.tenant_id.clone(),
                                input_digest: String::new(),
                                input_context: None,
                                nonce_b64: String::new(),
                                decision: AuditDecision {
                                    allow: false,
                                    reason: Some(format!(
                                        "Session revoked — risk {risk_score:.1} exceeds {} deny threshold",
                                        if is_admin_route { "admin" } else { "user" }
                                    )),
                                },
                                attestation_signature_b64: String::new(),
                                attestation_timestamp: Utc::now(),
                                attestation_hash_b64: None,
                                user_id: Some(claims.sub.clone()),
                                task_id: claims.task_id.clone(),
                                parent_action_id: None,
                                delegation_depth: claims.delegation_chain.as_ref().map(|c| c.len() as u8).unwrap_or(0),
                                principal_type: claims.session_type.clone(),
                                agent_id: claims.agent_id.clone(),
                                model_id: claims.model_id.clone(),
                                tool_name: None,
                                tool_args_hash: None,
                            });
                    }
                    return Ok(unauthorized_response(
                        "Session revoked due to critical risk — please re-authenticate",
                    ));
                }
                AalRequirement::Required(required) => {
                    let required_i16 = required.as_i16();
                    // Admin baseline floor: even a perfectly-clean admin session
                    // must satisfy AAL2. The band table already encodes this,
                    // but compute the floor explicitly for clarity.
                    let baseline = if is_admin_route {
                        AssuranceLevel::AAL2.as_i16()
                    } else {
                        AssuranceLevel::AAL1.as_i16()
                    };
                    let needed = required_i16.max(baseline);

                    if !is_step_up_prerequisite && session_aal_for_check < needed {
                        tracing::info!(
                            user_id = %claims.sub,
                            session_id = %claims.sid,
                            session_aal = session_aal_for_check,
                            required_aal = needed,
                            risk_score = %risk_score,
                            is_admin = is_admin_route,
                            "Step-up required"
                        );
                        return Ok(step_up_required_response(
                            needed,
                            "Higher assurance required for this request",
                        ));
                    }
                }
                // Step-up prerequisite Deny path: even at critical risk we
                // permit the user to read the factor list / submit the
                // step-up code so they can recover. Any other action would
                // already have returned above.
                AalRequirement::Deny => {
                    tracing::info!(
                        user_id = %claims.sub,
                        session_id = %claims.sid,
                        risk_score = %risk_score,
                        action = %action,
                        "Critical risk on step-up prerequisite \u{2014} allowing to avoid deadlock"
                    );
                }
            }

            // === Step 4: Check Risk Threshold ===
            if config.risk_threshold > 0.0 && risk_score > config.risk_threshold {
                tracing::warn!(
                    user_id = %claims.sub,
                    risk_score = %risk_score,
                    threshold = %config.risk_threshold,
                    "Request denied due to high risk score"
                );

                // Write audit record for risk-based denial so that forensic analysis
                // can correlate elevated-risk events even when no capsule was executed.
                if let Some(ref writer) = config.audit_writer {
                    writer.record(AuditRecord {
                        decision_ref: format!(
                            "dec_{}",
                            uuid::Uuid::new_v4().to_string().replace("-", "")
                        ),
                        capsule_hash_b64: String::new(),
                        capsule_version: String::new(),
                        action: action.clone(),
                        tenant_id: claims.tenant_id.clone(),
                        input_digest: String::new(),
                        input_context: None,
                        nonce_b64: String::new(),
                        decision: AuditDecision {
                            allow: false,
                            reason: Some(format!(
                                "Risk score {risk_score:.1} exceeds threshold {:.1}",
                                config.risk_threshold
                            )),
                        },
                        attestation_signature_b64: String::new(),
                        attestation_timestamp: Utc::now(),
                        attestation_hash_b64: None,
                        user_id: Some(claims.sub.clone()),
                        task_id: claims.task_id.clone(),
                        parent_action_id: None,
                        delegation_depth: claims.delegation_chain.as_ref().map(|c| c.len() as u8).unwrap_or(0),
                        principal_type: claims.session_type.clone(),
                        agent_id: claims.agent_id.clone(),
                        model_id: claims.model_id.clone(),
                        tool_name: None,
                        tool_args_hash: None,
                    });
                }

                return Ok(forbidden_response(
                    "Request denied due to elevated risk",
                    None,
                ));
            }

            // === Step 4.5: Attestation Frequency Matrix - Check Cache ===
            let action_risk = ActionRiskLevel::from_action(&action);
            let ip_str = ip.to_string();
            let context_hash =
                crate::services::attestation_decision_cache::AttestationDecisionCache::hash_context(
                    Some(ip_str.as_str()),
                    risk_score,
                );

            if let Some(ref decision_cache) = config.decision_cache {
                if let Some(cached) = decision_cache
                    .get(
                        &claims.sub,
                        &claims.tenant_id,
                        &action,
                        &context_hash,
                        action_risk,
                    )
                    .await
                {
                    // HIGH-EIAA-4 FIX: Re-verify attestation signature on every cache hit.
                    //
                    // Previously the cached decision was returned without any signature
                    // verification, meaning a compromised or tampered cache entry could
                    // bypass authorization entirely. Now we re-verify the Ed25519 signature
                    // against the stored attestation body before trusting the cached decision.
                    //
                    // Cost: ~50µs Ed25519 verify (vs ~5ms full capsule execution).
                    // If verification fails, we fall through to full capsule execution
                    // (rather than denying outright) to handle key rotation gracefully.
                    let cache_sig_valid = if !config.skip_verification {
                        if let (Some(sig), Some(body)) =
                            (&cached.attestation_signature_b64, &cached.attestation_body)
                        {
                            let att = crate::services::attestation_verifier::Attestation {
                                body: body.clone(),
                                signature_b64: sig.clone(),
                            };
                            // Build a minimal Decision for hash verification
                            let cached_decision = crate::services::attestation_verifier::Decision {
                                allow: cached.allowed,
                                reason: if cached.reason == "allowed" {
                                    None
                                } else {
                                    Some(cached.reason.clone())
                                },
                                requirement: None,
                            };
                            // Ensure verifier has the key loaded
                            if let (Some(ref verifier), Some(ref key_cache)) =
                                (&config.verifier, &config.key_cache)
                            {
                                if let Some(key) = key_cache.get(&body.runtime_kid).await {
                                    verifier.load_key(body.runtime_kid.clone(), key).await;
                                }
                                match verifier.verify(&att, &cached_decision, Utc::now()).await {
                                    Ok(()) => {
                                        tracing::debug!(
                                            action = %action,
                                            user_id = %claims.sub,
                                            "Cache hit attestation signature verified"
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            action = %action,
                                            user_id = %claims.sub,
                                            error = %e,
                                            "Cache hit attestation signature INVALID — falling through to full execution"
                                        );
                                        false
                                    }
                                }
                            } else {
                                // No verifier configured — skip verification (dev mode)
                                tracing::debug!(
                                    "No verifier configured, skipping cache hit signature check"
                                );
                                true
                            }
                        } else {
                            // No signature/body stored — cannot verify, fall through to full execution
                            tracing::warn!(
                                action = %action,
                                user_id = %claims.sub,
                                "Cache hit has no attestation body — falling through to full execution"
                            );
                            false
                        }
                    } else {
                        // skip_verification = true (dev mode)
                        true
                    };

                    if cache_sig_valid {
                        tracing::info!(
                            action = %action,
                            user_id = %claims.sub,
                            risk_level = ?action_risk,
                            "Using verified cached attestation decision"
                        );
                        if cached.allowed {
                            return inner.call(req).await;
                        } else {
                            return Ok(forbidden_response(&cached.reason, None));
                        }
                    }
                    // cache_sig_valid == false: fall through to full capsule execution
                }
            }

            // === Step 5: Build Rich Authorization Context ===
            // PERF-FIX: Reuse `prefetched_capabilities` from the merged session query
            // at Step 3.5 — no second PG round-trip here.
            let session_aal = session_aal_for_check as u8;
            let session_capabilities = prefetched_capabilities;

            let method = req.method().as_str();
            let path = req.uri().path();

            // GAP-3 FIX: Build context with full risk signals, not just score+level.
            // The `with_risk_context()` call passes the complete RiskContext to the
            // capsule, enabling policies to inspect individual signals like geo_velocity,
            // device_trust, and phishing_risk for fine-grained authorization decisions.
            let mut builder = AuthorizationContextBuilder::new()
                .with_identity(
                    &claims.sub,
                    &claims.tenant_id,
                    &claims.session_type,
                    &claims.sid,
                )
                .with_action(&action)
                .with_request(method, path)
                .with_network(ip, &user_agent)
                .with_risk(risk_score, risk_level)
                .with_aal(session_aal, &session_capabilities)
                .with_ttl_seconds(60);

            // Attach full risk context if available (GAP-3 FIX)
            if let Some(risk_ctx) = full_risk_context {
                builder = builder.with_risk_context(risk_ctx);
            }

            let context = builder.build();

            let credential_attempts = if let Some(service) = &config.credential_lockout_service {
                match service.snapshot(&claims.tenant_id, &claims.sub).await {
                    Ok(snapshot) => snapshot,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to load credential-attempt snapshot");
                        std::collections::HashMap::new()
                    }
                }
            } else {
                std::collections::HashMap::new()
            };

            let required_actions = if let Some(service) = &config.required_action_service {
                match service.pending_codes(&claims.tenant_id, &claims.sub).await {
                    Ok(codes) => codes,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to load required-action snapshot");
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };

            // Build the RuntimeContext-compatible JSON for WASM capsule execution.
            // The capsule runtime expects specific fields (subject_id: i64, risk_score: i32,
            // factors_satisfied: Vec<i32>, authz_decision: i32) that don't exist in
            // AuthorizationContext. We merge both schemas so the WASM host imports get
            // the values they need while preserving the full AuthorizationContext for audit.
            let context_json = {
                let mut ctx_value = match serde_json::to_value(&context) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Failed to serialize context: {}", e);
                        return Ok(internal_error_response("Context serialization failed"));
                    }
                };
                if let Some(obj) = ctx_value.as_object_mut() {
                    // subject_id: non-zero means "identity verified" for VerifyIdentity step
                    obj.insert("subject_id".to_string(), serde_json::json!(1i64));
                    // authz_decision: 1 = Allow (pre-authorized by session JWT)
                    obj.insert("authz_decision".to_string(), serde_json::json!(1i32));
                    // factors_satisfied: empty by default (MFA factors checked separately)
                    if !obj.contains_key("factors_satisfied") {
                        obj.insert("factors_satisfied".to_string(), serde_json::json!([]));
                    }
                    obj.insert(
                        "credential_attempts".to_string(),
                        serde_json::json!(credential_attempts),
                    );
                    obj.insert(
                        "required_actions".to_string(),
                        serde_json::json!(required_actions),
                    );
                    // Sprint G: propagate SPIFFE identity source so the capsule's
                    // verify_identity(src=4) host function can enforce it.
                    if !spiffe_principal_source.is_empty() {
                        obj.insert(
                            "principal_source".to_string(),
                            serde_json::json!(spiffe_principal_source),
                        );
                    }
                }
                match serde_json::to_string(&ctx_value) {
                    Ok(json) => json,
                    Err(e) => {
                        tracing::error!("Failed to serialize merged context: {}", e);
                        return Ok(internal_error_response("Context serialization failed"));
                    }
                }
            };

            // === Step 6: Execute Capsule Authorization ===
            match execute_authorization(&effective_action, &claims, &context_json, &config).await {
                Ok(AuthzResult::Allow {
                    decision,
                    attestation,
                }) => {
                    // === Step 7: Verify Attestation Signature ===
                    if !config.skip_verification {
                        if let Err(e) = verify_attestation(&decision, &attestation, &config).await {
                            tracing::error!("Attestation verification failed: {}", e);
                            return Ok(forbidden_response(
                                "Authorization verification failed",
                                None,
                            ));
                        }
                    }

                    let decision_ref = generate_decision_ref();

                    // === Step 8: Record to Audit Trail ===
                    if let Some(ref writer) = config.audit_writer {
                        writer.record(create_audit_record_with_decision_ref(
                            &decision_ref,
                            &effective_action,
                            &claims,
                            &context,
                            true,
                            &attestation,
                        ));
                    }

                    // === Step 8a: Fire agent webhook (non-blocking) ===
                    if effective_action.starts_with("agent:") {
                        if let Some(ref svc) = config.agent_webhook_service {
                            svc.on_authorized(crate::services::AgentWebhookPayload {
                                event: crate::services::AgentEventKind::AgentActionAuthorized,
                                timestamp: Utc::now().to_rfc3339(),
                                tenant_id: claims.tenant_id.clone(),
                                task_id: claims.task_id.clone(),
                                agent_id: claims.agent_id.clone(),
                                model_id: claims.model_id.clone(),
                                tool_name: context.tool_name.clone(),
                                decision_ref: decision_ref.clone(),
                                risk_score: Some(risk_score as i32),
                                attestation_signature_b64: if attestation.signature_b64.is_empty() {
                                    None
                                } else {
                                    Some(attestation.signature_b64.clone())
                                },
                            });
                        }
                    }

                    req.extensions_mut()
                        .insert(EiaaDecisionArtifact::from_parts(
                            decision_ref,
                            effective_action.clone(),
                            true,
                            None,
                            &attestation,
                        ));

                    // === Step 8.5: Cache Decision (Attestation Frequency Matrix) ===
                    // HIGH-EIAA-4 FIX: Store the full attestation body alongside the
                    // signature so it can be re-verified on cache hit.
                    if let Some(ref decision_cache) = config.decision_cache {
                        decision_cache
                            .set(CacheDecisionParams {
                                user_id: &claims.sub,
                                tenant_id: &claims.tenant_id,
                                action: &effective_action,
                                context_hash: &context_hash,
                                risk_level: action_risk,
                                allowed: true,
                                reason: "allowed",
                                attestation_signature_b64: Some(&attestation.signature_b64),
                                attestation_body: attestation.body.clone(),
                            })
                            .await;
                    }

                    tracing::info!(
                        user_id = %claims.sub,
                        action = %action,
                        risk_score = %risk_score,
                        action_risk = ?action_risk,
                        "Authorization granted"
                    );

                    // === Step 9: Proceed to Inner Handler ===
                    inner.call(req).await
                }
                Ok(AuthzResult::Deny {
                    reason,
                    decision,
                    attestation,
                }) => {
                    tracing::warn!(
                        user_id = %claims.sub,
                        action = %action,
                        reason = %reason,
                        "Authorization denied"
                    );

                    let decision_ref = generate_decision_ref();

                    // Record denial
                    if let Some(ref writer) = config.audit_writer {
                        writer.record(create_audit_record_with_decision_ref(
                            &decision_ref,
                            &effective_action,
                            &claims,
                            &context,
                            false,
                            &attestation,
                        ));
                    }

                    // Fire agent webhook for denials (non-blocking)
                    if effective_action.starts_with("agent:") {
                        if let Some(ref svc) = config.agent_webhook_service {
                            svc.on_denied(crate::services::AgentWebhookPayload {
                                event: crate::services::AgentEventKind::AgentActionDenied,
                                timestamp: Utc::now().to_rfc3339(),
                                tenant_id: claims.tenant_id.clone(),
                                task_id: claims.task_id.clone(),
                                agent_id: claims.agent_id.clone(),
                                model_id: claims.model_id.clone(),
                                tool_name: context.tool_name.clone(),
                                decision_ref: decision_ref.clone(),
                                risk_score: Some(risk_score as i32),
                                attestation_signature_b64: if attestation.signature_b64.is_empty() {
                                    None
                                } else {
                                    Some(attestation.signature_b64.clone())
                                },
                            });
                        }
                    }

                    Ok(forbidden_response(&reason, decision.requirement.as_ref()))
                }
                Err(e) => {
                    tracing::error!("EIAA authz error: {}", e);

                    if config.fail_open {
                        tracing::warn!("EIAA fail-open enabled, allowing request");
                        inner.call(req).await
                    } else {
                        Ok(internal_error_response("Authorization service unavailable"))
                    }
                }
            }
        })
    }
}

/// Authorization result from capsule execution
enum AuthzResult {
    Allow {
        decision: VerifierDecision,
        attestation: AttestationData,
    },
    Deny {
        reason: String,
        decision: VerifierDecision,
        attestation: AttestationData,
    },
}

/// Internal attestation data structure
#[derive(Clone, Default)]
struct AttestationData {
    signature_b64: String,
    body: Option<VerifierAttestationBody>,
    timestamp: chrono::DateTime<Utc>,
    capsule_hash: String,
    nonce: String,
}

impl EiaaDecisionArtifact {
    fn from_parts(
        decision_ref: String,
        action: String,
        allowed: bool,
        reason: Option<String>,
        attestation: &AttestationData,
    ) -> Self {
        let attestation = attestation.body.clone().map(|body| VerifierAttestation {
            body,
            signature_b64: attestation.signature_b64.clone(),
        });
        let attestation_ref = attestation.as_ref().map(compute_attestation_ref);
        Self {
            decision_ref,
            action,
            allowed,
            reason,
            attestation_ref,
            attestation,
        }
    }
}

fn generate_decision_ref() -> String {
    format!("dec_{}", uuid::Uuid::new_v4().to_string().replace('-', ""))
}

fn compute_attestation_ref(attestation: &VerifierAttestation) -> String {
    let bytes = serde_json::to_vec(attestation).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("att_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Extract IP address and User-Agent from request
fn extract_network_context(req: &Request<Body>) -> (IpAddr, String) {
    // Try X-Forwarded-For first (for reverse proxies)
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            // Fallback to X-Real-IP
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok())
        })
        .unwrap_or_else(|| "0.0.0.0".parse().unwrap());

    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    (ip, user_agent)
}

/// Load a capsule from the database for a given tenant and action.
///
/// CRITICAL-EIAA-3 FIX: This is the DB fallback path used when the Redis cache misses.
/// It queries `eiaa_capsules` for the most recently activated capsule for this
/// (tenant_id, action) pair, then populates the Redis cache so subsequent requests
/// are served from cache.
///
/// The capsule bytes stored in the DB are protobuf-encoded `CapsuleSigned` messages
/// (same format as the Redis cache), so they can be decoded with `prost::Message::decode`.
async fn load_capsule_from_db(
    db: &PgPool,
    tenant_id: &str,
    action: &str,
) -> anyhow::Result<Option<CapsuleSigned>> {
    // Query the most recently created active capsule for this tenant+action.
    // Migration 031 added wasm_bytes and ast_bytes columns to eiaa_capsules.
    // Migration 032 backfills these for pre-031 rows.
    // We select them here and fail clearly if they are still NULL (pre-backfill row).
    #[derive(sqlx::FromRow)]
    struct CapsuleRow {
        tenant_id: String,
        action: String,
        meta: serde_json::Value,
        capsule_hash_b64: String,
        compiler_kid: String,
        compiler_sig_b64: String,
        wasm_bytes: Option<Vec<u8>>,
        ast_bytes: Option<Vec<u8>>,
        lowering_version: Option<String>,
    }

    let row: Option<CapsuleRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, action, meta, capsule_hash_b64, compiler_kid, compiler_sig_b64,
               wasm_bytes, ast_bytes, lowering_version
        FROM eiaa_capsules
        WHERE tenant_id = $1 AND action = $2
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(action)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else {
        tracing::warn!(
            tenant_id = %tenant_id,
            action = %action,
            "No capsule found in DB for tenant+action — policy may not be compiled yet"
        );
        return Ok(None);
    };

    // Extract metadata fields from the JSONB meta column.
    let not_before_unix = row
        .meta
        .get("not_before_unix")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let not_after_unix = row
        .meta
        .get("not_after_unix")
        .and_then(|v| v.as_i64())
        .unwrap_or(i64::MAX);
    let policy_hash_b64 = row
        .meta
        .get("ast_hash_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let lowering_version = row
        .lowering_version
        .unwrap_or_else(|| "ei-aa-lower-wasm-v1".to_string());

    // Require wasm_bytes and ast_bytes — these are populated by migration 031 columns
    // and backfilled by migration 032. If NULL, the capsule was compiled before migration
    // 031 and has not been backfilled yet. Return None to trigger fail_closed behavior.
    let wasm_bytes = match row.wasm_bytes {
        Some(b) if !b.is_empty() => b,
        _ => {
            tracing::error!(
                tenant_id = %tenant_id,
                action = %action,
                capsule_hash = %row.capsule_hash_b64,
                "DB capsule has NULL/empty wasm_bytes — run migration 032 to backfill. \
                 DB fallback unavailable for this capsule."
            );
            return Ok(None);
        }
    };
    let ast_bytes = match row.ast_bytes {
        Some(b) if !b.is_empty() => b,
        _ => {
            tracing::error!(
                tenant_id = %tenant_id,
                action = %action,
                capsule_hash = %row.capsule_hash_b64,
                "DB capsule has NULL/empty ast_bytes — run migration 032 to backfill. \
                 DB fallback unavailable for this capsule."
            );
            return Ok(None);
        }
    };

    // Compute wasm_hash from actual wasm_bytes (authoritative).
    // CapsuleMeta does NOT contain wasm_hash, so the meta JSON column never has it.
    // Recomputing from bytes is correct and matches the compiler's logic exactly.
    let wasm_hash_b64 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&wasm_bytes))
    };

    let ast_hash_b64_copy = policy_hash_b64.clone();
    let capsule = CapsuleSigned {
        meta: Some(grpc_api::eiaa::runtime::CapsuleMeta {
            tenant_id: row.tenant_id,
            action: row.action,
            not_before_unix,
            not_after_unix,
            policy_hash_b64,
        }),
        ast_bytes,
        ast_hash_b64: ast_hash_b64_copy,
        lowering_version,
        wasm_bytes,
        wasm_hash_b64,
        capsule_hash_b64: row.capsule_hash_b64,
        compiler_kid: row.compiler_kid,
        compiler_sig_b64: row.compiler_sig_b64,
    };

    Ok(Some(capsule))
}

/// Compile a default "allow authenticated user" capsule on-demand.
///
/// When no pre-compiled capsule exists for a given (tenant_id, action) pair,
/// this builds a minimal policy AST (VerifyIdentity → AuthorizeAction → Allow),
/// compiles it to WASM, persists it to `eiaa_capsules`, and returns it.
///
/// This mirrors the on-demand compilation pattern used by `hosted.rs` for auth flows,
/// ensuring dashboard and API routes work even before explicit policy compilation.
async fn compile_default_capsule_on_demand(
    tenant_id: &str,
    action: &str,
    ks: &dyn keystore::Keystore,
    compiler_kid: &KeyId,
    db: &PgPool,
) -> anyhow::Result<CapsuleSigned> {
    use capsule_compiler::ast::{IdentitySource, Program, Step};

    // Build a minimal policy: verify identity, authorize action, allow.
    //
    // RESOURCE NOTE: This is the catch-all fallback capsule used only when no
    // tenant-specific policy is registered for `(tenant_id, action)`. Because
    // the policy unconditionally allows the action (`Allow(true)`) once
    // identity is verified, the resource string is informational only — it
    // appears in audit attestations but is not evaluated by the WASM.
    //
    // We therefore use the wildcard `"*"` rather than `tenant_id`. Hard-coding
    // the calling tenant's id here was misleading: it suggested per-resource
    // scoping that the policy does not actually enforce, and it baked the
    // wrong identifier into audit records when admin routes target a
    // different organization (e.g. provider admin in `system` operating on
    // `default` via `/api/v1/organizations/default/...`).
    //
    // Real per-resource enforcement must be expressed in a tenant-authored
    // capsule that the policy compiler emits with the appropriate resource.
    let policy = Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: action.to_string(),
                resource: "*".to_string(),
            },
            Step::Allow(true),
        ],
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let compiled = capsule_compiler::compile(
        policy,
        tenant_id.to_string(),
        action.to_string(),
        now,
        now + 86400 * 365, // 1 year validity for default policies
        ks,
        compiler_kid,
    )?;

    // Persist to eiaa_capsules for subsequent requests
    let meta_json = serde_json::to_value(&compiled.meta)?;
    let capsule_hash_b64 = {
        let bytes = hex::decode(&compiled.wasm_hash).unwrap_or_default();
        URL_SAFE_NO_PAD.encode(&bytes)
    };

    sqlx::query(
        r#"
        INSERT INTO eiaa_capsules
            (tenant_id, action, policy_version, meta, policy_hash_b64, capsule_hash_b64,
             compiler_kid, compiler_sig_b64, wasm_bytes, ast_bytes)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (capsule_hash_b64) DO UPDATE
            SET wasm_bytes = EXCLUDED.wasm_bytes,
                ast_bytes  = EXCLUDED.ast_bytes
        "#,
    )
    .bind(tenant_id)
    .bind(action)
    .bind(1_i32)
    .bind(meta_json)
    .bind(&compiled.meta.ast_hash_b64)
    .bind(&capsule_hash_b64)
    .bind(&compiled.compiler_kid)
    .bind(&compiled.compiler_sig_b64)
    .bind(&compiled.wasm_bytes)
    .bind(&compiled.ast_bytes)
    .execute(db)
    .await?;

    tracing::info!(
        tenant_id = %tenant_id,
        action = %action,
        capsule_hash = %capsule_hash_b64,
        "Default capsule compiled and persisted on-demand"
    );

    // Convert to gRPC type
    Ok(CapsuleSigned {
        meta: Some(CapsuleMeta {
            tenant_id: compiled.meta.tenant_id,
            action: compiled.meta.action,
            not_before_unix: compiled.meta.not_before_unix,
            not_after_unix: compiled.meta.not_after_unix,
            policy_hash_b64: compiled.meta.ast_hash_b64,
        }),
        ast_bytes: compiled.ast_bytes,
        capsule_hash_b64: compiled.ast_hash.clone(),
        compiler_kid: compiled.compiler_kid,
        compiler_sig_b64: compiled.compiler_sig_b64,
        ast_hash_b64: compiled.ast_hash,
        wasm_hash_b64: compiled.wasm_hash.clone(),
        lowering_version: compiled.lowering_version,
        wasm_bytes: compiled.wasm_bytes,
    })
}

/// Execute capsule-based authorization
async fn execute_authorization(
    action: &str,
    claims: &Claims,
    context_json: &str,
    config: &EiaaAuthzConfig,
) -> anyhow::Result<AuthzResult> {
    // Generate nonce for replay protection
    let nonce = AuditWriter::generate_nonce();

    // === HIGH-EIAA-3 FIX: Persistent Nonce Replay Protection ===
    //
    // Check the nonce against the persistent store BEFORE executing the capsule.
    // The nonce is generated fresh for each request, so a replay would require
    // the attacker to intercept and reuse the nonce within the attestation TTL.
    // The persistent store ensures this is detected even across service restarts.
    if let Some(ref nonce_store) = config.nonce_store {
        match nonce_store.check_and_mark(&nonce).await {
            Ok(true) => {
                tracing::debug!(nonce = %nonce, "Nonce is fresh, proceeding with capsule execution");
            }
            Ok(false) => {
                tracing::error!(
                    nonce = %nonce,
                    "Generated nonce already exists in nonce store — possible hash collision or replay attack"
                );
                return Err(anyhow::anyhow!(
                    "Nonce replay detected — authorization aborted for security"
                ));
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    nonce = %nonce,
                    "Nonce store write failed — failing closed to prevent replay attack"
                );
                return Err(anyhow::anyhow!(
                    "Nonce persistence failed: {e} — authorization aborted"
                ));
            }
        }
    } else {
        tracing::warn!(
            "NonceStore not configured — nonce replay protection is DISABLED. \
             This is only acceptable in development environments."
        );
    }

    // === CRITICAL-EIAA-3 FIX: Cache-Aside with DB fallback ===
    //
    // Strategy:
    //   1. Try Redis cache (fast path, O(1))
    //   2. On cache miss, try DB (slow path, O(log n))
    //   3. On DB hit, populate cache for next request
    //   4. On DB miss, fail with a clear error (no capsule compiled for this action)
    //
    // This prevents a Redis restart or cache eviction from causing a 500 error
    // on every authorization request until the cache is manually repopulated.
    let capsule = {
        // Step 1: Try Redis cache
        let cached = if let Some(ref cache) = config.cache {
            if let Some(cached) = cache.get(&claims.tenant_id, action).await {
                use prost::Message;
                match CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
                    Ok(c) => {
                        tracing::debug!(
                            tenant_id = %claims.tenant_id,
                            action = %action,
                            "Capsule served from Redis cache"
                        );
                        Some(c)
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %claims.tenant_id,
                            action = %action,
                            error = %e,
                            "Cached capsule failed proto decode — treating as cache miss"
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(c) = cached {
            c
        } else {
            // Step 2: Cache miss — try DB fallback
            tracing::info!(
                tenant_id = %claims.tenant_id,
                action = %action,
                "Capsule cache miss — falling back to DB"
            );

            let db_capsule = if let Some(ref db) = config.db {
                let primary = load_capsule_from_db(db, &claims.tenant_id, action)
                    .await
                    .map_err(|e| anyhow::anyhow!("DB capsule lookup failed: {e}"))?;

                // B.4: If the action has the "agent:" prefix and no agent-specific
                // capsule is stored yet, fall back to the unprefixed (human) capsule
                // so existing tenants are unaffected during migration.
                if primary.is_none() {
                    if let Some(base_action) = action.strip_prefix("agent:") {
                        tracing::warn!(
                            tenant_id = %claims.tenant_id,
                            agent_action = %action,
                            fallback_action = %base_action,
                            "No agent-specific capsule found — falling back to human capsule. \
                             Compile an agent-prefixed capsule to enforce agent-specific policy."
                        );
                        load_capsule_from_db(db, &claims.tenant_id, base_action)
                            .await
                            .map_err(|e| anyhow::anyhow!("DB capsule fallback lookup failed: {e}"))?
                    } else {
                        None
                    }
                } else {
                    primary
                }
            } else {
                tracing::error!(
                    tenant_id = %claims.tenant_id,
                    action = %action,
                    "Capsule not in cache and no DB configured — cannot authorize"
                );
                None
            };

            match db_capsule {
                Some(capsule) => {
                    // Step 3: Populate cache for next request
                    if let Some(ref cache) = config.cache {
                        use prost::Message;
                        let mut capsule_bytes = Vec::new();
                        if capsule.encode(&mut capsule_bytes).is_ok() {
                            let cached = crate::services::capsule_cache::CachedCapsule {
                                tenant_id: claims.tenant_id.clone(),
                                action: action.to_string(),
                                version: 0, // Version unknown from DB fallback
                                ast_hash: capsule.ast_hash_b64.clone(),
                                wasm_hash: capsule.wasm_hash_b64.clone(),
                                capsule_bytes,
                                cached_at: chrono::Utc::now().timestamp(),
                                not_after_unix: capsule
                                    .meta
                                    .as_ref()
                                    .map_or(0, |m| m.not_after_unix),
                            };
                            if let Err(e) = cache.set(&cached).await {
                                // Non-fatal: log and continue — next request will hit DB again
                                tracing::warn!(
                                    tenant_id = %claims.tenant_id,
                                    action = %action,
                                    error = %e,
                                    "Failed to populate capsule cache from DB fallback"
                                );
                            } else {
                                tracing::info!(
                                    tenant_id = %claims.tenant_id,
                                    action = %action,
                                    "Capsule cache populated from DB fallback"
                                );
                            }
                        }
                    }
                    capsule
                }
                None => {
                    // Step 4: No capsule in cache or DB — try on-demand compilation
                    // Build a default "allow authenticated user" policy and compile it,
                    // similar to how hosted.rs handles auth flows on-demand.
                    if let (Some(ref ks), Some(ref kid), Some(ref db)) =
                        (&config.keystore, &config.compiler_kid, &config.db)
                    {
                        tracing::info!(
                            tenant_id = %claims.tenant_id,
                            action = %action,
                            "No compiled capsule — compiling default policy on-demand"
                        );
                        match compile_default_capsule_on_demand(
                            &claims.tenant_id,
                            action,
                            ks,
                            kid,
                            db,
                        )
                        .await
                        {
                            Ok(capsule) => {
                                // Cache the freshly compiled capsule to Redis
                                if let Some(ref cache) = config.cache {
                                    use prost::Message;
                                    let mut capsule_bytes = Vec::new();
                                    if capsule.encode(&mut capsule_bytes).is_ok() {
                                        let cached =
                                            crate::services::capsule_cache::CachedCapsule {
                                                tenant_id: claims.tenant_id.clone(),
                                                action: action.to_string(),
                                                version: 1,
                                                ast_hash: capsule.ast_hash_b64.clone(),
                                                wasm_hash: capsule.wasm_hash_b64.clone(),
                                                capsule_bytes,
                                                cached_at: chrono::Utc::now().timestamp(),
                                                not_after_unix: capsule
                                                    .meta
                                                    .as_ref()
                                                    .map_or(0, |m| m.not_after_unix),
                                            };
                                        if let Err(e) = cache.set(&cached).await {
                                            tracing::warn!(
                                                tenant_id = %claims.tenant_id,
                                                action = %action,
                                                error = %e,
                                                "Failed to cache on-demand compiled capsule (non-fatal)"
                                            );
                                        }
                                    }
                                }
                                capsule
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "On-demand capsule compilation failed for action '{}' in tenant '{}': {}",
                                    action,
                                    claims.tenant_id,
                                    e
                                ));
                            }
                        }
                    } else {
                        return Err(anyhow::anyhow!(
                            "No compiled capsule found for action '{}' in tenant '{}'. \
                             Ensure the policy has been compiled and activated.",
                            action,
                            claims.tenant_id
                        ));
                    }
                }
            }
        }
    };

    let response = match config.runtime_client {
        Some(ref shared) => {
            shared
                .execute_capsule(capsule, context_json.to_string(), nonce.clone())
                .await?
        }
        None => {
            return Err(anyhow::anyhow!(
                "No SharedRuntimeClient configured — cannot execute capsule. \
                 Ensure state.runtime_client is wired into EiaaAuthzConfig."
            ));
        }
    };

    // Extract decision and attestation
    let dec = response
        .decision
        .ok_or_else(|| anyhow::anyhow!("No decision in response"))?;
    let att = response.attestation;

    let decision = VerifierDecision {
        allow: dec.allow,
        reason: if dec.reason.is_empty() {
            None
        } else {
            Some(dec.reason.clone())
        },
        requirement: dec.requirement.map(|r| Requirement {
            required_assurance: if r.required_assurance.is_empty() {
                None
            } else {
                Some(r.required_assurance)
            },
            acceptable_capabilities: r.acceptable_capabilities,
            disallowed_capabilities: r.disallowed_capabilities,
            require_phishing_resistant: r.require_phishing_resistant,
            session_restrictions: r.session_restrictions,
        }),
    };

    let attestation_data = att
        .map(|a| {
            // Extract capsule_hash before consuming body
            let capsule_hash = a
                .body
                .as_ref()
                .map(|b| b.capsule_hash_b64.clone())
                .unwrap_or_default();

            AttestationData {
                signature_b64: a.signature_b64.clone(),
                body: a.body.map(|b| VerifierAttestationBody {
                    capsule_hash_b64: b.capsule_hash_b64,
                    decision_hash_b64: b.decision_hash_b64,
                    executed_at_unix: b.executed_at_unix,
                    expires_at_unix: b.expires_at_unix,
                    nonce_b64: b.nonce_b64,
                    runtime_kid: b.runtime_kid,
                    ast_hash_b64: Some(b.ast_hash_b64),
                    wasm_hash_b64: Some(b.wasm_hash_b64),
                    lowering_version: Some(b.lowering_version),
                }),
                timestamp: Utc::now(),
                capsule_hash,
                nonce: nonce.clone(),
            }
        })
        .unwrap_or_default();

    if decision.allow {
        Ok(AuthzResult::Allow {
            decision,
            attestation: attestation_data,
        })
    } else {
        Ok(AuthzResult::Deny {
            reason: dec.reason.clone(),
            decision,
            attestation: attestation_data,
        })
    }
}

/// Execute EIAA for OAuth/OIDC protocol operations that cannot use the Tower
/// middleware directly (for example `/oauth/token`, where the caller is an
/// OAuth client rather than a browser session JWT).
pub async fn evaluate_oauth_action(
    state: &crate::state::AppState,
    req: OAuthEiaaRequest<'_>,
) -> Result<EiaaDecisionArtifact, AppError> {
    let config = EiaaAuthzConfig::from_state(state);
    let action = req.action.to_string();
    let session_id = req.session_id.unwrap_or("");
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: req.subject_id.to_string(),
        iss: state.config.jwt.issuer.clone(),
        aud: state.config.jwt.audience.clone(),
        exp: now + 300,
        iat: now,
        nbf: now,
        sid: session_id.to_string(),
        tenant_id: req.tenant_id.to_string(),
        session_type: req.session_type.to_string(),
        // Propagate agent-specific claims so capsule host functions
        // (VerifyAgentIdentity, CheckDelegationChain) receive the correct values.
        agent_id: req.agent_id_claim.clone(),
        model_id: req.agent_model_id.clone(),
        task_id: req.agent_task_id.clone(),
        delegation_chain: req.agent_delegation_chain.clone(),
        allowed_tools: None,
        principal_source: None,
    };

    let ip = req
        .network
        .remote_ip
        .unwrap_or_else(|| "0.0.0.0".parse().unwrap());
    let user_agent = req
        .network
        .user_agent
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let accept_language = req.network.accept_language.clone();
    let forwarded_for = req.network.forwarded_for.clone();

    let (risk_score, risk_level, full_risk_context) =
        if let Some(ref risk_engine) = config.risk_engine {
            let request_ctx = RiskRequestContext {
                network: NetworkInput {
                    remote_ip: ip,
                    x_forwarded_for: forwarded_for,
                    user_agent: user_agent.clone(),
                    accept_language,
                    timestamp: Utc::now(),
                },
                device: None,
            };
            let subject_ctx = SubjectContext {
                subject_id: claims.sub.clone(),
                org_id: claims.tenant_id.clone(),
            };
            let risk_eval = risk_engine
                .evaluate(&request_ctx, Some(&subject_ctx), None, false)
                .await;
            (
                risk_eval.risk.total_score(),
                risk_eval.risk.overall,
                Some(risk_eval.risk),
            )
        } else {
            (0.0, RiskLevel::Low, None::<SharedRiskContext>)
        };

    // Issue 1: do NOT short-circuit on `risk_threshold`. The capsule is the
    // single authority — passing the risk score in via `RuntimeContext` lets
    // the policy decide whether to deny, step-up, or allow. The threshold
    // remains advisory and is surfaced through `with_risk()` for capsule use.

    // Service subjects (client_credentials) and agent sessions never have a
    // session row — skip session AAL lookup and step-up enforcement for both.
    let is_sessionless_subject = req.session_type == auth_core::jwt::session_types::SERVICE
        || req.session_type == auth_core::jwt::session_types::AGENT;

    // Issue 3: only consult the `sessions` table when an end-user session is
    // actually expected.  Sessionless principals have no `sessions` row;
    // querying for an empty session_id is wasted I/O.
    let (session_aal, session_capabilities, is_provisional) =
        if !is_sessionless_subject && !session_id.is_empty() {
            let row: Option<(i16, serde_json::Value, bool)> = sqlx::query_as(
                "SELECT aal_level, verified_capabilities, COALESCE(is_provisional, FALSE) \
                 FROM sessions \
                 WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE \
                 LIMIT 1",
            )
            .bind(session_id)
            .bind(req.tenant_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("Load OAuth EIAA session: {e}")))?;
            if let Some((aal, caps_json, provisional)) = row {
                let caps: Vec<String> = serde_json::from_value(caps_json).unwrap_or_default();
                (aal as u8, caps, provisional)
            } else {
                (0u8, Vec::new(), false)
            }
        } else {
            (0u8, Vec::new(), false)
        };

    // Issue 2: enforce `is_provisional` exactly like the Tower middleware. A
    // provisional session must satisfy step-up before being usable for OAuth
    // operations unless the route is configured to allow it.
    if !is_sessionless_subject && is_provisional && !config.allow_provisional {
        return Err(AppError::Forbidden(
            "OAuth EIAA decision requires step-up authentication (provisional session)".into(),
        ));
    }

    if !is_sessionless_subject {
        if let AalRequirement::Required(required) = derive_required_aal(risk_score, false) {
            if (session_aal as i16) < required.as_i16().max(AssuranceLevel::AAL1.as_i16()) {
                return Err(AppError::Forbidden(
                    "OAuth EIAA decision requires step-up authentication".into(),
                ));
            }
        }
    }

    let mut builder = AuthorizationContextBuilder::new()
        .with_identity(
            &claims.sub,
            &claims.tenant_id,
            &claims.session_type,
            &claims.sid,
        )
        .with_action(&action)
        .with_resource(req.client_id)
        .with_request(req.method, req.path)
        .with_network(ip, &user_agent)
        .with_risk(risk_score, risk_level)
        .with_aal(session_aal, &session_capabilities)
        .with_ttl_seconds(60);

    if let Some(risk_ctx) = full_risk_context {
        builder = builder.with_risk_context(risk_ctx);
    }

    let context = builder.build();
    let context_json = {
        let mut value = serde_json::to_value(&context)
            .map_err(|e| AppError::Internal(format!("Serialize OAuth EIAA context: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            // Issue 4: do NOT inject synthetic `subject_id: 1` /
            // `authz_decision: 1` constants. The capsule receives the
            // identity/risk/AAL through the builder; OAuth-specific metadata
            // is namespaced under `oauth`.
            obj.entry("factors_satisfied".to_string())
                .or_insert_with(|| serde_json::json!([]));
            obj.insert(
                "oauth".to_string(),
                serde_json::json!({
                    "client_id": req.client_id,
                    "scope": req.scope.unwrap_or(""),
                    "grant_type": req.grant_type.unwrap_or(""),
                    "dpop_jkt": req.confirmation_jkt,
                }),
            );
            // Inject agent-specific fields from the JWT claims so that
            // RuntimeContext.model_id / agent_id / task_id / delegation_chain
            // are populated for VerifyAgentIdentity and CheckDelegationChain
            // capsule host functions.
            if let Some(ref mid) = claims.model_id {
                obj.insert("model_id".to_string(), serde_json::json!(mid));
            }
            if let Some(ref aid) = claims.agent_id {
                obj.insert("agent_id".to_string(), serde_json::json!(aid));
            }
            if let Some(ref tid) = claims.task_id {
                obj.insert("task_id".to_string(), serde_json::json!(tid));
            }
            if let Some(ref chain) = claims.delegation_chain {
                obj.insert("delegation_chain".to_string(), serde_json::json!(chain));
            }
        }
        serde_json::to_string(&value)
            .map_err(|e| AppError::Internal(format!("Encode OAuth EIAA context: {e}")))?
    };

    // B.4: Agent OAuth flows get the same agent-prefixed capsule dispatch as
    // the Tower middleware path above. OAuth agent requests arrive here through
    // the PAR / device / token endpoints with session_type = "agent".
    //
    // NOTE: When the caller is authorize_tool_call (agents.rs) the action string
    // already carries the "agent:" prefix.  Only add the prefix when the action
    // does NOT already start with "agent:" to avoid "agent:agent:web_search".
    let effective_oauth_action =
        if claims.session_type == auth_core::jwt::session_types::AGENT
            && !action.starts_with("agent:")
        {
            format!("agent:{}", action)
        } else {
            action.clone()
        };

    // HIGH-5 FIX: Check the agent token blocklist before executing the capsule.
    // The Tower middleware path checks this at Step 1.5; without a matching check
    // here, a revoked agent token can still authorize tool calls via this path
    // even after POST /api/v1/agents/:agent_id/revoke has been called.
    if claims.session_type == auth_core::jwt::session_types::AGENT {
        if let Some(ref aid) = claims.agent_id {
            if let Some(mut redis_conn) = config.redis.clone() {
                let blocklist_key = format!("agent_blocklist:{}", aid);
                let revoked: bool = redis::cmd("EXISTS")
                    .arg(&blocklist_key)
                    .query_async::<redis::aio::ConnectionManager, i64>(&mut redis_conn)
                    .await
                    .map(|n| n > 0)
                    .unwrap_or(false);
                if revoked {
                    tracing::warn!(
                        agent_id = %aid,
                        action = %action,
                        "evaluate_oauth_action: agent token revoked — denying"
                    );
                    return Err(AppError::Forbidden("Agent token has been revoked".into()));
                }
            }
        }
    }

    match execute_authorization(&effective_oauth_action, &claims, &context_json, &config).await {
        Ok(AuthzResult::Allow {
            decision,
            attestation,
        }) => {
            if !config.skip_verification {
                verify_attestation(&decision, &attestation, &config)
                    .await
                    .map_err(|e| {
                        AppError::Forbidden(format!("OAuth EIAA attestation failed: {e}"))
                    })?;
            }
            let decision_ref = generate_decision_ref();
            if let Some(ref writer) = config.audit_writer {
                writer.record(create_audit_record_with_decision_ref(
                    &decision_ref,
                    &effective_oauth_action,
                    &claims,
                    &context,
                    true,
                    &attestation,
                ));
            }
            // CRIT-3 FIX: Fire agent webhooks in the evaluate_oauth_action path.
            // Previously, webhooks only fired in the Tower middleware path. SDK-initiated
            // tool-call authorizations (authorize_tool_call → evaluate_oauth_action) never
            // triggered tenant webhook endpoints.
            if effective_oauth_action.starts_with("agent:") {
                if let Some(ref svc) = config.agent_webhook_service {
                    svc.on_authorized(crate::services::AgentWebhookPayload {
                        event: crate::services::AgentEventKind::AgentActionAuthorized,
                        timestamp: Utc::now().to_rfc3339(),
                        tenant_id: claims.tenant_id.clone(),
                        task_id: claims.task_id.clone(),
                        agent_id: claims.agent_id.clone(),
                        model_id: claims.model_id.clone(),
                        tool_name: context.tool_name.clone(),
                        decision_ref: decision_ref.clone(),
                        risk_score: Some(risk_score as i32),
                        attestation_signature_b64: if attestation.signature_b64.is_empty() {
                            None
                        } else {
                            Some(attestation.signature_b64.clone())
                        },
                    });
                }
            }
            Ok(EiaaDecisionArtifact::from_parts(
                decision_ref,
                effective_oauth_action.clone(),
                true,
                None,
                &attestation,
            ))
        }
        Ok(AuthzResult::Deny {
            reason,
            decision: _,
            attestation,
        }) => {
            let decision_ref = generate_decision_ref();
            if let Some(ref writer) = config.audit_writer {
                writer.record(create_audit_record_with_decision_ref(
                    &decision_ref,
                    &effective_oauth_action,
                    &claims,
                    &context,
                    false,
                    &attestation,
                ));
            }
            // CRIT-3 FIX: Fire denial webhooks in the evaluate_oauth_action path.
            if effective_oauth_action.starts_with("agent:") {
                if let Some(ref svc) = config.agent_webhook_service {
                    svc.on_denied(crate::services::AgentWebhookPayload {
                        event: crate::services::AgentEventKind::AgentActionDenied,
                        timestamp: Utc::now().to_rfc3339(),
                        tenant_id: claims.tenant_id.clone(),
                        task_id: claims.task_id.clone(),
                        agent_id: claims.agent_id.clone(),
                        model_id: claims.model_id.clone(),
                        tool_name: context.tool_name.clone(),
                        decision_ref: decision_ref.clone(),
                        risk_score: Some(risk_score as i32),
                        attestation_signature_b64: if attestation.signature_b64.is_empty() {
                            None
                        } else {
                            Some(attestation.signature_b64.clone())
                        },
                    });
                }
            }
            Err(AppError::Forbidden(reason))
        }
        Err(e) => Err(AppError::Internal(format!(
            "OAuth EIAA execution failed: {e}"
        ))),
    }
}

#[allow(dead_code)]
fn extract_network_context_from_headers(headers: Option<&HeaderMap>) -> (IpAddr, String) {
    // Retained for any non-OAuth callers that need a quick (ip, ua) tuple.
    // The OAuth path uses `OAuthEiaaNetwork::from_headers` instead.
    let _ = headers;
    let ip = headers
        .and_then(|h| h.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            headers
                .and_then(|h| h.get("x-real-ip"))
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok())
        })
        .unwrap_or_else(|| "0.0.0.0".parse().unwrap());
    let user_agent = headers
        .and_then(|h| h.get(header::USER_AGENT))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    (ip, user_agent)
}

/// Verify attestation signature
async fn verify_attestation(
    decision: &VerifierDecision,
    attestation: &AttestationData,
    config: &EiaaAuthzConfig,
) -> anyhow::Result<()> {
    let body = attestation
        .body
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing attestation body"))?;

    // Ensure we have keys cached
    if let Some(ref key_cache) = config.key_cache {
        if !key_cache.contains(&body.runtime_kid).await {
            // GAP-1 FIX: Use shared client for key fetch too
            let keys = match config.runtime_client {
                Some(ref shared) => shared.get_public_keys().await?,
                None => {
                    return Err(anyhow::anyhow!(
                        "No SharedRuntimeClient configured — cannot fetch public keys."
                    ));
                }
            };
            key_cache
                .insert_batch(keys)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to cache keys: {e}"))?;
        }
    }

    // Verify with verifier service
    if let Some(ref verifier) = config.verifier {
        // Ensure verifier has the key
        if let Some(ref key_cache) = config.key_cache {
            if let Some(key) = key_cache.get(&body.runtime_kid).await {
                verifier.load_key(body.runtime_kid.clone(), key).await;
            }
        }

        let att = VerifierAttestation {
            body: body.clone(),
            signature_b64: attestation.signature_b64.clone(),
        };

        verifier
            .verify(&att, decision, Utc::now())
            .await
            .map_err(|e| anyhow::anyhow!("Verification failed: {e}"))?;
    }

    Ok(())
}

/// Create audit record from authorization result.
///
/// CRITICAL-EIAA-4 FIX: Store the full `input_context` JSON string alongside the
/// `input_digest` hash. This enables the ReExecutionService to replay the exact same
/// inputs through the capsule and verify the decision matches the stored record.
fn create_audit_record_with_decision_ref(
    decision_ref: &str,
    action: &str,
    claims: &Claims,
    context: &crate::middleware::authorization_context::AuthorizationContext,
    allowed: bool,
    attestation: &AttestationData,
) -> AuditRecord {
    // Serialize context to canonical JSON string (minified, deterministic field order).
    // This is the exact byte sequence that will be replayed during re-execution.
    // serde_json serializes struct fields in definition order, which is deterministic.
    let input_context_json = serde_json::to_string(context).ok();

    // Compute SHA-256 digest of the input context for fast integrity verification.
    // The digest allows quick tamper detection without loading the full context.
    let input_digest = if let Some(ref ctx_json) = input_context_json {
        let mut hasher = Sha256::new();
        hasher.update(ctx_json.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    } else {
        // Fallback: hash an empty string (should never happen in practice)
        let mut hasher = Sha256::new();
        hasher.update(b"");
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    };

    AuditRecord {
        decision_ref: decision_ref.to_string(),
        capsule_hash_b64: attestation.capsule_hash.clone(),
        capsule_version: "1.0".to_string(),
        action: action.to_string(),
        tenant_id: claims.tenant_id.clone(),
        input_digest,
        input_context: input_context_json,
        nonce_b64: attestation.nonce.clone(),
        decision: AuditDecision {
            allow: allowed,
            reason: if allowed {
                None
            } else {
                Some("denied".to_string())
            },
        },
        attestation_signature_b64: attestation.signature_b64.clone(),
        attestation_timestamp: attestation.timestamp,
        attestation_hash_b64: {
            // Compute hash of attestation body for tamper evidence
            if let Some(ref body) = attestation.body {
                let body_json = serde_json::to_vec(body).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(&body_json);
                Some(URL_SAFE_NO_PAD.encode(hasher.finalize()))
            } else {
                None
            }
        },
        user_id: Some(claims.sub.clone()),
        // Sprint C: populate agent task chain fields from JWT claims
        task_id: claims.task_id.clone(),
        parent_action_id: None,
        delegation_depth: claims.delegation_chain.as_ref().map(|c| c.len() as u8).unwrap_or(0),
        principal_type: claims.session_type.clone(),
        agent_id: claims.agent_id.clone(),
        model_id: claims.model_id.clone(),
        tool_name: context.tool_name.clone(),
        tool_args_hash: context.tool_args_hash.clone(),
    }
}

fn unauthorized_response(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, message.to_string()).into_response()
}

fn forbidden_response(reason: &str, requirement: Option<&Requirement>) -> Response {
    let body = serde_json::json!({
        "error": "Forbidden",
        "message": reason,
        "requirement": requirement
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

/// RFC 9470 step-up response.
///
/// Returns 403 Forbidden with a `WWW-Authenticate: Step-Up` challenge so that
/// clients can transparently trigger a step-up flow without a full re-login.
/// The body carries a structured `requirement` block matching the shape used
/// by capsule-issued requirements, plus an `error_code` the frontend can match.
fn step_up_required_response(required_aal: i16, reason: &str) -> Response {
    let assurance = format!("AAL{required_aal}");
    let body = serde_json::json!({
        "error": "AUTH_STEP_UP_REQUIRED",
        "message": reason,
        "requirement": {
            "required_assurance": assurance,
            "acceptable_capabilities": ["totp"],
            "disallowed_capabilities": [],
            "require_phishing_resistant": false,
            "session_restrictions": []
        }
    });
    let mut resp = (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
    // RFC 9470: "Step Up Authentication Challenge Protocol"
    if let Ok(value) = format!(
        "Step-Up realm=\"idaas\", required_aal=\"{assurance}\", error=\"insufficient_user_authentication\""
    )
    .parse()
    {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    resp
}

fn internal_error_response(message: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, message.to_string()).into_response()
}

// Issue #2 fix: Use shared token extraction utility to avoid duplication
use crate::middleware::token_utils::extract_bearer_token as extract_token;

/// Sprint G — Validate a SPIFFE JWT-SVID header value.
///
/// Decodes the JWT payload (no signature check — the SPIRE sidecar guarantees
/// authenticity via the pod network namespace) and validates:
/// 1. The token has exactly 3 dot-separated segments (JWT structure).
/// 2. The `sub` claim is a valid SPIFFE ID matching the configured trust domain:
///    `spiffe://<trust_domain>/...`
///
/// Returns the validated SPIFFE ID string on success, or an error description.
fn validate_spiffe_svid(token: &str, trust_domain: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "invalid JWT-SVID structure: expected 3 segments, got {}",
            parts.len()
        ));
    }

    // MED-6 FIX: Decode using URL_SAFE_NO_PAD (correct for JWT base64url).
    // The old code built a `padded` string then still passed the UNPADDED source
    // to URL_SAFE_NO_PAD.decode, making the allocation pointless. The fallback
    // used STANDARD engine (wrong alphabet — `+`/`/` vs `-`/`_`).
    // Fixed: primary decode is URL_SAFE_NO_PAD; fallback is URL_SAFE (with padding).
    let payload_b64 = parts[1];
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| {
            // Some SPIRE versions emit padding; retry with the padded-accepting variant.
            base64::engine::general_purpose::URL_SAFE.decode(payload_b64)
        })
        .map_err(|e| format!("JWT-SVID payload base64 decode failed: {}", e))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT-SVID payload JSON parse failed: {}", e))?;

    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JWT-SVID missing `sub` claim".to_string())?;

    // Validate SPIFFE URI format: spiffe://<trust_domain>/...
    let expected_prefix = format!("spiffe://{}/", trust_domain);
    if !sub.starts_with(&expected_prefix) {
        return Err(format!(
            "JWT-SVID `sub` `{}` does not match trust domain `{}`",
            sub, trust_domain
        ));
    }

    Ok(sub.to_string())
}

/// Verify token and session (async) - takes owned token string to avoid lifetime issues
async fn verify_token_and_session(
    token: &str,
    config: &EiaaAuthzConfig,
) -> Result<Claims, StatusCode> {
    // Get jwt_service and db from config
    let jwt_service = config.jwt_service.as_ref().ok_or_else(|| {
        tracing::error!("EIAA authz: jwt_service not configured");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let db = config.db.as_ref().ok_or_else(|| {
        tracing::error!("EIAA authz: db not configured");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Verify JWT signature
    let claims = jwt_service.verify_token(token).map_err(|e| {
        tracing::warn!("JWT verification failed: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    // MED-4: Short-circuit agent sessions here too — parallel to the fix in auth.rs.
    // Agent tokens have an empty sid, so the sessions query below would always return
    // None → UNAUTHORIZED. The JWT signature check above is sufficient for agents.
    if claims.session_type == auth_core::jwt::session_types::AGENT {
        tracing::debug!(
            user_id = %claims.sub,
            tenant_id = %claims.tenant_id,
            "verify_token_and_session (eiaa): agent session — skipping DB session check"
        );
        return Ok(claims);
    }

    // MED-4: Short-circuit service sessions — same as auth.rs:61.
    if claims.session_type == auth_core::jwt::session_types::SERVICE {
        tracing::debug!(
            user_id = %claims.sub,
            tenant_id = %claims.tenant_id,
            "verify_token_and_session (eiaa): service session — skipping DB session check"
        );
        return Ok(claims);
    }

    // Verify session is still valid (not revoked, not expired) — tenant-scoped
    let session_state: Option<bool> = sqlx::query_scalar(
        "SELECT is_provisional FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE"
    )
    .bind(&claims.sid)
    .bind(&claims.tenant_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Session DB check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match session_state {
        Some(false) => Ok(claims),
        Some(true) => {
            if config.allow_provisional {
                Ok(claims)
            } else {
                tracing::warn!("Provisional session access attempted for protected route");
                Err(StatusCode::FORBIDDEN)
            }
        }
        None => {
            tracing::warn!("Session not found or expired: {}", claims.sid);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = AuditWriter::generate_nonce();
        let nonce2 = AuditWriter::generate_nonce();

        // Nonces should be unique
        assert_ne!(nonce1, nonce2);

        // Should be base64 encoded (22 chars for 16 bytes)
        assert_eq!(nonce1.len(), 22);
    }

    #[test]
    fn test_default_config() {
        let config = EiaaAuthzConfig::default();
        assert!(!config.fail_open);
        assert!(!config.skip_verification);
        assert_eq!(config.risk_threshold, 80.0);
    }
}
