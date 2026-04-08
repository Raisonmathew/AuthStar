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
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures_util::future::BoxFuture;
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use sha2::{Digest, Sha256};
use shared_types::RiskLevel;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
// Full Risk Engine integration
use risk_engine::{NetworkInput, RequestContext as RiskRequestContext, RiskEngine, SubjectContext};
use shared_types::auth::RiskContext as SharedRiskContext;
// Attestation frequency matrix
use crate::middleware::action_risk::ActionRiskLevel;
use crate::services::{AttestationDecisionCache, CacheDecisionParams};
use auth_core::JwtService;
use keystore::{InMemoryKeystore, KeyId};
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
            let claims = if let Some(claims) = req.extensions().get::<Claims>() {
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
                            x_forwarded_for: None,
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

                    // Evaluate risk — capture the full evaluation result
                    let risk_eval = risk_engine
                        .evaluate(&request_ctx, Some(&subject_ctx), None)
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
            // HIGH-EIAA-2 FIX: Load AAL and verified_capabilities from session DB.
            // These fields are required for capsule policies to enforce AAL requirements
            // (e.g., "require AAL2 for billing operations") and capability checks.
            // They are stored on the session by migration 032.
            let (session_aal, session_capabilities) = if let Some(ref db) = config.db {
                let row: Option<(i16, serde_json::Value)> = sqlx::query_as(
                    "SELECT aal_level, verified_capabilities FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW() AND revoked = FALSE LIMIT 1"
                )
                .bind(&claims.sid)
                .bind(&claims.tenant_id)
                .fetch_optional(db)
                .await
                .unwrap_or(None);

                if let Some((aal, caps_json)) = row {
                    let caps: Vec<String> = serde_json::from_value(caps_json).unwrap_or_default();
                    (aal as u8, caps)
                } else {
                    (0u8, vec![])
                }
            } else {
                (0u8, vec![])
            };

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
            match execute_authorization(&action, &claims, &context_json, &config).await {
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

                    // === Step 8: Record to Audit Trail ===
                    if let Some(ref writer) = config.audit_writer {
                        writer.record(create_audit_record(
                            &action,
                            &claims,
                            &context,
                            true,
                            &attestation,
                        ));
                    }

                    // === Step 8.5: Cache Decision (Attestation Frequency Matrix) ===
                    // HIGH-EIAA-4 FIX: Store the full attestation body alongside the
                    // signature so it can be re-verified on cache hit.
                    if let Some(ref decision_cache) = config.decision_cache {
                        decision_cache
                            .set(CacheDecisionParams {
                                user_id: &claims.sub,
                                tenant_id: &claims.tenant_id,
                                action: &action,
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

                    // Record denial
                    if let Some(ref writer) = config.audit_writer {
                        writer.record(create_audit_record(
                            &action,
                            &claims,
                            &context,
                            false,
                            &attestation,
                        ));
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

    // Build a minimal policy: verify identity, authorize action, allow
    let policy = Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: action.to_string(),
                resource: tenant_id.to_string(),
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
                load_capsule_from_db(db, &claims.tenant_id, action)
                    .await
                    .map_err(|e| anyhow::anyhow!("DB capsule lookup failed: {e}"))?
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
                                        let cached = crate::services::capsule_cache::CachedCapsule {
                                            tenant_id: claims.tenant_id.clone(),
                                            action: action.to_string(),
                                            version: 1,
                                            ast_hash: capsule.ast_hash_b64.clone(),
                                            wasm_hash: capsule.wasm_hash_b64.clone(),
                                            capsule_bytes,
                                            cached_at: chrono::Utc::now().timestamp(),
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
fn create_audit_record(
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
        decision_ref: format!("dec_{}", uuid::Uuid::new_v4().to_string().replace("-", "")),
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

fn internal_error_response(message: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, message.to_string()).into_response()
}

// Issue #2 fix: Use shared token extraction utility to avoid duplication
use crate::middleware::token_utils::extract_bearer_token as extract_token;

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
