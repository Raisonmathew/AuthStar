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

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use auth_core::Claims;
use crate::services::{
    AuditWriter, AuditRecord, AuditDecision, CapsuleCacheService,
    AttestationVerifier, RuntimeKeyCache,
    attestation_verifier::{Decision as VerifierDecision, Attestation as VerifierAttestation, AttestationBody as VerifierAttestationBody, Requirement},
};
use crate::services::eiaa_flow_service::EiaaFlowService;
use crate::middleware::authorization_context::AuthorizationContextBuilder;
use crate::clients::runtime_client::EiaaRuntimeClient;
use grpc_api::eiaa::runtime::{CapsuleSigned, GetPublicKeysRequest};
use chrono::Utc;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use shared_types::RiskLevel;
// Full Risk Engine integration
use risk_engine::{RiskEngine, RequestContext as RiskRequestContext, SubjectContext, NetworkInput};
// Attestation frequency matrix
use crate::middleware::action_risk::ActionRiskLevel;
use crate::services::AttestationDecisionCache;
use auth_core::JwtService;
use sqlx::PgPool;
use std::sync::Arc as StdArc;

/// EIAA Authorization Layer (Production-Grade)
///
/// Apply to routes that require capsule-based authorization:
/// ```rust
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
    /// Database pool for session verification
    pub db: Option<PgPool>,
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

    /// Create with minimal config (for testing)
    pub fn simple(action: &str, runtime_addr: &str) -> Self {
        Self::new(
            action,
            EiaaAuthzConfig {
                runtime_addr: runtime_addr.to_string(),
                ..Default::default()
            },
        )
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
            let (risk_score, risk_level) = if let Some(ref risk_engine) = config.risk_engine {
                // Build request context for Risk Engine
                let request_ctx = RiskRequestContext {
                    network: NetworkInput {
                        remote_ip: ip,
                        x_forwarded_for: None,
                        user_agent: user_agent.clone(),
                        accept_language: req.headers()
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

                // Evaluate risk
                let risk_eval = risk_engine.evaluate(&request_ctx, Some(&subject_ctx), None).await;
                
                // Convert RiskContext to score and level
                let score = risk_eval.risk.total_score();
                let level = risk_eval.risk.overall;

                tracing::debug!(
                    user_id = %claims.sub,
                    risk_score = %score,
                    risk_level = ?level,
                    "Risk evaluation completed"
                );

                (score, level)
            } else {
                // No risk engine configured - use safe defaults
                tracing::warn!("RiskEngine not configured, using default low risk");
                (0.0, RiskLevel::Low)
            };

            // === Step 4: Check Risk Threshold ===
            if config.risk_threshold > 0.0 && risk_score > config.risk_threshold {
                tracing::warn!(
                    user_id = %claims.sub,
                    risk_score = %risk_score,
                    threshold = %config.risk_threshold,
                    "Request denied due to high risk score"
                );
                return Ok(forbidden_response("Request denied due to elevated risk", None));
            }

            // === Step 4.5: Attestation Frequency Matrix - Check Cache ===
            let action_risk = ActionRiskLevel::from_action(&action);
            let ip_str = ip.to_string();
            let context_hash = crate::services::attestation_decision_cache::AttestationDecisionCache::hash_context(
                Some(ip_str.as_str()),
                risk_score,
            );

            if let Some(ref decision_cache) = config.decision_cache {
                if let Some(cached) = decision_cache.get(
                    &claims.sub,
                    &claims.tenant_id,
                    &action,
                    &context_hash,
                    action_risk,
                ).await {
                    tracing::info!(
                        action = %action,
                        user_id = %claims.sub,
                        risk_level = ?action_risk,
                        "Using cached attestation decision"
                    );
                    
                    if cached.allowed {
                        return Ok(inner.call(req).await?);
                    } else {
                        return Ok(forbidden_response(&cached.reason, None));
                    }
                }
            }

            // === Step 5: Build Rich Authorization Context ===
            let method = req.method().as_str();
            let path = req.uri().path();
            let context = AuthorizationContextBuilder::new()
                .with_identity(&claims.sub, &claims.tenant_id, &claims.session_type, &claims.sid)
                .with_action(&action)
                .with_request(method, path)
                .with_network(ip, &user_agent)
                .with_risk(risk_score, risk_level)
                .with_ttl_seconds(60)
                .build();

            let context_json = match serde_json::to_string(&context) {
                Ok(json) => json,
                Err(e) => {
                    tracing::error!("Failed to serialize context: {}", e);
                    return Ok(internal_error_response("Context serialization failed"));
                }
            };

            // === Step 6: Execute Capsule Authorization ===
            match execute_authorization(&action, &claims, &context_json, &config).await {
                Ok(AuthzResult::Allow { decision, attestation }) => {
                    // === Step 7: Verify Attestation Signature ===
                    if !config.skip_verification {
                        if let Err(e) = verify_attestation(&decision, &attestation, &config).await {
                            tracing::error!("Attestation verification failed: {}", e);
                            return Ok(forbidden_response("Authorization verification failed", None));
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
                    if let Some(ref decision_cache) = config.decision_cache {
                        decision_cache.set(
                            &claims.sub,
                            &claims.tenant_id,
                            &action,
                            &context_hash,
                            action_risk,
                            true,
                            "allowed",
                            Some(&attestation.signature_b64),
                        ).await;
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
                Ok(AuthzResult::Deny { reason, decision, attestation }) => {
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

/// Execute capsule-based authorization
async fn execute_authorization(
    action: &str,
    claims: &Claims,
    context_json: &str,
    config: &EiaaAuthzConfig,
) -> anyhow::Result<AuthzResult> {
    // Generate nonce for replay protection
    let nonce = generate_nonce();

    // Try cache first
    let capsule = if let Some(ref cache) = config.cache {
        if let Some(cached) = cache.get(&claims.tenant_id, action).await {
            use prost::Message;
            CapsuleSigned::decode(cached.capsule_bytes.as_slice()).ok()
        } else {
            None
        }
    } else {
        None
    };

    // Connect to runtime
    let mut client = EiaaRuntimeClient::connect(config.runtime_addr.clone()).await?;

    // Execute capsule
    let response = if let Some(capsule) = capsule {
        client.execute_capsule(capsule, context_json.to_string(), nonce.clone()).await?
    } else {
        return Err(anyhow::anyhow!("Capsule not found in cache for action: {}", action));
    };

    // Extract decision and attestation
    let dec = response.decision.ok_or_else(|| anyhow::anyhow!("No decision in response"))?;
    let att = response.attestation;

    let decision = VerifierDecision {
        allow: dec.allow,
        reason: if dec.reason.is_empty() { None } else { Some(dec.reason.clone()) },
        requirement: dec.requirement.map(|r| Requirement {
            required_assurance: if r.required_assurance.is_empty() { None } else { Some(r.required_assurance) },
            acceptable_capabilities: r.acceptable_capabilities,
            disallowed_capabilities: r.disallowed_capabilities,
            require_phishing_resistant: r.require_phishing_resistant,
            session_restrictions: r.session_restrictions,
        }),
    };

    let attestation_data = att.map(|a| {
        // Extract capsule_hash before consuming body
        let capsule_hash = a.body.as_ref()
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
    }).unwrap_or_default();

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
    let body = attestation.body.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing attestation body"))?;

    // Ensure we have keys cached
    if let Some(ref key_cache) = config.key_cache {
        if !key_cache.contains(&body.runtime_kid).await {
            // Fetch keys from runtime
            let mut client = EiaaRuntimeClient::connect(config.runtime_addr.clone()).await?;
            let keys = client.get_public_keys().await?;
            key_cache.insert_batch(keys).await
                .map_err(|e| anyhow::anyhow!("Failed to cache keys: {}", e))?;
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

        verifier.verify(&att, decision, Utc::now()).await
            .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))?;
    }

    Ok(())
}

/// Generate cryptographic nonce
fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Create audit record from authorization result
fn create_audit_record(
    action: &str,
    claims: &Claims,
    context: &crate::middleware::authorization_context::AuthorizationContext,
    allowed: bool,
    attestation: &AttestationData,
) -> AuditRecord {
    // Generate input digest for re-execution verification
    let input_bytes = serde_json::to_vec(context).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&input_bytes);
    let input_digest = URL_SAFE_NO_PAD.encode(hasher.finalize());

    AuditRecord {
        decision_ref: format!("dec_{}", uuid::Uuid::new_v4().to_string().replace("-", "")),
        capsule_hash_b64: attestation.capsule_hash.clone(),
        capsule_version: "1.0".to_string(),
        action: action.to_string(),
        tenant_id: claims.tenant_id.clone(),
        input_digest,
        nonce_b64: attestation.nonce.clone(),
        decision: AuditDecision {
            allow: allowed,
            reason: if allowed { None } else { Some("denied".to_string()) },
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

/// Extract auth token from cookie first, then Authorization header.
fn extract_token(req: &Request<Body>) -> Option<String> {
    // 1. Try httpOnly session cookie
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("__session=") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    // 2. Fall back to Authorization header (server SDK, API key mode)
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.to_string())
}

/// Verify token and session (async) - takes owned token string to avoid lifetime issues
async fn verify_token_and_session(
    token: &str,
    config: &EiaaAuthzConfig,
) -> Result<Claims, StatusCode> {
    // Get jwt_service and db from config
    let jwt_service = config.jwt_service.as_ref()
        .ok_or_else(|| {
            tracing::error!("EIAA authz: jwt_service not configured");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    let db = config.db.as_ref()
        .ok_or_else(|| {
            tracing::error!("EIAA authz: db not configured");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Verify JWT signature
    let claims = jwt_service.verify_token(token)
        .map_err(|e| {
            tracing::warn!("JWT verification failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Verify session is still valid (not revoked, not expired) — tenant-scoped
    let session_state: Option<bool> = sqlx::query_scalar(
        "SELECT is_provisional FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()"
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
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

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
