#![allow(dead_code)]
//! EIAA Runtime gRPC Client with Circuit Breaker + Retry
//!
//! ## Architecture
//!
//! `SharedRuntimeClient` is the production entry point, stored in `AppState`.
//! It is `Clone`-cheap (Arc over atomics + tonic Channel clone) and fully
//! concurrent — **no mutex**. Tonic's `Channel` already multiplexes HTTP/2
//! streams internally, so cloning it is an Arc bump, not a new TCP connection.
//!
//! ### Wire format
//!
//! The gRPC transport uses **protobuf binary** encoding (tonic/prost default).
//! The `input_json` field inside `ExecuteRequest` carries a JSON-encoded
//! runtime context string inside a protobuf `string` field — this is by design
//! so capsules receive dynamic context without schema coupling.
//!
//! ### Circuit Breaker (lock-free)
//!
//! Pure atomic state machine — no mutex needed. Prevents cascading failures
//! when the runtime pod is down by fast-failing requests instead of blocking
//! for the gRPC timeout.
//!
//! - **Closed** → all requests pass; failure counter increments on transient error.
//! - **Open** → all requests immediately fail with `ServiceUnavailable`.
//!   Trips after `failure_threshold` (5) consecutive failures.
//! - **HalfOpen** → one probe request allowed after `recovery_window_secs` (30s).
//!   Success → Closed; failure → back to Open.
//!
//! ### Retry with Exponential Backoff
//!
//! Transient gRPC errors are retried up to 3 times with exponential backoff
//! (100ms → 200ms → 400ms, ±25% jitter). Only retryable status codes
//! (Unavailable, DeadlineExceeded, ResourceExhausted, Unknown, Internal,
//! Aborted) trigger retries. Permanent errors fail immediately without
//! touching the circuit breaker.
//!
//! ### Trace Context Propagation (GAP-4)
//!
//! W3C `traceparent` is injected into outgoing gRPC metadata so runtime spans
//! appear as children of API server spans in Jaeger/Tempo.

use anyhow::{anyhow, Result};
use grpc_api::eiaa::runtime::{
    capsule_runtime_client::CapsuleRuntimeClient, CapsuleSigned, ExecuteRequest,
    ExecuteResponse, GetPublicKeysRequest, AuthEvidence,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;
use tonic::transport::Channel;
use tonic::Code;

// ─── Trace Context Propagation ───────────────────────────────────────────────

struct TonicMetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);

impl<'a> opentelemetry::propagation::Injector for TonicMetadataInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = tonic::metadata::MetadataValue::try_from(value.as_str()) {
                self.0.insert(key, val);
            }
        }
    }
}

fn inject_trace_context(metadata: &mut tonic::metadata::MetadataMap) {
    let cx = opentelemetry::Context::current();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut TonicMetadataInjector(metadata));
    });
}

// ─── Retry Configuration ─────────────────────────────────────────────────────

const MAX_ATTEMPTS: u32 = 3;
const RETRY_BASE_MS: u64 = 100;

fn is_retryable(code: Code) -> bool {
    matches!(
        code,
        Code::Unavailable
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Unknown
            | Code::Internal
            | Code::Aborted
    )
}

fn retry_delay(attempt: u32) -> Duration {
    use rand::Rng;
    let base = RETRY_BASE_MS * (1u64 << attempt.min(10));
    let jitter_range = base / 4;
    let jitter = if jitter_range > 0 {
        rand::thread_rng().gen_range(0..=jitter_range * 2).saturating_sub(jitter_range)
    } else {
        0
    };
    Duration::from_millis(base.saturating_add(jitter))
}

// ─── Circuit Breaker (lock-free) ─────────────────────────────────────────────

const CB_CLOSED: u8 = 0;
const CB_OPEN: u8 = 1;
const CB_HALF_OPEN: u8 = 2;

#[derive(Clone)]
struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

struct CircuitBreakerInner {
    state: AtomicU8,
    failure_count: AtomicU32,
    opened_at: AtomicU64,
    failure_threshold: u32,
    recovery_window_secs: u64,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, recovery_window_secs: u64) -> Self {
        Self {
            inner: Arc::new(CircuitBreakerInner {
                state: AtomicU8::new(CB_CLOSED),
                failure_count: AtomicU32::new(0),
                opened_at: AtomicU64::new(0),
                failure_threshold,
                recovery_window_secs,
            }),
        }
    }

    fn allow_request(&self) -> bool {
        let state = self.inner.state.load(Ordering::Acquire);
        match state {
            CB_CLOSED => true,
            CB_OPEN => {
                let now = now_secs();
                let opened_at = self.inner.opened_at.load(Ordering::Acquire);
                if now.saturating_sub(opened_at) >= self.inner.recovery_window_secs {
                    if self.inner.state.compare_exchange(
                        CB_OPEN, CB_HALF_OPEN, Ordering::AcqRel, Ordering::Acquire
                    ).is_ok() {
                        tracing::info!("Circuit breaker: OPEN → HALF_OPEN (recovery probe)");
                        true
                    } else {
                        self.inner.state.load(Ordering::Acquire) == CB_HALF_OPEN
                    }
                } else {
                    false
                }
            }
            CB_HALF_OPEN => false,
            _ => true,
        }
    }

    fn record_success(&self) {
        let prev = self.inner.state.swap(CB_CLOSED, Ordering::AcqRel);
        self.inner.failure_count.store(0, Ordering::Release);
        if prev != CB_CLOSED {
            tracing::info!("Circuit breaker: → CLOSED (runtime recovered)");
        }
    }

    /// Record a transient infrastructure failure. Uses CAS to avoid the
    /// TOCTOU race between `fetch_add(failure_count)` and `load(state)`:
    /// we atomically transition CLOSED→OPEN only if still CLOSED.
    fn record_failure(&self) {
        let count = self.inner.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
        let state = self.inner.state.load(Ordering::Acquire);

        if state == CB_HALF_OPEN {
            // Probe failed — back to Open. CAS so only one thread wins.
            let now = now_secs();
            if self.inner.state.compare_exchange(
                CB_HALF_OPEN, CB_OPEN, Ordering::AcqRel, Ordering::Acquire
            ).is_ok() {
                self.inner.opened_at.store(now, Ordering::Release);
                tracing::warn!("Circuit breaker: HALF_OPEN → OPEN (probe failed)");
            }
        } else if state == CB_CLOSED && count >= self.inner.failure_threshold {
            // Threshold reached — CAS to avoid double-open from concurrent failures.
            let now = now_secs();
            if self.inner.state.compare_exchange(
                CB_CLOSED, CB_OPEN, Ordering::AcqRel, Ordering::Acquire
            ).is_ok() {
                self.inner.opened_at.store(now, Ordering::Release);
                tracing::error!(
                    "Circuit breaker: CLOSED → OPEN after {} consecutive failures \
                     (runtime gRPC unavailable; recovery probe in {}s)",
                    count, self.inner.recovery_window_secs
                );
            }
        }
    }

    /// Reset the consecutive failure counter without changing state.
    /// Called on permanent (non-infrastructure) errors so they don't
    /// inflate the counter toward tripping the breaker.
    fn reset_failure_count(&self) {
        self.inner.failure_count.store(0, Ordering::Release);
    }

    fn is_open(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == CB_OPEN
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Low-level Client (not public — use SharedRuntimeClient) ─────────────────

#[derive(Clone)]
struct EiaaRuntimeClient {
    client: CapsuleRuntimeClient<Channel>,
    cb: CircuitBreaker,
}

/// Endpoint configuration constants.
const GRPC_TIMEOUT: Duration = Duration::from_secs(5);
const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GRPC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const GRPC_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

impl EiaaRuntimeClient {
    pub fn connect(addr: String) -> Result<Self> {
        let channel = tonic::transport::Endpoint::from_shared(addr)?
            .timeout(GRPC_TIMEOUT)
            .connect_timeout(GRPC_CONNECT_TIMEOUT)
            .keep_alive_timeout(GRPC_KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(GRPC_KEEP_ALIVE_INTERVAL)
            .connect_lazy();
        let client = CapsuleRuntimeClient::new(channel);
        Ok(Self {
            client,
            cb: CircuitBreaker::new(5, 30),
        })
    }

    /// Connect with client-side load balancing across multiple endpoints.
    ///
    /// Uses tonic's `Channel::balance_list` which distributes requests
    /// round-robin across all healthy endpoints. Each endpoint gets its own
    /// HTTP/2 connection with keep-alive and adaptive flow control.
    pub fn connect_balanced(endpoints: Vec<String>) -> Result<Self> {
        let eps: Vec<tonic::transport::Endpoint> = endpoints
            .into_iter()
            .map(|addr| {
                tonic::transport::Endpoint::from_shared(addr)
                    .map(|ep| {
                        ep.timeout(GRPC_TIMEOUT)
                            .connect_timeout(GRPC_CONNECT_TIMEOUT)
                            .keep_alive_timeout(GRPC_KEEP_ALIVE_TIMEOUT)
                            .keep_alive_while_idle(true)
                            .http2_adaptive_window(true)
                            .http2_keep_alive_interval(GRPC_KEEP_ALIVE_INTERVAL)
                    })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let channel = Channel::balance_list(eps.into_iter());
        let client = CapsuleRuntimeClient::new(channel);
        Ok(Self {
            client,
            cb: CircuitBreaker::new(5, 30),
        })
    }

    /// Unified execute with retry + circuit breaker.
    /// `evidence` is `None` for normal capsule execution, `Some(...)` for SSO.
    async fn execute_inner(
        &self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
        evidence: Option<AuthEvidence>,
    ) -> Result<ExecuteResponse> {
        if !self.cb.allow_request() {
            return Err(anyhow!(
                "Runtime circuit breaker is OPEN — authorization service temporarily unavailable"
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let label = if evidence.is_some() { "execute_with_evidence" } else { "execute" };

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            let is_last = attempt + 1 == MAX_ATTEMPTS;

            let exec_req = ExecuteRequest {
                capsule: Some(capsule.clone()),
                input_json: input_json.clone(),
                nonce_b64: nonce_b64.clone(),
                now_unix: now,
                expires_at_unix: now + 300,
                auth_evidence: evidence.clone(),
            };

            let mut req = tonic::Request::new(exec_req);
            inject_trace_context(req.metadata_mut());

            // Clone the tonic client (cheap Arc bump on the HTTP/2 channel)
            // so we don't need &mut self and multiple requests can fly concurrently.
            let mut client = self.client.clone();

            match client.execute(req).await {
                Ok(response) => {
                    self.cb.record_success();
                    if attempt > 0 {
                        tracing::info!(attempt, "Runtime gRPC {label} succeeded after {attempt} retries");
                    }
                    return Ok(response.into_inner());
                }
                Err(e) => {
                    let code = e.code();
                    last_err = e.to_string();

                    if !is_retryable(code) {
                        // Permanent error — reset failure counter so non-infra
                        // errors don't accumulate toward tripping the breaker.
                        self.cb.reset_failure_count();
                        tracing::warn!(?code, "Runtime gRPC {label}: non-retryable error: {last_err}");
                        return Err(anyhow!("Runtime gRPC {label} failed (permanent): {last_err}"));
                    }

                    if !is_last {
                        let delay = retry_delay(attempt);
                        tracing::warn!(
                            attempt, ?code, delay_ms = delay.as_millis(),
                            "Runtime gRPC {label}: transient error, retrying in {delay:?}: {last_err}"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        self.cb.record_failure();
        Err(anyhow!("Runtime gRPC {label} failed after {MAX_ATTEMPTS} attempts: {last_err}"))
    }

    async fn get_public_keys(&self) -> Result<Vec<(String, String)>> {
        if !self.cb.allow_request() {
            return Err(anyhow!(
                "Runtime circuit breaker is OPEN — cannot fetch public keys"
            ));
        }

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            let is_last = attempt + 1 == MAX_ATTEMPTS;
            let mut req = tonic::Request::new(GetPublicKeysRequest {});
            inject_trace_context(req.metadata_mut());

            let mut client = self.client.clone();

            match client.get_public_keys(req).await {
                Ok(response) => {
                    self.cb.record_success();
                    if attempt > 0 {
                        tracing::info!(attempt, "Runtime gRPC get_public_keys succeeded after {attempt} retries");
                    }
                    let keys = response
                        .into_inner()
                        .keys
                        .into_iter()
                        .map(|k| (k.kid, k.pk_b64))
                        .collect();
                    return Ok(keys);
                }
                Err(e) => {
                    let code = e.code();
                    last_err = e.to_string();

                    if !is_retryable(code) {
                        self.cb.reset_failure_count();
                        return Err(anyhow!("Runtime gRPC get_public_keys failed (permanent): {last_err}"));
                    }

                    if !is_last {
                        let delay = retry_delay(attempt);
                        tracing::warn!(
                            attempt, ?code, delay_ms = delay.as_millis(),
                            "Runtime gRPC get_public_keys: transient error, retrying in {delay:?}: {last_err}"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        self.cb.record_failure();
        Err(anyhow!("Runtime gRPC get_public_keys failed after {MAX_ATTEMPTS} attempts: {last_err}"))
    }
}

// ─── Shared Client (public API) ──────────────────────────────────────────────
//
// No mutex — tonic `Channel` is already `Clone + Send + Sync` and multiplexes
// HTTP/2 streams internally. The circuit breaker uses pure atomics.
// `SharedRuntimeClient::clone()` is O(1) (two Arc bumps).

#[derive(Clone)]
pub struct SharedRuntimeClient {
    inner: EiaaRuntimeClient,
}

impl SharedRuntimeClient {
    pub fn new(addr: String) -> Result<Self> {
        let inner = EiaaRuntimeClient::connect(addr)?;
        Ok(Self { inner })
    }

    /// Create a load-balanced client across multiple runtime endpoints.
    ///
    /// Requests are distributed round-robin across all endpoints.
    /// If only one endpoint is provided, behaves identically to `new()`.
    pub fn new_balanced(endpoints: Vec<String>) -> Result<Self> {
        if endpoints.len() <= 1 {
            let addr = endpoints.into_iter().next()
                .ok_or_else(|| anyhow!("At least one runtime gRPC endpoint is required"))?;
            return Self::new(addr);
        }
        let inner = EiaaRuntimeClient::connect_balanced(endpoints)?;
        Ok(Self { inner })
    }

    pub async fn execute_capsule(
        &self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
    ) -> Result<ExecuteResponse> {
        self.inner.execute_inner(capsule, input_json, nonce_b64, None).await
    }

    pub async fn execute_with_evidence(
        &self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
        evidence: AuthEvidence,
    ) -> Result<ExecuteResponse> {
        self.inner.execute_inner(capsule, input_json, nonce_b64, Some(evidence)).await
    }

    pub async fn get_public_keys(&self) -> Result<Vec<(String, String)>> {
        self.inner.get_public_keys().await
    }

    /// Lock-free circuit breaker status check — always returns accurate state
    /// even under high concurrency (no mutex contention).
    pub fn is_circuit_open(&self) -> bool {
        self.inner.cb.is_open()
    }
}
