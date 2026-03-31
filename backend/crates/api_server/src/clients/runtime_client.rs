#![allow(dead_code)]
//! EIAA Runtime gRPC Client with Circuit Breaker + Retry
//!
//! ## GAP-1 FIX: Shared Singleton Client
//!
//! Previously `EiaaRuntimeClient::connect()` was called on **every authorization
//! request**, creating a fresh TCP connection and a fresh circuit breaker with zero
//! state. This meant:
//!   - The circuit breaker never accumulated failures across requests — it could
//!     never trip, so cascading failures were not prevented.
//!   - A new TCP handshake was paid on every auth call (~1–5ms overhead).
//!   - The `runtime_client` field in `AppState` (a raw `CapsuleRuntimeClient<Channel>`)
//!     was never used by the middleware.
//!
//! The fix: `SharedRuntimeClient` wraps `EiaaRuntimeClient` in
//! `Arc<tokio::sync::Mutex<...>>`. One instance is created at startup and stored in
//! `AppState`. The `EiaaAuthzConfig` holds an `Option<SharedRuntimeClient>` and uses
//! it instead of calling `connect()` per-request. The circuit breaker state is now
//! truly shared across all concurrent requests.
//!
//! ## GAP-4 FIX: Distributed Trace Context Propagation
//!
//! The API server initializes OpenTelemetry (OTLP/gRPC) in `telemetry.rs` and sets
//! the W3C TraceContext propagator. However, the `traceparent` header was never
//! injected into outgoing gRPC calls to the runtime service. This meant every
//! capsule execution appeared as a disconnected root span in Jaeger/Tempo — you
//! could not correlate an API server auth span with the runtime execution span.
//!
//! The fix: before each gRPC call, we extract the current OTel span context and
//! inject it as gRPC metadata using `opentelemetry::global::get_text_map_propagator()`.
//! The runtime service then extracts this context and creates a child span, making
//! the full auth flow visible as a single trace:
//!
//! ```text
//! [API server: POST /api/auth/flow/:id/submit]
//!   └─ [eiaa_authz: execute_authorization]
//!        └─ [runtime_client: execute_capsule]  ← traceparent injected here
//!             └─ [runtime_service: execute]    ← child span created here
//! ```
//!
//! ## MEDIUM-8 FIX: Circuit Breaker Pattern
//!
//! The circuit breaker prevents cascading failures when the runtime pod is down.
//! Without it, every auth request would block for the full gRPC timeout (default 30s)
//! before failing, exhausting the thread pool and causing a service-wide outage.
//!
//! ### States
//! - **Closed** (normal): All requests pass through. Failure counter increments on error.
//! - **Open** (tripped): All requests immediately return `ServiceUnavailable` without
//!   attempting the gRPC call. Trips when `failure_threshold` consecutive failures occur.
//! - **HalfOpen** (recovery probe): After `recovery_window_secs`, one probe request is
//!   allowed through. Success → Closed; failure → back to Open.
//!
//! ### Configuration
//! - `failure_threshold`: 5 consecutive failures → Open
//! - `recovery_window_secs`: 30 seconds before attempting recovery probe
//!
//! ## C-3: Retry with Exponential Backoff
//!
//! Transient gRPC errors (network blips, pod restarts) are retried up to
//! `MAX_RETRIES` times with exponential backoff before the circuit breaker
//! failure counter is incremented.
//!
//! ### Retry policy
//! - Max attempts: 3 (1 original + 2 retries)
//! - Base delay: 100ms, doubled each attempt (100ms → 200ms → 400ms)
//! - Jitter: ±25% of the delay to prevent thundering herd
//! - Retryable status codes: Unavailable, DeadlineExceeded, ResourceExhausted,
//!   Unknown, Internal
//! - Non-retryable: InvalidArgument, NotFound, PermissionDenied, Unauthenticated,
//!   AlreadyExists, FailedPrecondition (permanent errors — retry would not help)

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

// ─── GAP-4: Trace Context Propagation ────────────────────────────────────────
//
// We use the `opentelemetry` global propagator (set to W3C TraceContext in
// `telemetry.rs`) to inject the current span context into outgoing gRPC metadata.
//
// `TonicMetadataInjector` implements `opentelemetry::propagation::Injector` for
// `tonic::metadata::MetadataMap`, allowing `propagator.inject_context()` to write
// the `traceparent` (and optionally `tracestate`) key-value pairs directly into
// the gRPC request metadata.
//
// This is a zero-cost abstraction when OTel is disabled (OTEL_SDK_DISABLED=true):
// the propagator is a no-op and inject_context() does nothing.

/// Adapter that implements `opentelemetry::propagation::Injector` for tonic's
/// `MetadataMap`. Allows the W3C TraceContext propagator to write `traceparent`
/// into outgoing gRPC request metadata.
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

/// Inject the current OTel span context into a tonic `MetadataMap`.
///
/// Uses the global W3C TraceContext propagator (set in `telemetry.rs`).
/// If OTel is disabled or no active span exists, this is a no-op.
fn inject_trace_context(metadata: &mut tonic::metadata::MetadataMap) {
    let cx = opentelemetry::Context::current();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut TonicMetadataInjector(metadata));
    });
}

// ─── Retry Configuration ──────────────────────────────────────────────────────

/// Maximum number of attempts (1 original + MAX_RETRIES retries).
const MAX_ATTEMPTS: u32 = 3;

/// Base delay in milliseconds for the first retry.
const RETRY_BASE_MS: u64 = 100;

/// Returns true if the tonic status code is transient and worth retrying.
/// Permanent errors (bad input, auth failures) are not retried.
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

/// Compute the retry delay for attempt `n` (0-indexed) with ±25% jitter.
/// n=0 → ~100ms, n=1 → ~200ms, n=2 → ~400ms
fn retry_delay(attempt: u32) -> Duration {
    use rand::Rng;
    let base = RETRY_BASE_MS * (1u64 << attempt.min(10));
    // ±25% jitter
    let jitter_range = base / 4;
    let jitter = if jitter_range > 0 {
        rand::thread_rng().gen_range(0..=jitter_range * 2).saturating_sub(jitter_range)
    } else {
        0
    };
    Duration::from_millis(base.saturating_add(jitter))
}

/// Circuit breaker state values (stored as u8 for atomic ops)
const CB_CLOSED: u8 = 0;
const CB_OPEN: u8 = 1;
const CB_HALF_OPEN: u8 = 2;

/// Shared circuit breaker state — `Arc` so it survives `EiaaRuntimeClient` clones.
#[derive(Clone)]
struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

struct CircuitBreakerInner {
    /// Current state: CB_CLOSED / CB_OPEN / CB_HALF_OPEN
    state: AtomicU8,
    /// Consecutive failure count (reset to 0 on success)
    failure_count: AtomicU32,
    /// Unix timestamp (seconds) when the circuit was opened
    opened_at: AtomicU64,
    /// Number of consecutive failures before opening
    failure_threshold: u32,
    /// Seconds to wait before attempting a recovery probe
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

    /// Returns `true` if the request should be allowed through.
    /// Transitions Open → HalfOpen when the recovery window has elapsed.
    fn allow_request(&self) -> bool {
        let state = self.inner.state.load(Ordering::Acquire);
        match state {
            CB_CLOSED => true,
            CB_OPEN => {
                let now = now_secs();
                let opened_at = self.inner.opened_at.load(Ordering::Acquire);
                if now.saturating_sub(opened_at) >= self.inner.recovery_window_secs {
                    // Attempt transition to HalfOpen (only one goroutine wins the CAS)
                    if self.inner.state.compare_exchange(
                        CB_OPEN, CB_HALF_OPEN, Ordering::AcqRel, Ordering::Acquire
                    ).is_ok() {
                        tracing::info!("Circuit breaker: OPEN → HALF_OPEN (recovery probe)");
                        true
                    } else {
                        // Another thread already transitioned; re-check state
                        self.inner.state.load(Ordering::Acquire) == CB_HALF_OPEN
                    }
                } else {
                    false
                }
            }
            CB_HALF_OPEN => {
                // Only allow one probe at a time — subsequent requests are rejected
                // until the probe succeeds or fails
                false
            }
            _ => true, // Unknown state — allow (fail open for safety)
        }
    }

    /// Record a successful call. Resets failure count and closes the circuit.
    fn record_success(&self) {
        let prev = self.inner.state.swap(CB_CLOSED, Ordering::AcqRel);
        self.inner.failure_count.store(0, Ordering::Release);
        if prev != CB_CLOSED {
            tracing::info!("Circuit breaker: → CLOSED (runtime recovered)");
        }
    }

    /// Record a failed call. Increments failure count; opens circuit if threshold reached.
    fn record_failure(&self) {
        let count = self.inner.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
        let state = self.inner.state.load(Ordering::Acquire);

        if state == CB_HALF_OPEN {
            // Probe failed — go back to Open
            self.inner.opened_at.store(now_secs(), Ordering::Release);
            self.inner.state.store(CB_OPEN, Ordering::Release);
            tracing::warn!("Circuit breaker: HALF_OPEN → OPEN (probe failed)");
        } else if state == CB_CLOSED && count >= self.inner.failure_threshold {
            self.inner.opened_at.store(now_secs(), Ordering::Release);
            self.inner.state.store(CB_OPEN, Ordering::Release);
            tracing::error!(
                "Circuit breaker: CLOSED → OPEN after {} consecutive failures \
                 (runtime gRPC unavailable; recovery probe in {}s)",
                count, self.inner.recovery_window_secs
            );
        }
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

#[derive(Clone)]
pub struct EiaaRuntimeClient {
    client: CapsuleRuntimeClient<Channel>,
    cb: CircuitBreaker,
}

impl EiaaRuntimeClient {
    pub async fn connect(addr: String) -> Result<Self> {
        // Use connect_lazy so the channel is created without immediately
        // establishing a TCP connection.  The actual handshake happens on
        // the first gRPC call.  This prevents a startup failure when the
        // runtime service is not yet available (or when running in tests
        // without a gRPC server).
        let channel = tonic::transport::Endpoint::from_shared(addr)?
            .connect_lazy();
        let client = CapsuleRuntimeClient::new(channel);
        Ok(Self {
            client,
            // Trip after 5 consecutive failures; probe after 30s
            cb: CircuitBreaker::new(5, 30),
        })
    }

    pub async fn execute_capsule(
        &mut self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
    ) -> Result<ExecuteResponse> {
        if !self.cb.allow_request() {
            return Err(anyhow!(
                "Runtime circuit breaker is OPEN — authorization service temporarily unavailable"
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // C-3: Retry loop with exponential backoff for transient errors.
        // The circuit breaker failure counter is only incremented when ALL
        // attempts are exhausted, preventing a single transient blip from
        // contributing to circuit-open decisions.
        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            // GAP-4 FIX: Wrap in tonic::Request so we can inject the W3C traceparent
            // header into the gRPC metadata. This propagates the current OTel span
            // context to the runtime service, enabling end-to-end trace correlation.
            let mut req = tonic::Request::new(ExecuteRequest {
                capsule: Some(capsule.clone()),
                input_json: input_json.clone(),
                nonce_b64: nonce_b64.clone(),
                now_unix: now,
                expires_at_unix: now + 300, // 5 minutes
                auth_evidence: None,
            });
            inject_trace_context(req.metadata_mut());

            match self.client.execute(req).await {
                Ok(response) => {
                    self.cb.record_success();
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            "Runtime gRPC execute succeeded after {} retries", attempt
                        );
                    }
                    return Ok(response.into_inner());
                }
                Err(e) => {
                    let code = e.code();
                    last_err = e.to_string();

                    if !is_retryable(code) {
                        // Permanent error — don't retry, don't trip circuit breaker
                        tracing::warn!(
                            ?code,
                            "Runtime gRPC execute: non-retryable error: {}", last_err
                        );
                        return Err(anyhow!("Runtime gRPC execute failed (permanent): {last_err}"));
                    }

                    if attempt + 1 < MAX_ATTEMPTS {
                        let delay = retry_delay(attempt);
                        tracing::warn!(
                            attempt,
                            ?code,
                            delay_ms = delay.as_millis(),
                            "Runtime gRPC execute: transient error, retrying in {:?}: {}", delay, last_err
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All attempts exhausted — record circuit breaker failure
        self.cb.record_failure();
        Err(anyhow!(
            "Runtime gRPC execute failed after {MAX_ATTEMPTS} attempts: {last_err}"
        ))
    }

    /// Execute capsule with authentication evidence from an IdP assertion.
    /// Used for SSO login flows where the capsule needs IdP context to make decisions.
    pub async fn execute_with_evidence(
        &mut self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
        evidence: AuthEvidence,
    ) -> Result<ExecuteResponse> {
        if !self.cb.allow_request() {
            return Err(anyhow!(
                "Runtime circuit breaker is OPEN — authorization service temporarily unavailable"
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // C-3: Retry loop with exponential backoff for transient errors.
        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            // GAP-4 FIX: Inject traceparent into gRPC metadata for trace correlation.
            let mut req = tonic::Request::new(ExecuteRequest {
                capsule: Some(capsule.clone()),
                input_json: input_json.clone(),
                nonce_b64: nonce_b64.clone(),
                now_unix: now,
                expires_at_unix: now + 300,
                auth_evidence: Some(evidence.clone()),
            });
            inject_trace_context(req.metadata_mut());

            match self.client.execute(req).await {
                Ok(response) => {
                    self.cb.record_success();
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            "Runtime gRPC execute_with_evidence succeeded after {} retries", attempt
                        );
                    }
                    return Ok(response.into_inner());
                }
                Err(e) => {
                    let code = e.code();
                    last_err = e.to_string();

                    if !is_retryable(code) {
                        tracing::warn!(
                            ?code,
                            "Runtime gRPC execute_with_evidence: non-retryable error: {}", last_err
                        );
                        return Err(anyhow!(
                            "Runtime gRPC execute_with_evidence failed (permanent): {last_err}"
                        ));
                    }

                    if attempt + 1 < MAX_ATTEMPTS {
                        let delay = retry_delay(attempt);
                        tracing::warn!(
                            attempt,
                            ?code,
                            delay_ms = delay.as_millis(),
                            "Runtime gRPC execute_with_evidence: transient error, retrying in {:?}: {}", delay, last_err
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        self.cb.record_failure();
        Err(anyhow!(
            "Runtime gRPC execute_with_evidence failed after {MAX_ATTEMPTS} attempts: {last_err}"
        ))
    }

    /// Fetch public keys from the runtime for attestation verification.
    /// Returns a list of (kid, pk_b64) tuples.
    pub async fn get_public_keys(&mut self) -> Result<Vec<(String, String)>> {
        if !self.cb.allow_request() {
            return Err(anyhow!(
                "Runtime circuit breaker is OPEN — cannot fetch public keys"
            ));
        }

        // C-3: Retry loop for transient errors.
        // get_public_keys is idempotent so retrying is always safe.
        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            // GAP-4 FIX: Inject traceparent into gRPC metadata for trace correlation.
            let mut req = tonic::Request::new(GetPublicKeysRequest {});
            inject_trace_context(req.metadata_mut());

            match self.client.get_public_keys(req).await {
                Ok(response) => {
                    self.cb.record_success();
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            "Runtime gRPC get_public_keys succeeded after {} retries", attempt
                        );
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
                        return Err(anyhow!(
                            "Runtime gRPC get_public_keys failed (permanent): {last_err}"
                        ));
                    }

                    if attempt + 1 < MAX_ATTEMPTS {
                        let delay = retry_delay(attempt);
                        tracing::warn!(
                            attempt,
                            ?code,
                            delay_ms = delay.as_millis(),
                            "Runtime gRPC get_public_keys: transient error, retrying in {:?}: {}", delay, last_err
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        self.cb.record_failure();
        Err(anyhow!(
            "Runtime gRPC get_public_keys failed after {MAX_ATTEMPTS} attempts: {last_err}"
        ))
    }

    /// Returns true if the circuit breaker is currently open (runtime is down).
    /// Useful for health check endpoints to report degraded state.
    pub fn is_circuit_open(&self) -> bool {
        self.cb.is_open()
    }
}

// ─── Shared Singleton Client ──────────────────────────────────────────────────
//
// GAP-1 FIX: `SharedRuntimeClient` is the type stored in `AppState` and passed
// into `EiaaAuthzConfig`. It wraps `EiaaRuntimeClient` in an `Arc<Mutex<...>>`
// so that:
//   1. A single TCP connection (with HTTP/2 multiplexing) is reused across all
//      concurrent requests — no per-request TCP handshake overhead.
//   2. The circuit breaker state accumulates failures across ALL requests, not
//      just within a single request's lifetime. This means the breaker can
//      actually trip after 5 consecutive failures and protect the service.
//   3. The `Clone` impl is cheap (Arc clone) — safe to store in AppState and
//      pass into every EiaaAuthzConfig without copying the underlying connection.
//
// ### Concurrency model
// `tokio::sync::Mutex` is used (not `std::sync::Mutex`) because the lock is
// held across `.await` points inside `execute_capsule` / `get_public_keys`.
// The lock is held only for the duration of a single gRPC call (~1–10ms), so
// contention is low even under high concurrency.
//
// ### Fallback
// If `SharedRuntimeClient` is not present in `EiaaAuthzConfig` (e.g. in tests
// that don't wire up a real runtime), the middleware falls back to the legacy
// `EiaaRuntimeClient::connect()` per-request path. This preserves backward
// compatibility for unit tests.

/// A cheaply-cloneable, shared handle to the EIAA runtime gRPC client.
///
/// Created once at startup via `SharedRuntimeClient::new()` and stored in
/// `AppState`. Pass a clone into each `EiaaAuthzConfig` via the
/// `runtime_client` field.
#[derive(Clone)]
pub struct SharedRuntimeClient {
    inner: std::sync::Arc<tokio::sync::Mutex<EiaaRuntimeClient>>,
}

impl SharedRuntimeClient {
    /// Connect to the runtime and wrap in a shared handle.
    ///
    /// Uses `connect_lazy` semantics internally (the underlying tonic `Channel`
    /// is already lazy), so this returns immediately without blocking on the
    /// network. The first actual gRPC call will establish the connection.
    pub async fn new(addr: String) -> Result<Self> {
        let client = EiaaRuntimeClient::connect(addr).await?;
        Ok(Self {
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(client)),
        })
    }

    /// Execute a capsule, using the shared circuit-breaker-protected client.
    pub async fn execute_capsule(
        &self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
    ) -> Result<ExecuteResponse> {
        let mut guard = self.inner.lock().await;
        guard.execute_capsule(capsule, input_json, nonce_b64).await
    }

    /// Execute a capsule with authentication evidence.
    pub async fn execute_with_evidence(
        &self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
        evidence: AuthEvidence,
    ) -> Result<ExecuteResponse> {
        let mut guard = self.inner.lock().await;
        guard.execute_with_evidence(capsule, input_json, nonce_b64, evidence).await
    }

    /// Fetch public keys from the runtime.
    pub async fn get_public_keys(&self) -> Result<Vec<(String, String)>> {
        let mut guard = self.inner.lock().await;
        guard.get_public_keys().await
    }

    /// Returns true if the circuit breaker is currently open.
    pub fn is_circuit_open(&self) -> bool {
        // Try to get a non-blocking read on the state.
        // We use try_lock here — if the lock is held by an in-flight request,
        // we conservatively return false (not open) to avoid blocking the
        // health check path.
        match self.inner.try_lock() {
            Ok(guard) => guard.is_circuit_open(),
            Err(_) => false,
        }
    }
}
