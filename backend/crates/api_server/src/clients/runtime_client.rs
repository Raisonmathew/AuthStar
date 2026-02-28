//! EIAA Runtime gRPC Client with Circuit Breaker + Retry
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
        let client = CapsuleRuntimeClient::connect(addr).await?;
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
            let req = ExecuteRequest {
                capsule: Some(capsule.clone()),
                input_json: input_json.clone(),
                nonce_b64: nonce_b64.clone(),
                now_unix: now,
                expires_at_unix: now + 300, // 5 minutes
                auth_evidence: None,
            };

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
                        return Err(anyhow!("Runtime gRPC execute failed (permanent): {}", last_err));
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
            "Runtime gRPC execute failed after {} attempts: {}", MAX_ATTEMPTS, last_err
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
            let req = ExecuteRequest {
                capsule: Some(capsule.clone()),
                input_json: input_json.clone(),
                nonce_b64: nonce_b64.clone(),
                now_unix: now,
                expires_at_unix: now + 300,
                auth_evidence: Some(evidence.clone()),
            };

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
                            "Runtime gRPC execute_with_evidence failed (permanent): {}", last_err
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
            "Runtime gRPC execute_with_evidence failed after {} attempts: {}", MAX_ATTEMPTS, last_err
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
            match self.client.get_public_keys(GetPublicKeysRequest {}).await {
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
                            "Runtime gRPC get_public_keys failed (permanent): {}", last_err
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
            "Runtime gRPC get_public_keys failed after {} attempts: {}", MAX_ATTEMPTS, last_err
        ))
    }

    /// Returns true if the circuit breaker is currently open (runtime is down).
    /// Useful for health check endpoints to report degraded state.
    pub fn is_circuit_open(&self) -> bool {
        self.cb.is_open()
    }
}
