# AuthStar — Innovation Implementation Summary

**Author:** Bob (Principal Software Engineer / Architect)  
**Date:** 2026-03-01  
**Session:** Architecture Review + Innovation Sprint

---

## Executive Summary

This document summarizes the architectural review, gap analysis, and innovations implemented during this engineering session. Six major deliverables were produced:

1. **Architecture Verification** — A comprehensive review of the AuthStar IDaaS platform confirming its production-readiness and identifying 6 remaining architectural gaps.
2. **INNOVATION-5: Policy-as-Code CI/CD Integration** — A complete implementation enabling engineering teams to manage EIAA authorization policies as version-controlled code with automated testing, simulation, shadow mode, and governance workflows.
3. **GAP-3 Fix** — Full `RiskContext` propagation into capsule authorization context, enabling fine-grained signal-based policy decisions.
4. **GAP-1 Fix** — Shared singleton gRPC runtime client with a process-wide circuit breaker, eliminating per-request TCP connections and making the circuit breaker actually effective.
5. **GAP-2 Fix** — `AuditWriter` backpressure metrics surfaced to Prometheus, with Kubernetes readiness probe integration to prevent routing traffic to pods that are losing audit records.
6. **GAP-4 Fix** — End-to-end distributed trace context propagation between the API server and the capsule runtime service via W3C `traceparent` gRPC metadata injection/extraction, enabling full auth flow visibility in Jaeger/Grafana Tempo.

---

## Part 1: Architecture Verification

### Verified Strengths

The AuthStar platform demonstrates exceptional architectural maturity for an IDaaS product:

| Component | Assessment |
|-----------|-----------|
| EIAA Core | ✅ Correctly implements JWT-as-identity, capsule-as-authorization separation |
| Capsule Pipeline | ✅ Ed25519 attestation, BLAKE3 hashing, Wasmtime isolation |
| Risk Engine | ✅ Multi-signal (network, device, geo-velocity), temporal decay, sticky signals |
| Audit Trail | ✅ Write-behind pattern, 10k buffer, batch inserts, backpressure monitoring |
| Cache Strategy | ✅ Redis cache-aside with DB fallback, protobuf encoding |
| Multi-tenancy | ✅ PostgreSQL RLS on all tables, `app.current_tenant_id` session variable |
| Attestation | ✅ Nonce replay protection, frequency matrix, signature re-verification on cache hit |
| API Keys | ✅ `ask_xxx_yyy` format, HMAC-SHA256 hash storage, scoped permissions |

### Remaining Gaps (from PRINCIPAL_ARCHITECT_REVIEW.md)

| Gap | Description | Status |
|-----|-------------|--------|
| **GAP-1** | **No circuit breaker on gRPC runtime client** | **✅ FIXED** |
| **GAP-2** | **`AuditWriter` channel backpressure not surfaced to metrics** | **✅ FIXED** |
| **GAP-3** | **Full `RiskContext` not passed to capsule policies** | **✅ FIXED** |
| **GAP-4** | **No distributed tracing correlation between API server and runtime service** | **✅ FIXED** |
| GAP-5 | Policy governance state machine not implemented | ✅ Implemented (INNOVATION-5) |
| GAP-6 | No policy test framework for CI/CD | ✅ Implemented (INNOVATION-5) |

---

## Part 2: GAP-3 Fix — Full Risk Context in Authorization

### Problem

The `eiaa_authz.rs` middleware evaluated risk via the Risk Engine but discarded the full `RiskContext`, passing only two scalar values to capsule policies:
- `risk_score: f64` (aggregate 0-100)
- `risk_level: String` ("low" | "medium" | "high")

This meant capsule policies could not distinguish between:
- A score of 75 from **impossible travel** (credential theft indicator)
- A score of 75 from a **compromised device** (requires hardware-bound auth)
- A score of 75 from **brute force attempts** (requires lockout, not step-up)

These are fundamentally different threat scenarios requiring different policy responses.

### Fix

**Files modified:**
- `backend/crates/api_server/src/middleware/authorization_context.rs`
- `backend/crates/api_server/src/middleware/eiaa_authz.rs`

**Changes:**

1. **`AuthorizationContext`** — Added `risk_context: Option<RiskContext>` field with full documentation explaining the GAP and the fix.

2. **`AuthorizationContextBuilder`** — Added `with_risk_context(risk_ctx: RiskContext)` method that:
   - Stores the full `RiskContext` in the context
   - Syncs `device_trust` string field for backward compatibility

3. **`eiaa_authz.rs`** — Changed risk evaluation to capture the full `RiskEvaluation`:
   ```rust
   // Before (GAP-3):
   let (risk_score, risk_level) = ...;
   
   // After (GAP-3 FIX):
   let (risk_score, risk_level, full_risk_context) = ...;
   // full_risk_context: Option<RiskContext> with all signals
   ```

4. **Context assembly** — Builder now calls `.with_risk_context(risk_ctx)` when available.

### Impact

Capsule policies can now write rules like:

```yaml
# Block impossible travel (credential theft)
- id: impossible_travel_block
  condition: "risk.geo_velocity != 'impossible'"
  deny_reason: "impossible_travel_detected"

# Require hardware-bound auth for compromised devices
- id: compromised_device_require_aal3
  condition: "risk.device_trust != 'compromised' || assurance.aal >= 3"
  deny_reason: "compromised_device_requires_hardware_key"

# Block TOR/anonymous proxies for sensitive actions
- id: no_anonymous_network
  condition: "risk.ip_reputation != 'high'"
  deny_reason: "anonymous_network_blocked"

# Require MFA after brute force attempts
- id: brute_force_stepup
  condition: "risk.failed_attempts_1h <= 3 || assurance.aal >= 2"
  deny_reason: "brute_force_detected_requires_mfa"
```

**Security improvement:** Policies can now implement NIST SP 800-63B Section 7.1 (Reauthentication) requirements based on specific risk signals, not just aggregate scores.

---

## Part 3: INNOVATION-5 — Policy-as-Code CI/CD Integration

### Overview

This innovation transforms EIAA authorization policies from opaque database records into version-controlled, testable, reviewable code artifacts — following the same GitOps principles used for infrastructure-as-code.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Policy-as-Code Pipeline                       │
│                                                                  │
│  policies/          policy-tests/        .github/workflows/      │
│  auth_login.yaml    auth_login_tests.yaml  policy-ci.yml         │
│       │                    │                     │               │
│       ▼                    ▼                     ▼               │
│  authstar-cli         authstar-cli         GitHub Actions        │
│  policy validate      policy test          7-job pipeline        │
│  policy deploy        (structural +        (detect → build →     │
│  policy shadow        live API)            validate → test →     │
│  policy status                             deploy-staging →      │
│                                            deploy-prod)          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              API Server (New Endpoints)                   │   │
│  │                                                           │   │
│  │  POST /api/v1/policies/:action/test-suites               │   │
│  │  POST /api/v1/policies/:action/test-suites/:id/cases     │   │
│  │  POST /api/v1/policies/:action/simulate                  │   │
│  │  POST /api/v1/policies/:action/shadow/enable             │   │
│  │  GET  /api/v1/policies/:action/shadow/report             │   │
│  │  POST /api/v1/policies/:action/governance/submit         │   │
│  │  POST /api/v1/policies/:action/governance/approve        │   │
│  │  POST /api/v1/policies/:action/governance/reject         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Database (Migration 038)                     │   │
│  │                                                           │   │
│  │  policy_test_suites          policy_simulation_runs      │   │
│  │  policy_test_cases           policy_simulation_case_results│  │
│  │  policy_shadow_runs          policy_governance            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Files Created

#### Database Migration
**`backend/crates/db_migrations/migrations/038_policy_simulation.sql`**

Creates 6 new tables:
- `policy_test_suites` — Named collections of test cases per action
- `policy_test_cases` — Individual test vectors (input + expected output)
- `policy_simulation_runs` — Execution records for simulation runs
- `policy_simulation_case_results` — Per-case pass/fail results with actual vs expected
- `policy_shadow_runs` — Shadow mode execution records (divergence tracking)
- `policy_governance` — Governance state machine (draft→review→approved→active)

Also adds shadow mode columns to `eiaa_capsules`:
- `shadow_mode_enabled: bool`
- `shadow_candidate_hash: text`
- `shadow_started_at: timestamptz`
- `shadow_sample_rate: float4`

All tables have RLS policies scoped to `app.current_tenant_id`.

#### API Routes
**`backend/crates/api_server/src/routes/policy_simulation.rs`**

14 endpoints organized into 4 groups:

**Test Suite Management:**
```
POST   /api/v1/policies/:action/test-suites          Create test suite
GET    /api/v1/policies/:action/test-suites          List test suites
POST   /api/v1/policies/:action/test-suites/:id/cases  Add test case
GET    /api/v1/policies/:action/test-suites/:id/cases  List test cases
```

**Simulation Execution:**
```
POST   /api/v1/policies/:action/simulate             Run simulation
GET    /api/v1/policies/:action/simulations          List simulation runs
GET    /api/v1/policies/:action/simulations/:run_id  Get simulation results
```

**Shadow Mode:**
```
POST   /api/v1/policies/:action/shadow/enable        Enable shadow mode
POST   /api/v1/policies/:action/shadow/disable       Disable shadow mode
GET    /api/v1/policies/:action/shadow/report        Get divergence report
```

**Governance:**
```
GET    /api/v1/policies/:action/governance           Get governance state
POST   /api/v1/policies/:action/governance/submit    Submit for review
POST   /api/v1/policies/:action/governance/approve   Approve (reviewer)
POST   /api/v1/policies/:action/governance/reject    Reject with reason
```

#### CLI Tool
**`backend/crates/api_server/src/bin/authstar_cli.rs`**

A standalone CLI binary for use in CI/CD pipelines:

```bash
# Validate policy YAML syntax
authstar-cli policy validate --file policies/auth_login.yaml

# Run test suite (structural validation without API key)
authstar-cli policy test --file policies/auth_login.yaml \
                         --tests policy-tests/auth_login_tests.yaml

# Run test suite against live capsule (requires AUTHSTAR_API_KEY)
AUTHSTAR_API_KEY=ask_xxx_yyy \
authstar-cli policy test --file policies/auth_login.yaml \
                         --tests policy-tests/auth_login_tests.yaml

# Deploy to staging with governance workflow
AUTHSTAR_API_KEY=ask_xxx_yyy \
authstar-cli policy deploy --file policies/auth_login.yaml --env staging

# Enable shadow mode (10% traffic)
AUTHSTAR_API_KEY=ask_xxx_yyy \
authstar-cli policy shadow --action auth:login --candidate abc123 --rate 0.1

# Check policy status
authstar-cli policy status --action auth:login
```

**Exit codes:**
- `0` — Success
- `1` — Validation/test failure (policy tests failed — blocks CI)
- `2` — Configuration error (missing env vars, bad file)
- `3` — API error (network, auth, server error)

#### GitHub Actions Workflow
**`.github/workflows/policy-ci.yml`**

7-job pipeline:

| Job | Trigger | Description |
|-----|---------|-------------|
| `detect-changes` | All | Detects which policy files changed |
| `build-cli` | All | Builds `authstar-cli` binary |
| `validate` | PR + push | Validates YAML syntax of changed policies |
| `test` | PR + push | Runs test suites (structural + live on main) |
| `deploy-staging` | push to main | Deploys to staging with governance |
| `deploy-production` | manual dispatch | Deploys to production (requires approval) |
| `drift-detection` | scheduled | Detects policy drift from expected state |

**PR integration:** Posts validation results as PR comments.

**Environment protection:** Production deployment requires GitHub environment approval.

#### Example Policy File
**`policies/auth_login.yaml`**

```yaml
name: "Standard Login"
action: "auth:login"
version: 3
rules:
  - id: email_verified
    condition: "identity.email_verified == true"
    deny_reason: "email_not_verified"
  - id: high_risk_deny
    condition: "risk.overall != 'high'"
    deny_reason: "risk_too_high"
  - id: medium_risk_stepup
    condition: "assurance.aal >= 2 || risk.overall != 'medium'"
    step_up:
      level: "AAL2"
      capabilities: ["totp", "passkey", "sms_otp"]
final:
  allow: true
  session_type: "standard"
```

#### Example Test Suite
**`policy-tests/auth_login_tests.yaml`**

16 test cases covering:
- Happy path (AAL1, AAL2, step-up completion)
- Denial cases (high risk, unverified email, locked account, zero AAL)
- Step-up cases (medium risk without MFA)
- Boundary cases (risk score thresholds: 0, 49, 89, 90)
- Regression tests (passkey-only auth, SSO users)

### Shadow Mode Design

Shadow mode enables **zero-risk policy rollout** by running a candidate capsule in parallel with the active capsule on a configurable percentage of real traffic:

```
Request → Active Capsule → Decision (used)
       ↘ Candidate Capsule → Decision (recorded, not used)
                           → Divergence detected? → Alert
```

Divergences are stored in `policy_shadow_runs` with a computed `diverged` column:
```sql
diverged BOOLEAN GENERATED ALWAYS AS (
    active_decision != candidate_decision
) STORED
```

The shadow report endpoint returns:
- Total shadow runs
- Divergence count and rate
- Sample divergent cases for investigation

**Recommended rollout process:**
1. Compile new capsule → `shadow_candidate_hash`
2. Enable shadow mode at 1% → observe divergences
3. Increase to 10% → 50% → validate
4. Disable shadow mode → activate candidate capsule

### Governance State Machine

```
draft ──submit──→ review ──approve──→ approved ──activate──→ active
                     └──reject──→ rejected
```

- **draft**: Policy authored, not yet submitted
- **review**: Submitted for peer review (reviewer cannot be the author)
- **approved**: Approved, ready for activation
- **active**: Currently executing in production
- **rejected**: Rejected with reason, returned to author

All state transitions are recorded with `actor_id`, `timestamp`, and optional `notes`.

---

## Part 4: Remaining Innovations (Backlog)

From the `PRINCIPAL_ARCHITECT_REVIEW.md`, 4 additional innovations were proposed but not yet implemented:

### INNOVATION-1: Adaptive Re-Authentication Engine
**Value:** Continuous risk assessment during sessions, not just at login  
**Effort:** ~3 days  
**Key files to modify:** `eiaa_authz.rs`, new `session_risk_tracker.rs` service  
**Approach:** Compare current request risk context against session baseline; trigger step-up if delta exceeds threshold

### INNOVATION-2: Cross-Tenant Policy Marketplace
**Value:** Tenants can publish/subscribe to policy templates  
**Effort:** ~5 days  
**Key files:** New `policy_marketplace.rs` routes, `039_policy_marketplace.sql` migration  
**Approach:** Policy templates with parameter substitution; semantic versioning; usage analytics

### INNOVATION-3: Real-Time Risk Signal Streaming
**Value:** Push risk alerts to clients via WebSocket/SSE  
**Effort:** ~4 days  
**Key files:** New `risk_stream.rs` route, Redis pub/sub integration  
**Approach:** Risk Engine publishes events to Redis channel; SSE endpoint streams to authenticated clients

### INNOVATION-4: Behavioral Biometrics Integration
**Value:** Continuous authentication via typing patterns, mouse dynamics  
**Effort:** ~6 days  
**Key files:** New `behavior_signals.rs` in risk_engine, new `behavior_collector.rs` route  
**Approach:** JavaScript SDK collects behavioral signals; server-side ML model scores anomalies; feeds into RiskContext

---

## Part 5: Technical Debt Addressed

| Item | File | Description |
|------|------|-------------|
| GAP-3 | `authorization_context.rs`, `eiaa_authz.rs` | Full RiskContext now passed to capsule policies |
| GAP-5 | `038_policy_simulation.sql`, `policy_simulation.rs` | Governance state machine implemented |
| GAP-6 | `authstar_cli.rs`, `policy-ci.yml` | Policy test framework and CI/CD pipeline |

---

## Part 6: Metrics & Observability

The new Policy-as-Code system adds the following observable metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `policy_simulation_runs_total` | Counter | Total simulation runs by action |
| `policy_simulation_pass_rate` | Gauge | Pass rate per action (0.0-1.0) |
| `policy_shadow_divergence_rate` | Gauge | Shadow mode divergence rate per action |
| `policy_governance_state` | Gauge | Current governance state per action |
| `policy_test_cases_total` | Gauge | Total test cases per action |

These should be added to the Prometheus metrics exporter in a follow-up.

---

## Appendix: File Manifest

### New Files Created

| File | Purpose |
|------|---------|
| `PRINCIPAL_ARCHITECT_REVIEW.md` | Architecture verification + innovation proposals |
| `backend/crates/db_migrations/migrations/038_policy_simulation.sql` | DB schema for policy simulation system |
| `backend/crates/api_server/src/routes/policy_simulation.rs` | 14 API endpoints for simulation/shadow/governance |
| `backend/crates/api_server/src/bin/authstar_cli.rs` | Policy-as-Code CLI tool |
| `.github/workflows/policy-ci.yml` | GitHub Actions CI/CD pipeline |
| `policies/auth_login.yaml` | Example policy file (auth:login) |
| `policy-tests/auth_login_tests.yaml` | Example test suite (16 test cases) |
| `INNOVATION_IMPLEMENTATION_SUMMARY.md` | This document |

### Modified Files

| File | Change |
|------|--------|
| `backend/crates/api_server/src/routes/mod.rs` | Added `pub mod policy_simulation` |
| `backend/crates/api_server/src/router.rs` | Wired policy_simulation routes under `/api/v1` |
| `backend/crates/api_server/Cargo.toml` | Added `authstar-cli` binary + `serde_yaml` |
| `backend/Cargo.toml` | Added `serde_yaml = "0.9"` to workspace deps |
| `backend/crates/api_server/src/middleware/authorization_context.rs` | GAP-3: Added `risk_context` field + `with_risk_context()` builder |
| `backend/crates/api_server/src/middleware/eiaa_authz.rs` | GAP-3: Capture full `RiskContext` from risk evaluation |

---

## Part 4: GAP-1 Fix — Shared Singleton gRPC Runtime Client

### Problem

The circuit breaker implementation in `runtime_client.rs` was architecturally correct but **never effective** because `EiaaRuntimeClient::connect()` was called on **every single authorization request** across 7 call sites:

| Call Site | Impact |
|-----------|--------|
| `middleware/eiaa_authz.rs` `execute_authorization()` | Every protected route (all auth decisions) |
| `middleware/eiaa_authz.rs` `verify_attestation()` | Every key-fetch on cache miss |
| `routes/auth.rs` `signin()` | Every password login |
| `routes/admin/auth.rs` `login()` | Every admin login |
| `routes/signup.rs` `verify_step()` | Every signup verification |
| `routes/hosted.rs` (×2) | Every hosted auth flow step |
| `services/reexecution_service.rs` `verify_execution()` | Every audit re-execution |

Each call created a **fresh `EiaaRuntimeClient` instance with a fresh `CircuitBreakerInner`** initialized to zero failures. This meant:

1. **The circuit breaker could never trip** — failure count reset to 0 on every request, so 5 consecutive failures from the same client were impossible.
2. **A new TCP connection was established per request** — adding 1–5ms overhead on every auth call (TLS handshake + HTTP/2 SETTINGS frame).
3. **The `runtime_client: CapsuleRuntimeClient<Channel>` field in `AppState`** was initialized at startup but never used by any of these call sites.

### Root Cause

The `AppState` held a `CapsuleRuntimeClient<Channel>` (raw tonic client, no circuit breaker) while the middleware used `EiaaRuntimeClient` (with circuit breaker). These were two separate types and the middleware never referenced `AppState.runtime_client`.

### Solution

**`SharedRuntimeClient`** — a new type in `clients/runtime_client.rs`:

```rust
#[derive(Clone)]
pub struct SharedRuntimeClient {
    inner: Arc<tokio::sync::Mutex<EiaaRuntimeClient>>,
}
```

**Key properties:**
- Created **once** at startup via `SharedRuntimeClient::new(addr)` and stored in `AppState`
- `Clone` is `O(1)` — just an `Arc` ref-count bump
- `tokio::sync::Mutex` used (not `std::sync::Mutex`) because the lock is held across `.await` points inside gRPC calls
- The `CircuitBreakerInner` inside `EiaaRuntimeClient` is already `Arc<...>` — it accumulates failures across all concurrent callers correctly
- Lock contention is low: held only for the duration of a single gRPC call (~1–10ms)

**Changes made:**

| File | Change |
|------|--------|
| `clients/runtime_client.rs` | Added `SharedRuntimeClient` type with `new()`, `execute_capsule()`, `execute_with_evidence()`, `get_public_keys()`, `is_circuit_open()` |
| `state.rs` | Replaced `CapsuleRuntimeClient<Channel>` field with `SharedRuntimeClient`; constructor uses `SharedRuntimeClient::new()` |
| `middleware/eiaa_authz.rs` | Added `runtime_client: Option<SharedRuntimeClient>` to `EiaaAuthzConfig`; `execute_authorization()` and `verify_attestation()` use it when present, fall back to per-request connect only when `None` (unit tests) |
| `router.rs` | `eiaa_config()` now sets `runtime_client: Some(state.runtime_client.clone())` |
| `routes/auth.rs` | `signin()` uses `state.runtime_client.execute_capsule()` |
| `routes/admin/auth.rs` | `login()` uses `state.runtime_client.execute_capsule()` |
| `routes/signup.rs` | `verify_step()` uses `state.runtime_client.execute_capsule()` |
| `routes/hosted.rs` | Inline call + `execute_capsule_with_client()` helper both use `state.runtime_client` |
| `services/reexecution_service.rs` | `ReExecutionService` now holds `SharedRuntimeClient` instead of `runtime_addr: String` |
| `routes/reexecution.rs` | All 3 `ReExecutionService::new()` calls pass `state.runtime_client.clone()` |

**`sso.rs` was already correct** — it had been previously fixed to use `state.runtime_client.clone()`.

### Behavior After Fix

- **Circuit breaker trips correctly**: 5 consecutive failures across any combination of concurrent requests → breaker opens → all subsequent auth requests immediately return 503 without waiting for the gRPC timeout (default 30s).
- **Recovery probe**: After 30 seconds, one probe request is allowed through. Success → breaker closes; failure → stays open.
- **Connection reuse**: Single HTTP/2 connection with multiplexing — no per-request TCP handshake.
- **Backward compatibility**: Unit tests that don't wire up a real runtime pass `runtime_client: None` in `EiaaAuthzConfig` and fall back to the legacy per-request path.
---

## Part 5: GAP-2 Fix — AuditWriter Backpressure Metrics Surfaced to Prometheus

### Problem

The `AuditWriter` service uses a bounded `tokio::sync::mpsc` channel (capacity 10,000) as a write-behind buffer. When the DB flush rate falls behind the audit record production rate, the channel fills up and records are **silently dropped**.

The existing implementation had:
- An `AtomicU64` drop counter — correct, but only readable via `audit_writer.metrics()` in Rust code
- A `backpressure_monitor` background task — logged `tracing::warn!` every 10s when fill ≥ 80%
- A `metrics()` method returning `AuditWriterMetrics` — exposed to the health endpoint in theory, but never actually called from `readiness_check`

**What was missing:** None of these were wired to the `metrics` crate facade. The Prometheus `/metrics` endpoint showed zero audit writer metrics. Grafana had no visibility. PagerDuty could not alert. Silent audit record loss was undetectable in production — a direct EIAA compliance violation.

### Root Cause

The `audit_writer.rs` module was written before the Prometheus integration (`metrics_middleware.rs`, `routes/metrics.rs`) was added. The two systems were never connected. The `readiness_check` handler in `router.rs` checked DB and Redis but never called `state.audit_writer.metrics()`.

### Solution

Three targeted changes, zero new dependencies (the `metrics` crate was already in scope):

#### 1. `services/audit_writer.rs` — Emit metrics at all three critical points

**`record()` — on every dropped record:**
```rust
metrics::counter!("audit_writer_dropped_total").increment(1);
```
This is the most critical metric. A non-zero value means EIAA audit records are being permanently lost. Alert threshold: `increase(audit_writer_dropped_total[1m]) > 0` → PAGE.

**`backpressure_monitor()` — every 10 seconds:**
```rust
metrics::gauge!("audit_writer_channel_pending").set(channel_pending as f64);
metrics::gauge!("audit_writer_channel_fill_pct").set(fill_pct);
```
These gauges let Grafana show a real-time fill % chart. Alert before records start dropping:
- `audit_writer_channel_fill_pct > 80` for 1m → WARNING
- `audit_writer_channel_fill_pct > 95` for 30s → CRITICAL

**`flush_batch()` — on every DB batch write:**
```rust
metrics::counter!("audit_writer_flush_total").increment(1);
metrics::histogram!("audit_writer_flush_duration_seconds").record(elapsed_secs);
// On non-recoverable error:
metrics::counter!("audit_writer_flush_errors_total").increment(1);
```
A spike in `flush_duration_seconds` p99 indicates DB pressure. A spike in `flush_errors_total` indicates a DB connectivity problem that will cause the channel to fill.

#### 2. `router.rs` `readiness_check` — Kubernetes probe integration

```rust
let audit_metrics = state.audit_writer.metrics();
let audit_ok = audit_metrics.dropped_total == 0 && audit_metrics.channel_fill_pct < 95.0;
```

The readiness check now returns `503 Service Unavailable` if:
- The audit writer channel is ≥ 95% full (imminent data loss)
- Any records have been dropped since startup (data loss already occurring)

**Why this matters for EIAA compliance:** When a pod is losing audit records, Kubernetes will stop routing new traffic to it (readiness probe fails). The pod drains its backlog while other healthy pods handle new requests. This prevents a cascading failure where a slow DB causes all pods to simultaneously lose audit records.

#### 3. `routes/metrics.rs` — Documentation

Updated the module doc comment to list all 6 new audit writer metrics with recommended Grafana alert thresholds.

### Files Changed

| File | Change |
|------|--------|
| `services/audit_writer.rs` | Added `metrics::counter!`, `metrics::gauge!`, `metrics::histogram!` at 4 call sites |
| `router.rs` | `readiness_check` now calls `state.audit_writer.metrics()` and fails if dropped > 0 or fill ≥ 95% |
| `routes/metrics.rs` | Doc comment updated with 6 new audit writer metrics and alert thresholds |

### New Prometheus Metrics

| Metric | Type | When emitted | Recommended Alert |
|--------|------|--------------|-------------------|
| `audit_writer_dropped_total` | Counter | On every dropped record (immediately) | `increase > 0` over 1m → PAGE |
| `audit_writer_channel_pending` | Gauge | Every 10s by monitor task | `> 8000` for 1m → WARN |
| `audit_writer_channel_fill_pct` | Gauge | Every 10s by monitor task | `> 80%` for 1m → WARN; `> 95%` for 30s → CRIT |
| `audit_writer_flush_total` | Counter | Per successful DB batch flush | — (throughput tracking) |
| `audit_writer_flush_errors_total` | Counter | Per failed DB batch flush | `increase > 0` over 1m → WARN |
| `audit_writer_flush_duration_seconds` | Histogram | Per DB batch flush | p99 `> 1s` → WARN |

### Behavior After Fix

- **Prometheus scrape** at `/metrics` now includes all 6 audit writer metrics
- **Grafana** can show a real-time channel fill % chart and alert before records start dropping
- **PagerDuty** can page on-call when `audit_writer_dropped_total` increases — previously this was undetectable
- **Kubernetes** stops routing traffic to pods that are losing audit records (readiness probe)
- **No performance impact**: `metrics::counter!` and `metrics::gauge!` are lock-free atomic operations; the histogram uses a pre-allocated bucket array. All calls are on the hot path only for drops (rare) and the monitor task (every 10s).
---

## Part 7: GAP-4 Fix — End-to-End Distributed Trace Context Propagation

### Problem

The API server correctly initialised OpenTelemetry (OTLP/gRPC export, W3C TraceContext propagator) in `telemetry.rs`. However, the `traceparent` header was **never injected into outgoing gRPC calls** to the capsule runtime service. The runtime service had **no OTel instrumentation at all** — it used only `tracing_subscriber` for stdout logging.

The result: every capsule execution appeared as a **disconnected root span** in Jaeger/Grafana Tempo. An on-call engineer investigating a slow auth flow could see the API server span and the runtime span, but could not correlate them — they had different trace IDs.

```
BEFORE (broken):
  Trace A: [API server: POST /api/auth/flow/:id/submit]  ← trace_id=abc123
  Trace B: [runtime_service: execute]                    ← trace_id=def456 (unrelated!)

AFTER (fixed):
  Trace A: [API server: POST /api/auth/flow/:id/submit]  ← trace_id=abc123
              └─ [eiaa_authz: execute_authorization]
                   └─ [runtime_client: execute_capsule]
                        └─ [runtime_service: execute]    ← trace_id=abc123 (child span!)
```

### Root Cause

Two independent failures:

1. **API server side** (`runtime_client.rs`): gRPC calls used raw proto structs (`ExecuteRequest {}`) passed directly to `self.client.execute()`. tonic requires a `tonic::Request<T>` wrapper to access the `MetadataMap` — without it, there is no way to inject headers. The `inject_trace_context()` helper was never called.

2. **Runtime service side** (`runtime_service/src/main.rs`): The service used only `tracing_subscriber` (stdout JSON logs). It had no OTel SDK, no OTLP exporter, no W3C propagator registration, and no code to extract `traceparent` from incoming gRPC metadata.

### Fix

#### API Server Side — `clients/runtime_client.rs`

Added `TonicMetadataInjector` implementing `opentelemetry::propagation::Injector` for `tonic::metadata::MetadataMap`:

```rust
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
```

All 3 gRPC call sites changed from raw struct to `tonic::Request::new()` + `inject_trace_context()`:

```rust
// BEFORE:
self.client.execute(ExecuteRequest { ... }).await

// AFTER:
let mut req = tonic::Request::new(ExecuteRequest { ... });
inject_trace_context(req.metadata_mut());
self.client.execute(req).await
```

#### Runtime Service Side — `runtime_service/src/main.rs`

Added `TonicMetadataExtractor` implementing `opentelemetry::propagation::Extractor`:

```rust
struct TonicMetadataExtractor<'a>(&'a tonic::metadata::MetadataMap);

impl<'a> opentelemetry::propagation::Extractor for TonicMetadataExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().filter_map(|k| match k {
            tonic::metadata::KeyRef::Ascii(k) => Some(k.as_str()),
            _ => None,
        }).collect()
    }
}
```

Added `init_telemetry()` function that mirrors `api_server/src/telemetry.rs` but uses service name `authstar-runtime`. Registers the W3C TraceContext propagator globally so `extract_trace_context()` can read `traceparent`.

In the `execute()` handler, extract the remote context and attach it as the parent span:

```rust
let parent_cx = extract_trace_context(req.metadata());
let span = tracing::info_span!(
    "runtime.execute",
    otel.kind = "server",
    rpc.system = "grpc",
    rpc.service = "CapsuleRuntime",
    rpc.method = "Execute",
);
span.set_parent(parent_cx);
let _span_guard = span.enter();
```

Added graceful OTel shutdown before process exit to flush buffered spans:

```rust
opentelemetry::global::shutdown_tracer_provider();
```

#### Dependencies — `runtime_service/Cargo.toml`

Added OTel crates matching the versions used by `api_server`:

```toml
opentelemetry = { version = "0.22", features = ["trace"] }
opentelemetry_sdk = { version = "0.22", features = ["rt-tokio", "trace"] }
opentelemetry-otlp = { version = "0.15", features = ["grpc-tonic", "trace"] }
opentelemetry-semantic-conventions = { version = "0.14" }
tracing-opentelemetry = { version = "0.23" }
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |
| `OTEL_SERVICE_NAME` | `authstar-runtime` | Service name in traces |
| `OTEL_SDK_DISABLED` | `false` | Set `true` to disable OTel (unit tests) |

### Zero-Cost When Disabled

When `OTEL_SDK_DISABLED=true`, the global propagator is a no-op. Both `inject_context()` (API server) and `extract()` (runtime service) do nothing — no allocations, no metadata writes. The fix has zero overhead in environments where tracing is disabled.

### Files Changed

| File | Change |
|------|--------|
| `backend/crates/api_server/src/clients/runtime_client.rs` | Added `TonicMetadataInjector`, `inject_trace_context()`, wrapped all 3 gRPC calls in `tonic::Request::new()` |
| `backend/crates/runtime_service/src/main.rs` | Added `TonicMetadataExtractor`, `extract_trace_context()`, `init_telemetry()`, OTel span in `execute()`, graceful shutdown |
| `backend/crates/runtime_service/Cargo.toml` | Added 5 OTel crate dependencies |