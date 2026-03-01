# AuthStar — Robustness & Production Readiness Roadmap

**Date:** 2026-02-28  
**Engineer:** Bob (Principal SWE, Identity-as-a-Provider / EIAA)  
**Scope:** Full-stack assessment — what remains to make AuthStar robust, complete, and production-ready  
**Basis:** Complete codebase audit across all 7 layers: backend routes, services, middleware, DB migrations, frontend pages, API clients, infrastructure

---

## Executive Summary

AuthStar has a strong architectural foundation: EIAA capsule execution, WASM policy engine, risk engine, RLS-enforced multi-tenancy, in-memory JWT storage, and comprehensive audit trail. The 5 functional fixes in `FUNCTIONAL_FIXES.md` and 65 security/EIAA fixes in `RELEASE_AUDIT.md` have addressed the critical blockers.

What remains falls into **6 categories**:

| Category | Items | Priority |
|----------|-------|----------|
| **A. Security Gaps** | 4 | P0 — fix before any production traffic |
| **B. Missing Core Features** | 6 | P1 — required for basic user journeys |
| **C. Resilience & Error Handling** | 5 | P1 — required for production stability |
| **D. Observability** | 3 | P2 — required for operations |
| **E. Frontend UX Completeness** | 5 | P2 — required for usable product |
| **F. Infrastructure & DevOps** | 4 | P2 — required for deployment |

---

## A. Security Gaps (P0 — Fix Before Production Traffic)

### A-1. `Capability::Password` Was a No-Op in EIAA Flow Engine ✅ FIXED THIS SESSION

**File:** `backend/crates/api_server/src/routes/auth_flow.rs` L201-205  
**Status:** Fixed — now calls `state.user_service.verify_user_password(user_id, password)` which includes account lockout protection.

Previously any password was accepted unconditionally for the EIAA flow path. The `identify_user` step only sets `ctx.user_id` — it does NOT verify the password. This was a complete authentication bypass for the primary login path.

---

### A-2. Rate Limiting Not Applied to Auth Flow Endpoints ⚠️ OPEN

**Files:** `backend/crates/api_server/src/routes/auth_flow.rs`, `backend/crates/api_server/src/main.rs`

The EIAA flow endpoints (`/flows/init`, `/flows/:id/identify`, `/flows/:id/submit`, `/flows/:id/complete`) have no per-IP or per-flow rate limiting. The global API rate limiter (if configured) applies to all routes equally, but auth endpoints need stricter limits.

**Risk:** Brute-force password attacks via the flow engine. The `verify_user_password` lockout (5 attempts) protects individual accounts, but an attacker can enumerate valid user IDs by observing timing differences before lockout.

**Fix:**
```rust
// In auth_flow router, add per-IP rate limiting:
// - /flows/init: 10 req/min per IP (prevents flow farming)
// - /flows/:id/submit: 5 req/min per flow_id (prevents per-flow brute force)
// Use the existing Redis connection for rate limit counters.
```

---

### A-3. `identify_user` Accepts Any User ID Without Proof of Identity ⚠️ OPEN

**File:** `backend/crates/api_server/src/routes/auth_flow.rs` L134-172

`identify_user` takes a `user_id` directly in the request body and sets it on the flow context. There is no check that the caller knows the user's email or any other identifier. An attacker who knows a valid `user_id` can call `identify_user` to associate that user with their flow, then submit a password attempt against that account.

**Risk:** Targeted account lockout. An attacker who knows a victim's `user_id` can call `identify_user` + `submit_step(Password, "wrong")` 5 times to lock the victim's account.

**Fix:** Change `identify_user` to accept `email` (or other identifier) instead of `user_id`. Look up the user internally. Never expose `user_id` in the identify step response.

```rust
// BEFORE
pub struct IdentifyReq {
    pub user_id: String,  // ← attacker-controlled
}

// AFTER
pub struct IdentifyReq {
    pub identifier: String,  // email or username — looked up server-side
}
// Internally: look up user by email, store user_id in flow context (not returned to client)
```

---

### A-4. `auth/lib/api/auth.ts` `signOut` Calls Wrong URL ⚠️ OPEN

**File:** `frontend/src/lib/api/auth.ts` L44-45

```typescript
signOut: () => api.post('/api/v1/sign-out'),  // ← 404
```

Backend mounts logout at `/api/v1/logout`, not `/api/v1/sign-out`. This is a second logout URL bug (the `AuthContext.tsx` one was fixed, but this API client function is also wrong and may be used by other components).

**Fix:**
```typescript
signOut: () => api.post('/api/v1/logout'),
```

---

## B. Missing Core Features (P1 — Required for Basic User Journeys)

### B-1. Password Reset Flow — Backend Exists, Frontend Not Wired ⚠️ OPEN

**Status:** Backend has `reset_password` route in `auth.rs`. Frontend `AuthFlowPage.tsx` has `UiStep` type for `reset_code_verification` and `new_password` but the flow is never initiated from the UI.

**What's needed:**
1. A "Forgot Password" link on the login page that calls `POST /api/v1/auth/reset-password-request`
2. The `AuthFlowPage` already handles the `reset_code_verification` and `new_password` UI steps — just needs the entry point
3. Verify the backend reset flow sends the email via `email_service`

---

### B-2. Email Verification After Signup — `commitDecision` Has No Callers ⚠️ OPEN

**File:** `frontend/src/lib/api/signupFlows.ts`

`commitDecision(decisionRef, flowId)` is defined but never called from any UI component. The signup flow (`init_flow` → `submit_flow` → `decision_ready`) completes but the final `commit` step that actually creates the user account is never triggered.

**What's needed:**
1. After `submit_flow` returns `{ status: 'decision_ready', decision_ref }`, the frontend must call `commitDecision(decision_ref, flow_id)`
2. This should be wired in the component that handles the signup flow (likely `AuthFlowPage.tsx` or a dedicated `SignupFlowPage`)
3. After commit succeeds, auto-login the user or redirect to login

---

### B-3. MFA Enrollment Page — Not Reachable from Navigation ⚠️ OPEN

**File:** `frontend/src/pages/MFAEnrollmentPage.tsx`

The MFA enrollment page exists and is routed in `App.tsx` at `/mfa/enroll`, but there is no link to it from `UserLayout`, `ProfilePage`, or any settings page. Users cannot discover or reach MFA enrollment through the UI.

**What's needed:**
1. Add "Security" section to `UserLayout` sidebar with link to `/mfa/enroll`
2. Or add MFA enrollment card to `ProfilePage`
3. Consider showing a banner when MFA is not enrolled (especially for admin users)

---

### B-4. API Keys Page — Exists but Backend Route May Not Be Wired ⚠️ OPEN

**File:** `frontend/src/pages/APIKeysPage.tsx`

The API Keys page exists in the frontend. Verify the backend has a corresponding `/api/v1/api-keys` route. If not, the page will show errors on load.

**What's needed:**
1. Verify `GET /api/v1/api-keys` exists in the backend router
2. If missing, implement: list, create (returns key once), revoke
3. API keys should be scoped to organization and stored as hashed values

---

### B-5. Team Management — Invitation Flow Not End-to-End ⚠️ OPEN

**File:** `frontend/src/pages/TeamManagementPage.tsx`

The invitation service exists in `org_manager/src/services/invitation_service.rs`. The frontend team management page exists. But the invitation acceptance flow (clicking the link in the email → accepting → creating account) needs to be verified end-to-end.

**What's needed:**
1. Verify `GET /api/v1/invitations/:token` and `POST /api/v1/invitations/:token/accept` are routed
2. Verify the invitation email template sends the correct acceptance URL
3. Add an invitation acceptance page to the frontend router

---

### B-6. Organization Switcher — `OrganizationSwitcher.tsx` Has No Backend Call ⚠️ OPEN

**File:** `frontend/src/components/OrganizationSwitcher.tsx`

The component exists but needs to call `GET /api/v1/organizations` to list the user's orgs, then issue a new session scoped to the selected org. The backend has `get_user_organizations` in `auth.rs` but the switcher may not be calling it correctly.

**What's needed:**
1. Verify `OrganizationSwitcher` calls `GET /api/v1/organizations`
2. After org switch, call `POST /api/v1/auth/switch-org` (or re-authenticate) to get a new JWT scoped to the new org
3. Update `AuthContext` with the new token and org ID

---

## C. Resilience & Error Handling (P1 — Required for Production Stability)

### C-1. EIAA Flow Context Stored in Redis — No TTL Expiry Handling ⚠️ OPEN

**File:** `backend/crates/api_server/src/services/eiaa_flow_service.rs`

Flow contexts are stored in Redis. If Redis is unavailable or the key expires, `load_flow_context` returns `None` and the handler returns 404. The frontend has no handling for "flow expired" — it shows a generic error.

**What's needed:**
1. Set explicit TTL on flow context keys (e.g. 15 minutes)
2. Return a specific error code (`flow_expired`) when the flow is not found
3. Frontend: detect `flow_expired` and redirect to login with a "Session expired, please try again" message

---

### C-2. Database Connection Pool Exhaustion — No Circuit Breaker ⚠️ OPEN

**File:** `backend/crates/api_server/src/state.rs`

The DB pool has `max_connections` configured but no circuit breaker. Under load, if all connections are in use, new requests will queue indefinitely until timeout. This can cascade into a full service outage.

**What's needed:**
1. Set `acquire_timeout` on the pool (e.g. 5 seconds)
2. Return 503 with `Retry-After` header when pool is exhausted
3. Add a health check endpoint that tests DB connectivity with a short timeout

---

### C-3. gRPC Runtime Client — No Retry or Fallback ⚠️ OPEN

**File:** `backend/crates/api_server/src/clients/runtime_client.rs`

The EIAA runtime client (WASM capsule executor) is called synchronously. If the runtime service is down, all EIAA-gated requests fail with 500. There is no retry logic or fallback policy.

**What's needed:**
1. Add exponential backoff retry (3 attempts, 100ms/200ms/400ms)
2. Define a fallback policy: if runtime is unreachable, either deny all (fail-closed) or allow with audit log (fail-open, configurable per org)
3. Add a circuit breaker that opens after 5 consecutive failures and half-opens after 30 seconds

---

### C-4. Email Service — Failover Between Providers Not Tested ⚠️ OPEN

**File:** `backend/crates/email_service/tests/failover_test.rs`

The email service has a failover test file but it may not be running in CI. Email delivery failures (verification codes, password reset) are silent — the user gets no feedback.

**What's needed:**
1. Ensure failover test runs in CI
2. Add user-facing error when email delivery fails: "We couldn't send the verification email. Please try again or contact support."
3. Add email delivery status tracking (sent/failed/bounced) to the audit log

---

### C-5. Stripe Webhook — No Idempotency Key Validation ⚠️ OPEN

**File:** `backend/crates/billing_engine/src/services/webhook_service.rs`

Stripe webhooks can be delivered multiple times. The webhook handler should be idempotent (processing the same event twice should have no effect). Without idempotency checks, duplicate webhooks can cause double-billing or double-provisioning.

**What's needed:**
1. Store processed Stripe event IDs in the DB with a unique constraint
2. On receipt, check if the event ID has been processed; if so, return 200 immediately
3. Use a DB transaction to atomically process the event and record the event ID

---

## D. Observability (P2 — Required for Operations)

### D-1. Structured Logging — Inconsistent Log Levels and Fields ⚠️ OPEN

**Across:** Multiple backend files

Some handlers use `tracing::info!` with structured fields, others use `tracing::debug!` or plain string formatting. There is no consistent log schema.

**What's needed:**
1. Define a log schema: every auth event must include `user_id`, `tenant_id`, `session_id`, `decision_ref`, `ip`, `user_agent`
2. Use `tracing::Span` to propagate these fields through the request lifecycle
3. Add a request ID middleware that generates a UUID per request and includes it in all logs and response headers (`X-Request-ID`)

---

### D-2. Metrics — No Prometheus Endpoint ⚠️ OPEN

**File:** `backend/crates/api_server/src/main.rs`

There is no `/metrics` endpoint. Without metrics, you cannot set up alerting for:
- Auth failure rate (brute force detection)
- EIAA capsule execution latency
- DB pool utilization
- Redis connection health

**What's needed:**
1. Add `axum-prometheus` or `metrics-exporter-prometheus` crate
2. Instrument: request count/latency by route, auth success/failure rate, capsule execution time, DB pool size
3. Add Kubernetes `ServiceMonitor` for Prometheus scraping

---

### D-3. Distributed Tracing — No OpenTelemetry Integration ✅ FIXED

**File:** `backend/crates/api_server/src/main.rs`

The backend uses `tracing` but has no OpenTelemetry exporter. In a multi-service architecture (API server + EIAA runtime + Redis + PostgreSQL), you cannot trace a request across service boundaries.

**What's needed:**
1. Add `opentelemetry-otlp` exporter
2. Propagate `traceparent` header from frontend → API server → runtime service
3. Configure Jaeger or Tempo as the trace backend

**Fix Applied (Phase 2 Architecture):** `backend/crates/api_server/src/telemetry.rs` implements OTLP/gRPC exporter with W3C TraceContext propagation, configurable sampling, and graceful shutdown. `traceparent` header propagated to gRPC runtime service.

---

## E. Frontend UX Completeness (P2 — Required for Usable Product)

### E-1. Error Boundaries — No Global Error Boundary in `App.tsx` ⚠️ OPEN

**File:** `frontend/src/App.tsx`

There is no React Error Boundary wrapping the application. An unhandled JavaScript error in any component will crash the entire app with a blank white screen and no recovery path.

**What's needed:**
```tsx
// Wrap the router in an ErrorBoundary
<ErrorBoundary fallback={<ErrorPage />}>
  <RouterProvider router={router} />
</ErrorBoundary>
```

---

### E-2. Loading States — `isLoading` Not Shown During Silent Refresh ⚠️ OPEN

**File:** `frontend/src/App.tsx` or root layout

`AuthContext` has `isLoading: true` during the initial silent refresh, but the app may render protected routes before the refresh completes, causing a flash of the login page before redirecting to the dashboard.

**What's needed:**
```tsx
// In the root layout or ProtectedRoute component:
if (isLoading) return <FullPageSpinner />;
```

---

### E-3. Form Validation — Client-Side Validation Missing on Key Forms ⚠️ OPEN

**Files:** Multiple frontend form components

Password reset, MFA enrollment, and SSO configuration forms lack client-side validation. Users get server-side error messages after a round trip instead of immediate feedback.

**What's needed:**
1. Add `react-hook-form` + `zod` validation to all auth forms
2. Validate: email format, password strength (min 8 chars, complexity), TOTP code format (6 digits), SAML certificate format

---

### E-4. Accessibility — No ARIA Labels on Auth Forms ⚠️ OPEN

**Files:** `AuthFlowPage.tsx`, `AdminLoginPage.tsx`

Auth forms lack ARIA labels, roles, and keyboard navigation support. This is a compliance requirement (WCAG 2.1 AA) for enterprise identity providers.

**What's needed:**
1. Add `aria-label`, `aria-describedby`, `role` to all form inputs
2. Ensure focus management: after form submission, focus moves to the next step or error message
3. Add `aria-live` regions for error messages

---

### E-5. Mobile Responsiveness — Auth Flow Page Not Optimized for Mobile ⚠️ OPEN

**File:** `frontend/src/features/auth/AuthFlowPage.tsx`

The auth flow page uses fixed-width containers that may not render correctly on mobile viewports. Enterprise SSO flows are increasingly initiated from mobile devices.

**What's needed:**
1. Use responsive Tailwind classes (`sm:`, `md:`) throughout the auth flow
2. Test on 375px (iPhone SE) and 390px (iPhone 14) viewports
3. Ensure the TOTP input, passkey button, and SSO redirect buttons are touch-friendly (min 44px tap targets)

---

## F. Infrastructure & DevOps (P2 — Required for Deployment)

### F-1. Kubernetes HPA — CPU-Based Scaling Not Appropriate for Auth Workloads ⚠️ OPEN

**File:** `infrastructure/kubernetes/base/hpa.yaml`

The HPA scales on CPU utilization. Auth workloads are I/O-bound (DB queries, Redis, gRPC calls) — CPU is not the right scaling signal. Under a login spike, CPU may stay low while DB connections are exhausted.

**What's needed:**
1. Scale on custom metrics: request queue depth, DB pool utilization, Redis connection count
2. Or use KEDA (Kubernetes Event-Driven Autoscaling) with Prometheus metrics
3. Set minimum replicas to 2 for HA

---

### F-2. Secrets Management — Env Vars in ConfigMap ⚠️ OPEN

**File:** `infrastructure/kubernetes/base/configmap.yaml`

Sensitive configuration (JWT secret, DB URL, Stripe keys) should not be in ConfigMaps. They should be in Kubernetes Secrets, ideally backed by an external secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager).

**What's needed:**
1. Move all secrets to Kubernetes Secrets
2. Use `external-secrets-operator` to sync from AWS Secrets Manager or Vault
3. Rotate secrets without redeployment using secret version references

---

### F-3. Database Migrations — No Rollback Strategy ⚠️ OPEN

**File:** `backend/crates/db_migrations/`

Migrations 001-030 are all forward-only. There are no down migrations. A failed deployment that requires rollback cannot revert the DB schema.

**What's needed:**
1. Add `down.sql` for each migration (or use a migration tool that supports rollback)
2. Test rollback in staging before every production deployment
3. Use blue-green deployment with schema compatibility between versions

---

### F-4. CI/CD — No Integration Test Suite ⚠️ OPEN

**Files:** `backend/crates/api_server/tests/`, `frontend/playwright.config.ts`

There is a Playwright config and an audit load test, but no integration test suite that exercises the full auth flow end-to-end (signup → verify email → login → MFA → logout).

**What's needed:**
1. Playwright E2E tests for: signup flow, login flow, MFA enrollment, SSO login, password reset
2. Backend integration tests using `sqlx::test` with a real PostgreSQL instance
3. CI pipeline: lint → unit tests → integration tests → E2E tests → build → deploy to staging

---

## Sprint 3 Action Plan (Next Sprint)

### Week 1 — Security (P0)
1. ✅ Fix `Capability::Password` no-op (done — A-1)
2. Fix `identify_user` to accept email, not user_id (A-3) ⚠️ OPEN
3. Fix `auth/lib/api/auth.ts` signOut URL (A-4) ⚠️ OPEN
4. Add rate limiting to auth flow endpoints (A-2) ⚠️ OPEN

### Week 2 — Core Features (P1)
5. Wire `commitDecision` to signup flow UI (B-2) ⚠️ OPEN
6. Add "Forgot Password" entry point to login page (B-1) ⚠️ OPEN
7. Add MFA enrollment link to user settings (B-3) ⚠️ OPEN
8. Verify API Keys backend route exists (B-4) ⚠️ OPEN

### Week 3 — Resilience (P1)
9. Add flow expiry handling (C-1) ⚠️ OPEN
10. Add DB pool acquire timeout + 503 response (C-2) ⚠️ OPEN
11. Add gRPC retry + circuit breaker (C-3) ⚠️ OPEN
12. Add Stripe webhook idempotency (C-5) ⚠️ OPEN

### Week 4 — Observability & Frontend (P2)
13. Add request ID middleware (D-1) ⚠️ OPEN
14. Add Prometheus metrics endpoint (D-2) ⚠️ OPEN
15. Add React Error Boundary (E-1) ⚠️ OPEN
16. Fix loading state during silent refresh (E-2) ⚠️ OPEN

---

## Fix History (All Sessions)

| Fix | File | Description | Sprint |
|-----|------|-------------|--------|
| FUNC-1 to FUNC-5 | Various frontend | Functional correctness fixes | Sprint 0 |
| CRITICAL-EIAA-1 to 4 / C-1 to C-4 | Various backend | EIAA critical blockers | Sprint 1 |
| F-1 to F-5 | Various backend | Architecture & operational findings | Sprint 2 |
| A-1 | `auth_flow.rs` | `Capability::Password` now calls `verify_user_password()` with lockout protection | Sprint 2 |
| Phase 1 Arch (30 items) | Various | Security & architecture gaps | Phase 1 |
| Phase 2 Arch (21 items) | Various | Security & architecture gaps | Phase 2 |
| NEW-2, NEW-3, CAVEAT-EIAA-1, CAVEAT-INFRA-1 | Various | Release audit findings | Release Audit |

---

## Total Fix Count Across All Sessions

| Session | Fixes | Category |
|---------|-------|----------|
| Sprint 0 | 5 | Functional correctness (FUNC-1 to FUNC-5) |
| Sprint 1 | 4 | EIAA critical blockers (C-1 to C-4) |
| Sprint 2 | 6 | Architecture & operational (F-1 to F-5, A-1) |
| Phase 1 Arch | 30 | Security & architecture gaps |
| Phase 2 Arch | 21 | Security & architecture gaps |
| Release Audit | 4 | NEW-2, NEW-3, CAVEAT-EIAA-1, CAVEAT-INFRA-1 |
| EIAA Deep Research | 7 | MEDIUM-EIAA-5,7,8,9,10; HIGH-EIAA-5 |
| **Total** | **77** | |

See [`MASTER_ISSUE_TRACKER.md`](MASTER_ISSUE_TRACKER.md) for the consolidated view of all issues and their current status.