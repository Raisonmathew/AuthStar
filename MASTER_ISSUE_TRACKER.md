# AuthStar IDaaS Platform — Master Issue Tracker

**Maintained by:** IBM Bob — Senior Product Owner, IDaaS Domain  
**Last Updated:** 2026-02-28  
**Scope:** All issues, findings, gaps, and fixes across all 7 analysis documents  
**Source Documents:**
- [`FUNCTIONAL_FIXES.md`](FUNCTIONAL_FIXES.md) — Sprint 0 functional correctness fixes
- [`EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md`](EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md) — EIAA compliance deep-dive
- [`ARCHITECTURE_GAP_ANALYSIS.md`](ARCHITECTURE_GAP_ANALYSIS.md) — Full architecture gap analysis (Phase 1 + 2)
- [`RELEASE_AUDIT.md`](RELEASE_AUDIT.md) — Independent release audit (65 controls)
- [`PRODUCT_OWNER_ANALYSIS.md`](PRODUCT_OWNER_ANALYSIS.md) — PO analysis + Sprint 1 & 2 findings
- [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md) — Robustness & production readiness roadmap
- [`SPRINT_CLOSURE_REPORT.md`](SPRINT_CLOSURE_REPORT.md) — Sprint 2 acceptance evidence
- [`PROGRESS.md`](PROGRESS.md) — Original project progress summary

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ FIXED | Implemented and verified by code inspection |
| ⚠️ OPEN | Identified, not yet fixed |
| ℹ️ INFO | Informational / intentional trade-off, not a defect |
| 🔧 OPS | Operational requirement (config/deployment, not code) |

---

## Section 1: Sprint 0 — Functional Correctness Fixes

**Source:** [`FUNCTIONAL_FIXES.md`](FUNCTIONAL_FIXES.md)  
**Sprint:** 0 (initial functional pass)  
**All 5 issues: ✅ FIXED**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| FUNC-1 | CRITICAL | `silentRefresh()` blank page — refresh response missing `user` field | [`frontend/src/features/auth/AuthContext.tsx`](frontend/src/features/auth/AuthContext.tsx) | ✅ FIXED |
| FUNC-2 | HIGH | Logout 404 — wrong URL `/api/v1/auth/logout` vs `/api/v1/logout` | [`frontend/src/features/auth/AuthContext.tsx`](frontend/src/features/auth/AuthContext.tsx) | ✅ FIXED |
| FUNC-3 | HIGH | SSO management all 404 — missing `/api` prefix on admin SSO routes | [`frontend/src/lib/api/sso.ts`](frontend/src/lib/api/sso.ts) | ✅ FIXED |
| FUNC-4 | SECURITY | `commit_decision` unprotected — no `flow_id` ownership check | [`backend/crates/api_server/src/routes/auth_flow.rs`](backend/crates/api_server/src/routes/auth_flow.rs) | ✅ FIXED |
| FUNC-5 | CRITICAL | Flow login never sets auth — `res.token` vs `res.jwt` field name mismatch | [`frontend/src/lib/api/signupFlows.ts`](frontend/src/lib/api/signupFlows.ts) | ✅ FIXED |

---

## Section 2: Sprint 1 — EIAA Critical Blockers

**Source:** [`EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md`](EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md) + [`PRODUCT_OWNER_ANALYSIS.md`](PRODUCT_OWNER_ANALYSIS.md)  
**Sprint:** 1  
**All 4 critical issues: ✅ FIXED**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| CRITICAL-EIAA-1 / C-1 | CRITICAL | Compiler signature verification uses `bincode` in runtime service; compiler signs with canonical JSON — mismatch causes all capsule executions to fail when `RUNTIME_COMPILER_PK_B64` is set | [`backend/crates/runtime_service/src/main.rs`](backend/crates/runtime_service/src/main.rs:82) | ✅ FIXED |
| CRITICAL-EIAA-2 / C-2 | CRITICAL | Frontend attestation body serialization uses insertion-order JSON; backend uses `BTreeMap` (lexicographic) — every frontend attestation verification returns false negative | [`frontend/src/lib/attestation.ts`](frontend/src/lib/attestation.ts:162) | ✅ FIXED |
| CRITICAL-EIAA-3 / C-3 | CRITICAL | Capsule cache miss returns HTTP 500 — no DB fallback; any cold-start or cache eviction causes all EIAA-protected routes to fail | [`backend/crates/api_server/src/middleware/eiaa_authz.rs`](backend/crates/api_server/src/middleware/eiaa_authz.rs:466) | ✅ FIXED |
| CRITICAL-EIAA-4 / C-4 | CRITICAL | Re-execution verification is a stub — returns `Verified` for any DB record without actual capsule replay; `AuditWriter` stores `input_digest` not `input_context` | [`backend/crates/api_server/src/services/reexecution_service.rs`](backend/crates/api_server/src/services/reexecution_service.rs:127) | ✅ FIXED |

---

## Section 3: Sprint 2 — Architecture & Operational Findings

**Source:** [`PRODUCT_OWNER_ANALYSIS.md`](PRODUCT_OWNER_ANALYSIS.md)  
**Sprint:** 2  
**All 5 issues: ✅ FIXED**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| F-1 | HIGH | Duplicate `031_` / `032_` migration prefix collision — sqlx sorts alphabetically, causing non-deterministic execution order | [`backend/crates/db_migrations/migrations/`](backend/crates/db_migrations/migrations/) | ✅ FIXED — renamed to 033–036 |
| F-2 | MEDIUM | SSO cache write-back stores `version: 0` sentinel — cache always appears stale, forcing DB re-fetch on every request | [`backend/crates/api_server/src/routes/sso.rs`](backend/crates/api_server/src/routes/sso.rs) | ✅ FIXED — `build_sso_policy_ast()` returns `(Program, i32)` |
| F-3 | MEDIUM | SSO routes create new gRPC connection per request — connection pool exhaustion under load | [`backend/crates/api_server/src/routes/sso.rs`](backend/crates/api_server/src/routes/sso.rs) | ✅ FIXED — uses `state.runtime_client.clone()` |
| F-4 | MEDIUM | `audit_writer.rs` uses fragile locale-dependent string match for column-not-found detection | [`backend/crates/api_server/src/services/audit_writer.rs`](backend/crates/api_server/src/services/audit_writer.rs) | ✅ FIXED — uses SQLSTATE `42703` |
| F-5 | LOW | `capsule_cache.rs` uses Redis `KEYS` (blocking O(N)) for tenant invalidation and stats | [`backend/crates/api_server/src/services/capsule_cache.rs`](backend/crates/api_server/src/services/capsule_cache.rs) | ✅ FIXED — replaced with `SCAN` cursor loop |

---

## Section 4: Architecture Gap Analysis — Phase 1 Fixes

**Source:** [`ARCHITECTURE_GAP_ANALYSIS.md`](ARCHITECTURE_GAP_ANALYSIS.md)  
**All 30 Phase 1 issues: ✅ FIXED**

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| CRITICAL-1 | CRITICAL | OTP codes logged in verification service | ✅ FIXED |
| CRITICAL-2 | CRITICAL | TOTP replay protection missing (`totp_last_used_at`) | ✅ FIXED |
| CRITICAL-3 | CRITICAL | Backup codes hashed with SHA-256 instead of Argon2id | ✅ FIXED |
| CRITICAL-4 | CRITICAL | OAuth state stored in memory, not Redis; no constant-time comparison | ✅ FIXED |
| CRITICAL-5 | CRITICAL | PKCE S256 not implemented per RFC 7636 | ✅ FIXED |
| CRITICAL-6 | CRITICAL | OAuth tokens not encrypted at rest | ✅ FIXED |
| CRITICAL-7 | CRITICAL | Stripe webhook HMAC not constant-time | ✅ FIXED |
| CRITICAL-8 | CRITICAL | Webhook idempotency not enforced | ✅ FIXED |
| CRITICAL-9 | CRITICAL | RLS context set on pool, not per-connection | ✅ FIXED |
| CRITICAL-10/11 | CRITICAL | JWT stored in `localStorage`/`sessionStorage` | ✅ FIXED |
| CRITICAL-12 | CRITICAL | K8s image tags not pinned to SHA digest | ✅ FIXED |
| HIGH-1 | HIGH | No account lockout after failed attempts | ✅ FIXED |
| HIGH-2 | HIGH | User creation not atomic | ✅ FIXED |
| HIGH-3 | HIGH | MFA disable does not require re-authentication | ✅ FIXED |
| HIGH-4 | HIGH | Race condition in Stripe customer creation | ✅ FIXED |
| HIGH-5 | HIGH | No subscription enforcement middleware | ✅ FIXED |
| HIGH-6 | HIGH | `organization_id` missing on identities | ✅ FIXED |
| HIGH-7 | HIGH | No rate limiting on auth endpoints | ✅ FIXED |
| HIGH-8/9 | HIGH | Bincode signing in attestation (non-portable) | ✅ FIXED |
| HIGH-10 | HIGH | `useAuth` not reactive React Context | ✅ FIXED |
| HIGH-13 | HIGH | No RLS on `signup_tickets` | ✅ FIXED |
| HIGH-14 | HIGH | Private keys stored in DB | ✅ FIXED |
| HIGH-16 | HIGH | No Kubernetes NetworkPolicy | ✅ FIXED |
| HIGH-17 | HIGH | No pod security contexts | ✅ FIXED |
| MEDIUM-1 | MEDIUM | Unverified identities can log in | ✅ FIXED |
| MEDIUM-2 | MEDIUM | SAML audience restriction not enforced | ✅ FIXED |
| MEDIUM-3 | MEDIUM | SAML AuthnRequests not signed | ✅ FIXED |
| MEDIUM-4 | MEDIUM | Passkey AAL incorrectly classified | ✅ FIXED |
| MEDIUM-5 | MEDIUM | WebAuthn user handle not stable | ✅ FIXED |
| MEDIUM-10 | MEDIUM | No expired record cleanup function | ✅ FIXED |
| MEDIUM-11 | MEDIUM | `risk_states` unique constraint not tenant-scoped | ✅ FIXED |
| MEDIUM-13/14 | MEDIUM | JS SDK endpoints wrong + no auto token refresh | ✅ FIXED |

---

## Section 5: Architecture Gap Analysis — Phase 2 Fixes

**Source:** [`ARCHITECTURE_GAP_ANALYSIS.md`](ARCHITECTURE_GAP_ANALYSIS.md)  
**All 21 Phase 2 issues: ✅ FIXED**

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| CRITICAL-A | CRITICAL | OAuth state key uses 16-char prefix instead of full 256-bit state | ✅ FIXED |
| CRITICAL-B | CRITICAL | SAML digest comparison not constant-time | ✅ FIXED |
| HIGH-A | HIGH | `TenantConn` does not enforce RLS at compile time | ✅ FIXED |
| HIGH-B | HIGH | `require_active_subscription` middleware not implemented | ✅ FIXED |
| HIGH-C | HIGH | `rate_limit_auth_flow` not implemented | ✅ FIXED |
| HIGH-D | HIGH | Go SDK `checkResponse()` does not check all HTTP error codes | ✅ FIXED |
| HIGH-E | HIGH | nginx has no TLS configuration | ✅ FIXED |
| HIGH-F | HIGH | TOTP secrets not encrypted at rest | ✅ FIXED |
| HIGH-G | HIGH | No password history enforcement | ✅ FIXED |
| MEDIUM-A | MEDIUM | SSO `client_secret` not encrypted at rest | ✅ FIXED |
| MEDIUM-B | MEDIUM | Capsule cache not invalidated on policy activation | ✅ FIXED |
| MEDIUM-C | MEDIUM | No circuit breaker on runtime gRPC client | ✅ FIXED |
| MEDIUM-D | MEDIUM | CORS panics in production if `ALLOWED_ORIGINS` not set | ✅ FIXED |
| MEDIUM-E | MEDIUM | Runtime pod has no resource limits | ✅ FIXED |
| STRUCT-1 | MEDIUM | `api.ts` not a secure shim | ✅ FIXED |
| STRUCT-2 | MEDIUM | `UserLayout` uses `sessionStorage.clear()` instead of `useAuth()` | ✅ FIXED |
| STRUCT-3 | MEDIUM | `StepUpModal` does not use secure client or WebAuthn ceremony | ✅ FIXED |
| STRUCT-4 | MEDIUM | `AdminLoginPage` uses `localStorage.setItem` instead of `setAuth()` | ✅ FIXED |
| STRUCT-5 | MEDIUM | Dashboard navigation routes missing from `App.tsx` | ✅ FIXED |
| STRUCT-6 | MEDIUM | No OpenTelemetry distributed tracing | ✅ FIXED |

---

## Section 6: Release Audit — New Findings

**Source:** [`RELEASE_AUDIT.md`](RELEASE_AUDIT.md)  
**Identified during independent release audit**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| NEW-1 | LOW | `subscription.rs` fails open on DB/Redis error — documented trade-off | [`backend/crates/api_server/src/middleware/subscription.rs`](backend/crates/api_server/src/middleware/subscription.rs:79) | ℹ️ INFO — documented trade-off; configurable `strict/lenient` mode recommended post-launch |
| NEW-2 | LOW | `org_context_middleware` returns 404 for any DB error (including connection failure) — ambiguous | [`backend/crates/api_server/src/middleware/org_context.rs`](backend/crates/api_server/src/middleware/org_context.rs:43) | ✅ FIXED — `RowNotFound` → 404; other DB errors → 503 |
| NEW-3 | LOW | CSRF cookie missing `Secure` flag | [`backend/crates/api_server/src/middleware/csrf.rs`](backend/crates/api_server/src/middleware/csrf.rs:158) | ✅ FIXED — `csrf_cookie_header(token, secure: bool)` added |
| NEW-4 | INFO | TOTP window boundary is intentionally conservative (blocks previous window) | [`backend/crates/identity_engine/src/services/mfa_service.rs`](backend/crates/identity_engine/src/services/mfa_service.rs:282) | ℹ️ INFO — intentional conservative behavior |
| CAVEAT-EIAA-1 | HIGH | `wasm_bytes`/`ast_bytes` NULL for pre-migration capsules — DB fallback path non-functional for existing rows | [`backend/crates/api_server/src/routes/eiaa.rs`](backend/crates/api_server/src/routes/eiaa.rs) | ✅ FIXED — INSERT persists bytes; `load_capsule_from_db` reads bytes; migration 032 + `backfill-capsules` binary |
| CAVEAT-INFRA-1 | MEDIUM | SHA digest placeholder `REPLACE_WITH_ACTUAL_DIGEST` has no automated substitution | [`infrastructure/kubernetes/base/backend-deployment.yaml`](infrastructure/kubernetes/base/backend-deployment.yaml) | ✅ FIXED — CI/CD pipeline + `deploy-production.sh` automate digest substitution |

---

## Section 7: EIAA Deep Research — High Severity Gaps

**Source:** [`EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md`](EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md)  
**HIGH-EIAA-5 fixed in Sprint 2; HIGH-EIAA-1 through 4 remain open**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| HIGH-EIAA-1 | HIGH | `PolicyCompiler` generates invalid AST for Passkey+Password — `RequireFactor` emitted without preceding `VerifyIdentity`, violating verifier rule R10/R11 | [`backend/crates/capsule_compiler/src/policy_compiler.rs`](backend/crates/capsule_compiler/src/policy_compiler.rs:54) | ⚠️ OPEN |
| HIGH-EIAA-2 | HIGH | AAL/capabilities not propagated to `RuntimeContext` — `assurance_level` and `verified_capabilities` from session never passed to capsule; AAL-aware policies cannot be enforced | [`backend/crates/api_server/src/middleware/eiaa_authz.rs`](backend/crates/api_server/src/middleware/eiaa_authz.rs) | ⚠️ OPEN |
| HIGH-EIAA-3 | HIGH | Nonce replay protection is process-lifetime only — `HashSet` in memory; lost on pod restart; `eiaa_replay_nonces` table exists but unused | [`backend/crates/runtime_service/src/main.rs`](backend/crates/runtime_service/src/main.rs:40) | ⚠️ OPEN |
| HIGH-EIAA-4 | HIGH | Attestation frequency matrix cache bypasses signature verification — cached `allowed: bool` trusted without cryptographic proof; Redis injection could grant access | [`backend/crates/api_server/src/middleware/eiaa_authz.rs`](backend/crates/api_server/src/middleware/eiaa_authz.rs:278) | ⚠️ OPEN |
| HIGH-EIAA-5 | HIGH | `eiaa_executions` table has duplicate/conflicting schema between migrations 006 and 011 | [`backend/crates/db_migrations/migrations/`](backend/crates/db_migrations/migrations/) | ✅ FIXED — migration 033 reconciles schema idempotently |

---

## Section 8: EIAA Deep Research — Medium Severity Gaps

**Source:** [`EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md`](EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md)  
**MEDIUM-EIAA-5, 7, 8, 9, 10 fixed; MEDIUM-EIAA-1 through 4 and 6 remain open**

| ID | Severity | Description | File | Status |
|----|----------|-------------|------|--------|
| MEDIUM-EIAA-1 | MEDIUM | Lowerer ignores `IdentitySource` in `VerifyIdentity` — always passes `0` to host; `Federated` vs `Primary` source indistinguishable | [`backend/crates/capsule_compiler/src/lowerer.rs`](backend/crates/capsule_compiler/src/lowerer.rs:167) | ⚠️ OPEN |
| MEDIUM-EIAA-2 | MEDIUM | `AuthorizeAction` action/resource strings hardcoded to `0` in lowerer — all authorization actions are equivalent in WASM | [`backend/crates/capsule_compiler/src/lowerer.rs`](backend/crates/capsule_compiler/src/lowerer.rs:259) | ⚠️ OPEN |
| MEDIUM-EIAA-3 | MEDIUM | `Condition::IdentityLevel` and `Condition::Context` always evaluate to `false` in lowerer — conditional policies silently broken | [`backend/crates/capsule_compiler/src/lowerer.rs`](backend/crates/capsule_compiler/src/lowerer.rs:331) | ⚠️ OPEN |
| MEDIUM-EIAA-4 | MEDIUM | `CollectCredentials` step is a no-op in WASM — signup flow capsules cannot signal credential collection | [`backend/crates/capsule_compiler/src/lowerer.rs`](backend/crates/capsule_compiler/src/lowerer.rs:280) | ⚠️ OPEN |
| MEDIUM-EIAA-5 | MEDIUM | Proto `AttestationBody` fields 10–12 (`achieved_aal`, `verified_capabilities`, `risk_snapshot_hash`) never populated | [`backend/crates/runtime_service/src/main.rs`](backend/crates/runtime_service/src/main.rs:158) | ✅ FIXED — populated from `DecisionOutput` |
| MEDIUM-EIAA-6 | MEDIUM | Frontend `AttestationVerifier` never initialized or called — client-side attestation verification is dead code | [`frontend/src/lib/attestation.ts`](frontend/src/lib/attestation.ts) | ⚠️ OPEN |
| MEDIUM-EIAA-7 | MEDIUM | `eiaa_capsules` table missing `wasm_bytes`/`ast_bytes` columns — DB fallback cannot load capsule bytes | [`backend/crates/db_migrations/migrations/`](backend/crates/db_migrations/migrations/) | ✅ FIXED — migration 033 adds columns; migration 035 adds backfill infrastructure |
| MEDIUM-EIAA-8 | MEDIUM | `eiaa_replay_nonces` table never used — persistent nonce replay protection not implemented | [`backend/crates/db_migrations/migrations/`](backend/crates/db_migrations/migrations/) | ✅ FIXED — `PgNonceStore` uses `INSERT ... ON CONFLICT DO NOTHING` + row count check |
| MEDIUM-EIAA-9 | MEDIUM | `signup_tickets.decision_ref` never populated — signup EIAA audit chain broken | [`backend/crates/identity_engine/src/services/verification_service.rs`](backend/crates/identity_engine/src/services/verification_service.rs) | ✅ FIXED — `create_signup_ticket()` accepts and stores `decision_ref` |
| MEDIUM-EIAA-10 | MEDIUM | `sessions.decision_ref` never populated — session-to-decision linkage broken | [`backend/crates/identity_engine/src/services/user_service.rs`](backend/crates/identity_engine/src/services/user_service.rs) | ✅ FIXED — migration 036 + `CreateSessionParams.decision_ref` |

---

## Section 9: Robustness Roadmap — Security Gaps (P0)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | File | Status |
|----|----------|-------------|------|--------|
| A-1 | P0 | `Capability::Password` was a no-op in EIAA flow engine — any password accepted unconditionally | [`backend/crates/api_server/src/routes/auth_flow.rs`](backend/crates/api_server/src/routes/auth_flow.rs:201) | ✅ FIXED — calls `verify_user_password()` with lockout protection |
| A-2 | P0 | No rate limiting on auth flow endpoints (`/flows/init`, `/flows/:id/submit`) — brute-force and user enumeration risk | [`backend/crates/api_server/src/routes/auth_flow.rs`](backend/crates/api_server/src/routes/auth_flow.rs) | ⚠️ OPEN |
| A-3 | P0 | `identify_user` accepts `user_id` directly — attacker can target specific accounts for lockout | [`backend/crates/api_server/src/routes/auth_flow.rs`](backend/crates/api_server/src/routes/auth_flow.rs:134) | ⚠️ OPEN |
| A-4 | P0 | `auth/lib/api/auth.ts` `signOut` calls wrong URL `/api/v1/sign-out` (should be `/api/v1/logout`) | [`frontend/src/lib/api/auth.ts`](frontend/src/lib/api/auth.ts:44) | ⚠️ OPEN |

---

## Section 10: Robustness Roadmap — Missing Core Features (P1)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| B-1 | P1 | Password reset flow — backend exists, no "Forgot Password" entry point in frontend | ⚠️ OPEN |
| B-2 | P1 | `commitDecision` defined but never called from any UI component — signup flow never completes | ⚠️ OPEN |
| B-3 | P1 | MFA enrollment page exists at `/mfa/enroll` but not reachable from any navigation | ⚠️ OPEN |
| B-4 | P1 | API Keys page exists in frontend — backend `/api/v1/api-keys` route may not be wired | ⚠️ OPEN |
| B-5 | P1 | Team invitation acceptance flow not verified end-to-end | ⚠️ OPEN |
| B-6 | P1 | `OrganizationSwitcher.tsx` has no backend call — org switching not functional | ⚠️ OPEN |

---

## Section 11: Robustness Roadmap — Resilience & Error Handling (P1)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| C-1 | P1 | EIAA flow context stored in Redis — no TTL expiry handling; frontend shows generic error on flow expiry | ⚠️ OPEN |
| C-2 | P1 | DB connection pool exhaustion — no `acquire_timeout`; requests queue indefinitely; no 503 response | ⚠️ OPEN |
| C-3 | P1 | gRPC runtime client — no retry logic or fallback policy (circuit breaker exists but no retry) | ⚠️ OPEN |
| C-4 | P1 | Email service failover test may not run in CI; email delivery failures are silent to users | ⚠️ OPEN |
| C-5 | P1 | Stripe webhook idempotency — `stripe_webhook_events` table exists but idempotency check may not cover all event types | ⚠️ OPEN |

---

## Section 12: Robustness Roadmap — Observability (P2)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| D-1 | P2 | Structured logging inconsistent — no standard log schema with `user_id`, `tenant_id`, `session_id`, `decision_ref` | ⚠️ OPEN |
| D-2 | P2 | No Prometheus `/metrics` endpoint — cannot alert on auth failure rate, capsule latency, DB pool utilization | ⚠️ OPEN |
| D-3 | P2 | No OpenTelemetry integration for distributed tracing across API server + runtime service | ✅ FIXED — `telemetry.rs` with OTLP/gRPC exporter and W3C TraceContext propagation |

---

## Section 13: Robustness Roadmap — Frontend UX (P2)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| E-1 | P2 | No React Error Boundary in `App.tsx` — unhandled JS error crashes entire app | ⚠️ OPEN |
| E-2 | P2 | `isLoading` not shown during silent refresh — flash of login page before dashboard | ⚠️ OPEN |
| E-3 | P2 | Client-side form validation missing on key forms (password reset, MFA enrollment, SSO config) | ⚠️ OPEN |
| E-4 | P2 | No ARIA labels on auth forms — WCAG 2.1 AA compliance gap | ⚠️ OPEN |
| E-5 | P2 | Auth flow page not optimized for mobile viewports | ⚠️ OPEN |

---

## Section 14: Robustness Roadmap — Infrastructure & DevOps (P2)

**Source:** [`ROBUSTNESS_ROADMAP.md`](ROBUSTNESS_ROADMAP.md)

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| F-1-INFRA | P2 | K8s HPA scales on CPU — wrong signal for I/O-bound auth workloads | ⚠️ OPEN |
| F-2-INFRA | P2 | Secrets management — sensitive config may be in ConfigMap instead of Kubernetes Secrets | ⚠️ OPEN |
| F-3-INFRA | P2 | No rollback strategy — migrations are forward-only, no `down.sql` | ⚠️ OPEN |
| F-4-INFRA | P2 | No integration test suite — no E2E tests for full auth flow | ⚠️ OPEN |

---

## Section 15: Operational Requirements (Not Code Defects)

**Source:** [`RELEASE_AUDIT.md`](RELEASE_AUDIT.md) Part 9

| # | Requirement | Status |
|---|-------------|--------|
| OPS-1 | Replace SHA digest placeholder in K8s manifests with actual image digest from CI/CD | 🔧 OPS — automated in CI/CD pipeline (CAVEAT-INFRA-1 fix) |
| OPS-2 | Set `ALLOWED_ORIGINS` env var in production (CORS/CSRF enforcement) | 🔧 OPS |
| OPS-3 | Set `FACTOR_ENCRYPTION_KEY` env var (32-byte AES key for TOTP secret encryption) | 🔧 OPS |
| OPS-4 | Set `OAUTH_TOKEN_ENCRYPTION_KEY` env var (32-byte AES key for OAuth token encryption) | 🔧 OPS |
| OPS-5 | Set `SSO_ENCRYPTION_KEY` env var (32-byte AES key for SSO `client_secret` encryption) | 🔧 OPS |
| OPS-6 | Set `RUNTIME_DATABASE_URL` env var for runtime service PostgreSQL nonce store | 🔧 OPS |
| OPS-7 | Run capsule backfill after deploying migrations: `cargo run --bin backfill-capsules` (one-time) | 🔧 OPS |
| OPS-8 | Add pg_cron job for `cleanup_expired_records()` and `eiaa_replay_nonces` TTL cleanup | 🔧 OPS |

---

## Summary Dashboard

### By Status

| Status | Count |
|--------|-------|
| ✅ FIXED | **71** |
| ⚠️ OPEN | **27** |
| ℹ️ INFO | **2** |
| 🔧 OPS | **8** |
| **Total tracked** | **108** |

### Fixed Issues by Sprint

| Sprint | Issues Fixed | Category |
|--------|-------------|----------|
| Sprint 0 | 5 | Functional correctness (FUNC-1 to FUNC-5) |
| Sprint 1 | 4 | EIAA critical blockers (C-1 to C-4) |
| Sprint 2 | 5 | Architecture & operational (F-1 to F-5) |
| Phase 1 Arch | 30 | Security & architecture gaps |
| Phase 2 Arch | 21 | Security & architecture gaps |
| Release Audit | 4 | NEW-2, NEW-3, CAVEAT-EIAA-1, CAVEAT-INFRA-1 |
| Robustness | 2 | A-1 (password verify), D-3 (OpenTelemetry) |
| **Total** | **71** | |

### Open Issues by Priority

| Priority | Count | Issues |
|----------|-------|--------|
| P0 — Security | 3 | A-2, A-3, A-4 |
| P1 — Core Features | 6 | B-1 through B-6 |
| P1 — Resilience | 5 | C-1 through C-5 |
| P1 — EIAA Compliance | 4 | HIGH-EIAA-1 through HIGH-EIAA-4 |
| P2 — EIAA Completeness | 4 | MEDIUM-EIAA-1, 2, 3, 4, 6 (5 items) |
| P2 — Observability | 2 | D-1, D-2 |
| P2 — Frontend UX | 5 | E-1 through E-5 |
| P2 — Infrastructure | 4 | F-1-INFRA through F-4-INFRA |

---

## Recommended Next Sprint (Sprint 3)

### Week 1 — P0 Security (Must Fix Before Any Production Traffic)

| # | Issue | Effort |
|---|-------|--------|
| 1 | A-3: Change `identify_user` to accept `email`, not `user_id` | 2h |
| 2 | A-4: Fix `auth.ts` `signOut` URL to `/api/v1/logout` | 15min |
| 3 | A-2: Add per-IP rate limiting to `/flows/init` and per-flow-id to `/flows/:id/submit` | 2h |

### Week 2 — P1 Core Features (Required for Basic User Journeys)

| # | Issue | Effort |
|---|-------|--------|
| 4 | B-2: Wire `commitDecision` call after `submit_flow` returns `decision_ready` | 1h |
| 5 | B-1: Add "Forgot Password" link on login page | 1h |
| 6 | B-3: Add MFA enrollment link to user settings sidebar | 30min |
| 7 | B-4: Verify/implement `/api/v1/api-keys` backend route | 2h |

### Week 3 — P1 EIAA Compliance

| # | Issue | Effort |
|---|-------|--------|
| 8 | HIGH-EIAA-1: Fix `PolicyCompiler` to insert `VerifyIdentity` before `RequireFactor` | 30min |
| 9 | HIGH-EIAA-2: Add `assurance_level`/`verified_capabilities` to `RuntimeContext` | 2h |
| 10 | HIGH-EIAA-3: Persist nonces to `eiaa_replay_nonces` table with TTL | 1h |
| 11 | HIGH-EIAA-4: Verify attestation signature on cache hit | 1h |

### Week 4 — P1 Resilience

| # | Issue | Effort |
|---|-------|--------|
| 12 | C-1: Add `flow_expired` error code + frontend handling | 1h |
| 13 | C-2: Add `acquire_timeout` to DB pool + 503 response | 1h |
| 14 | C-3: Add exponential backoff retry to gRPC runtime client | 2h |

---

## EIAA Compliance Scorecard

| EIAA Component | Sprint 0 | Sprint 1 | Sprint 2 | Current |
|----------------|----------|----------|----------|---------|
| Identity-Only JWT | 100% | 100% | 100% | **100%** |
| Capsule Compiler | 85% | 85% | 85% | **85%** ⚠️ |
| Capsule Runtime | 90% | 90% | 90% | **90%** |
| Cryptographic Attestation | 100% | 100% | 100% | **100%** |
| Runtime Service | 70% | 95% | 95% | **95%** |
| Policy Management API | 100% | 100% | 100% | **100%** |
| Audit Trail | 60% | 85% | 90% | **90%** |
| Frontend Verification | 10% | 90% | 90% | **90%** |
| Route Coverage | 95% | 95% | 95% | **95%** |
| AAL Enforcement | 30% | 30% | 60% | **60%** ⚠️ |
| Re-Execution Verification | 15% | 95% | 95% | **95%** |
| **Overall EIAA** | ~72% | ~84% | ~87% | **~87%** |

---

## Platform Readiness Scorecard

| Domain | Score | Trend |
|--------|-------|-------|
| Core Authentication | 88% | ✅ Stable |
| Multi-Factor Authentication | 90% | ✅ Stable |
| Passkeys / WebAuthn | 85% | ✅ Stable |
| SSO / SAML / OAuth | 87% | ✅ Stable |
| EIAA Policy Engine | 87% | ↑ Improving |
| Multi-Tenancy & RLS | 85% | ✅ Stable |
| Billing / Stripe | 88% | ✅ Stable |
| Risk Engine | 80% | ✅ Stable |
| Security Posture | 89% | ✅ Stable |
| Frontend UX | 75% | ⚠️ Needs work |
| Test Coverage | 65% | ⚠️ Needs work |
| Infrastructure / DevOps | 91% | ✅ Stable |
| **Overall Platform** | **~87%** | ↑ Improving |

---

*This document is the single source of truth for all tracked issues. Update this file whenever a fix is implemented or a new issue is discovered. Cross-reference with individual analysis documents for full context and evidence.*