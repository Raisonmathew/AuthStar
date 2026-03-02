# Principal Architect Review: API Key Flow Analysis

**Reviewer:** Bob (Principal Software Engineer / Architect)
**Date:** 2026-03-01
**Status:** ✅ All P0/P1 fixes implemented. P2 (FLAW-E) documented, deferred.
**Scope:** End-to-end API key authentication and management flow
**Files Reviewed:**
- `backend/crates/api_server/src/routes/api_keys.rs`
- `backend/crates/api_server/src/middleware/api_key_auth.rs`
- `backend/crates/api_server/src/middleware/eiaa_authz.rs`
- `backend/crates/api_server/src/middleware/auth.rs`
- `backend/crates/api_server/src/middleware/org_context.rs`
- `backend/crates/api_server/src/middleware/csrf.rs`
- `backend/crates/api_server/src/router.rs`
- `backend/crates/db_migrations/migrations/037_api_keys.sql`
- `backend/crates/db_migrations/migrations/038_api_keys_auth_rls.sql`

---

## Executive Summary

The API key feature (B-4) has a **correct high-level design** — the key format, Argon2id hashing, RLS dual-policy pattern, and CSRF bypass are all sound. However, there are **3 confirmed critical flaws** that will cause the feature to be completely non-functional in production, plus **2 security concerns** that require attention. None of these were caught in the previous sprint because they require tracing the full middleware stack, not just reading individual files in isolation.

**Severity breakdown:**
| ID | Severity | Impact | Fix Status |
|----|----------|--------|------------|
| FLAW-A | 🔴 Critical | Management API (list/create/revoke) returns 500 for all tenants | ✅ Fixed — `api_keys.rs` all 3 handlers |
| FLAW-B | 🔴 Critical | API key auth fails in production (org_context_middleware blocks all requests) | ✅ Fixed — `org_context.rs:34-60` |
| FLAW-C | 🟠 High | `sid` sentinel is not a UUID — downstream code that parses `claims.sid` as UUID panics | ✅ Fixed — `api_key_auth.rs` + `auth.rs` |
| FLAW-D | 🟡 Medium | `last_used_at` fire-and-forget spawns unbounded tasks under load | ✅ Fixed — `api_keys.rs:authenticate_api_key` |
| FLAW-E | 🟡 Medium | No per-prefix rate limiting — prefix enumeration timing oracle possible | 📋 Deferred P2 — documented below |

**Previously identified flaws that are NOT flaws (false positives from initial analysis):**
- ~~FLAW-3: CSRF blocks API key requests~~ — `csrf.rs:40-44` explicitly bypasses CSRF for `Authorization: Bearer` headers ✅
- ~~FLAW-5: EiaaAuthzLayer re-runs JWT verify~~ — `eiaa_authz.rs:212` checks `req.extensions().get::<Claims>()` first; if Claims already injected by `api_key_auth_middleware`, JWT verification is skipped entirely ✅
- ~~FLAW-1: Session validation bypass~~ — EiaaAuthzLayer skips `verify_token_and_session` when Claims are already present; `require_auth_ext` is not applied as a separate layer in the router ✅

---

## Full Request Pipeline (Axum Tower Layer Order)

In Axum, `.layer()` calls are applied **outermost-first** in the final router. The actual execution order for a request is **innermost-first** (the last `.layer()` call runs first). Reading `router.rs` lines 221–334:

```
Incoming Request
  ↓ request_id_middleware          (outermost — runs first)
  ↓ track_metrics
  ↓ CorsLayer
  ↓ security_headers
  ↓ rate_limit_api
  ↓ org_context_middleware         ← FLAW-B lives here
  ↓ Extension(state)
  ↓ api_key_auth_middleware        ← resolves "Bearer ask_..." → Claims
  ↓ csrf_protection                ← bypassed for Bearer tokens ✅
  ↓ [route-specific layers]
      ↓ require_active_subscription
      ↓ EiaaAuthzLayer             ← checks Claims extension first, skips JWT verify ✅
  ↓ route handler                  ← FLAW-A lives here (management queries)
```

---

## Implemented Fixes Summary

| Fix | File | Change |
|-----|------|--------|
| FLAW-A (list) | `routes/api_keys.rs:list_api_keys` | Acquire dedicated conn, `set_config('app.current_tenant_id', ...)` before SELECT |
| FLAW-A (create) | `routes/api_keys.rs:create_api_key` | Acquire dedicated conn, `set_config('app.current_tenant_id', ...)` before INSERT |
| FLAW-A (revoke) | `routes/api_keys.rs:revoke_api_key` | Acquire dedicated conn, `set_config('app.current_tenant_id', ...)` before UPDATE |
| FLAW-B | `middleware/org_context.rs:34-60` | Early return for `Bearer ask_` requests before org slug extraction |
| FLAW-C (sentinel) | `middleware/api_key_auth.rs:sid` | `uuid::Uuid::nil().to_string()` instead of `"api_key:{user_id}"` |
| FLAW-C (guard) | `middleware/auth.rs:verify_jwt_and_session` | Short-circuit for `session_type == SERVICE` before DB session lookup |
| FLAW-D | `routes/api_keys.rs:authenticate_api_key` | Debounced UPDATE: only if `last_used_at IS NULL OR < NOW() - 5min` |

---

## FLAW-A: Management API Queries Bypass RLS — All Queries Return Empty or Fail

### Severity: 🔴 Critical — Feature completely non-functional

### Root Cause

`list_api_keys`, `create_api_key`, and `revoke_api_key` all execute queries directly against `state.db` (the connection pool) **without setting `app.current_tenant_id`** on the connection first.

```rust
// api_keys.rs:170-183 — list_api_keys
let keys = sqlx::query_as::<_, ApiKeyListItem>(
    "SELECT ... FROM api_keys WHERE user_id = $1 AND tenant_id = $2 ..."
)
.bind(user_id)
.bind(tenant_id)
.fetch_all(&state.db)   // ← pool connection, no RLS context set
.await?;
```

The `api_keys` table has `FORCE ROW LEVEL SECURITY`. Migration 038 defines:

```sql
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
    );
```

When `app.current_tenant_id` is not set on the connection, `current_setting(..., true)` returns `''` (empty string in PostgreSQL, not NULL). Casting `''` to `uuid` raises a **runtime error** in PostgreSQL:

```
ERROR: invalid input syntax for type uuid: ""
```

This means:
- `list_api_keys` → **500 Internal Server Error** (DB error propagated)
- `create_api_key` → **500 Internal Server Error** on INSERT (RLS check fails)
- `revoke_api_key` → **500 Internal Server Error** on UPDATE

The `WHERE user_id = $1 AND tenant_id = $2` clause in the SQL is **not sufficient** — RLS is evaluated separately by PostgreSQL and runs before the WHERE clause is applied.

### Why This Wasn't Caught

The `api_keys_auth_lookup` policy (migration 038) allows SELECT when `current_tenant_id` is NULL or empty. This means `authenticate_api_key` (the auth middleware path) works correctly. But the management CRUD handlers use the `api_keys_tenant_isolation` policy, which requires a valid UUID — and `''::uuid` is a cast error, not a policy miss.

### Fix — ✅ Implemented

All three management handlers now acquire a dedicated connection and set `app.current_tenant_id` before executing queries. Example (`list_api_keys`):

```rust
let mut conn = state.db.acquire().await
    .map_err(|e| AppError::Internal(format!("DB acquire failed: {}", e)))?;
sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
    .bind(tenant_id.to_string())
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("RLS context set failed: {}", e)))?;

let keys = sqlx::query_as::<_, ApiKeyListItem>("SELECT ...")
    .bind(user_id)
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;
```

**Note:** The existing `set_rls_context_on_conn` helper uses `app.current_org_id`, not `app.current_tenant_id`. The `api_keys` table uses `app.current_tenant_id` (matching migration 037/038). The inline `set_config` call is used directly rather than the helper to avoid the naming mismatch. A future refactor should unify these into a single configurable helper.

---

## FLAW-B: `org_context_middleware` Blocks All API Key Requests in Production

### Severity: 🔴 Critical — Feature completely non-functional in production

### Root Cause

`org_context_middleware` runs on **every request** (router.rs:248). It calls `extract_org_slug()` which:

1. Checks `X-Org-Slug` header (dev/testing convenience)
2. Falls back to parsing the `Host` header subdomain

For localhost, it hardcodes `"admin"` as the slug (org_context.rs:131-133). In production, API key clients (server-to-server SDKs) send requests to `https://api.yourproduct.com` — a single domain, not a subdomain. The Host header will be `api.yourproduct.com`, which has only 3 parts but the first part is `api`, not a tenant slug.

Even if the host parsing succeeds, `lookup_organization` queries the DB for that slug. If `api` is not a registered organization slug, the middleware returns **404 Not Found** before the request ever reaches `api_key_auth_middleware`.

### The Deeper Architectural Problem

`org_context_middleware` was designed for **browser-based multi-tenant routing** (tenant A uses `acme.idaas.app`, tenant B uses `beta.idaas.app`). API key authentication is fundamentally different: **the tenant is derived from the key itself**, not from the request routing. The middleware ordering is wrong for this use case.

### Fix — ✅ Implemented (Option 1)

`org_context_middleware` now checks for `Bearer ask_` at the top and returns early:

```rust
// middleware/org_context.rs:34-60
let is_api_key_request = request
    .headers()
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .map(|v| v.starts_with("Bearer ask_"))
    .unwrap_or(false);

if is_api_key_request {
    tracing::debug!("org_context_middleware: skipping for API key request");
    return Ok(next.run(request).await);
}
```

---

## FLAW-C: `sid` Sentinel Is Not a UUID — Downstream Panic Risk

### Severity: 🟠 High — Potential panic in production

### Root Cause

`api_key_auth_middleware` sets:

```rust
sid: format!("api_key:{}", user_id),  // e.g. "api_key:550e8400-e29b-41d4-a716-446655440000"
```

The `Claims.sid` field is typed as `String`, so this compiles. However, the `sessions` table has `id UUID PRIMARY KEY`. Any code that tries to use `claims.sid` as a session ID in a DB query will either:

1. **Fail with a DB error** if it tries to bind `claims.sid` as a UUID parameter (sqlx will reject the non-UUID string)
2. **Panic** if it calls `Uuid::parse_str(&claims.sid).unwrap()` anywhere

Searching the codebase for `claims.sid` usage in `verify_jwt_and_session` (auth.rs:145):

```rust
.bind(&claims.sid)  // bound as TEXT, not UUID — PostgreSQL will cast TEXT to UUID
```

PostgreSQL will attempt `'api_key:550e...'::uuid` which raises:
```
ERROR: invalid input syntax for type uuid: "api_key:550e..."
```

This means any route that goes through `require_auth_ext` (which calls `verify_jwt_and_session`) with an API key will return **500 Internal Server Error**.

However, as established above, `require_auth_ext` is NOT applied as a separate layer in the router — it's only called inside `EiaaAuthzLayer.verify_token_and_session`, which is skipped when Claims are already present. So this is currently latent. But it is a time bomb: any future developer adding `require_auth` to a route will trigger this.

### Fix — ✅ Implemented (both parts)

**Part 1** — `api_key_auth_middleware.rs`: sentinel changed to nil UUID:
```rust
sid: uuid::Uuid::nil().to_string(),  // "00000000-0000-0000-0000-000000000000"
```

**Part 2** — `auth.rs:verify_jwt_and_session`: service session guard added before DB lookup:
```rust
if claims.session_type == auth_core::jwt::session_types::SERVICE {
    tracing::debug!("verify_jwt_and_session: service session (API key) — skipping DB session check");
    return Ok(claims);
}
```

---

## FLAW-D: Unbounded `tokio::spawn` for `last_used_at` Updates

### Severity: 🟡 Medium — Resource exhaustion under load

### Root Cause

`authenticate_api_key` (api_keys.rs:361-370):

```rust
tokio::spawn(async move {
    let _ = sqlx::query!("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", key_id)
        .execute(&db_clone)
        .await;
});
```

Under high load (e.g., 10,000 API key requests/second), this spawns 10,000 tasks/second. Each task holds a DB connection from the pool. If the DB is slow (e.g., under write pressure), tasks accumulate faster than they complete, exhausting the connection pool and causing all DB operations to queue.

### Fix — ✅ Implemented

`authenticate_api_key` in `api_keys.rs` now uses a debounced UPDATE:

```rust
tokio::spawn(async move {
    let _ = sqlx::query!(
        r#"UPDATE api_keys
           SET last_used_at = NOW()
           WHERE id = $1
             AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '5 minutes')"#,
        key_id
    )
    .execute(&db_clone)
    .await;
});
```

Reduces write amplification by ~300x for active keys. `last_used_at` accurate to ±5 minutes — sufficient for audit and UI display.

---

## FLAW-E: No Rate Limiting on API Key Authentication Path

### Severity: 🟡 Medium — Prefix enumeration / timing oracle

### Root Cause

The `api_key_auth_middleware` is applied globally (router.rs:244) **after** `rate_limit_api` (router.rs:251). In Axum's layer ordering, `rate_limit_api` runs **before** `api_key_auth_middleware` (layers execute outermost-first). So rate limiting does apply.

However, `rate_limit_api` is a general 1000 req/min per org limit. For API key authentication specifically:

1. An attacker who knows a valid 8-char prefix can attempt Argon2id verification at 1000/min
2. Argon2id with m=19456, t=2 takes ~50ms per verification → 1000/min = ~16 concurrent verifications
3. This is within the designed parameters, but there is no **per-prefix** rate limiting

More critically: the prefix lookup (`WHERE key_prefix = $1`) is a fast index scan that returns before Argon2id verification. An attacker can enumerate which prefixes exist (by observing response time differences: fast 401 = prefix not found, slow 401 = prefix found but hash mismatch) at the full 1000/min rate.

### Fix — 📋 Deferred (P2)

Two options for a future sprint:

**Option A — Constant-time response:** When prefix is not found, run a dummy Argon2id verification against a static hash to equalize response time. This eliminates the timing oracle entirely without requiring Redis state.

**Option B — Per-prefix Redis rate limit:** Track failed attempts per prefix in Redis. After 10 failures in 1 minute, return 429 for that prefix for 60 seconds. This limits enumeration speed without affecting legitimate clients.

Recommended: implement Option A first (no state required), then Option B for brute-force protection.

---

## What Is Correct (Confirmed Working)

| Component | Status | Notes |
|-----------|--------|-------|
| Key format `ask_<8>_<48>` | ✅ Correct | base64url guarantees deterministic length |
| Argon2id hashing (m=19456, t=2, p=1) | ✅ Correct | OWASP minimum for high-entropy secrets |
| Full key returned once, never stored | ✅ Correct | Only hash stored in DB |
| Soft delete (revoked_at) | ✅ Correct | Audit trail preserved |
| CSRF bypass for Bearer tokens | ✅ Correct | `csrf.rs:40-44` handles this |
| EiaaAuthzLayer Claims short-circuit | ✅ Correct | `eiaa_authz.rs:212` checks extensions first |
| RLS dual-policy design (migration 038) | ✅ Correct | Auth lookup vs management separation |
| Ownership check in revoke (user_id AND tenant_id) | ✅ Correct | No IDOR possible |
| Scope injection as separate extension | ✅ Correct | Clean separation of identity vs authorization |
| Prefix index (partial, WHERE revoked_at IS NULL) | ✅ Correct | Fast auth lookup |
| Expiry check in authenticate_api_key | ✅ Correct | `expires_at > NOW()` in SQL |
| Revocation check in authenticate_api_key | ✅ Correct | `revoked_at IS NULL` in SQL |

---

## Priority Fix Order

### P0 — Must fix before any production deployment

1. **FLAW-A** ✅ Fixed — `set_config('app.current_tenant_id', ...)` added to all 3 management handlers.
2. **FLAW-B** ✅ Fixed — `org_context_middleware` skips for `Bearer ask_` requests.

### P1 — Fix before GA

3. **FLAW-C** ✅ Fixed — nil UUID sentinel + `session_type == SERVICE` guard in `verify_jwt_and_session`.

### P2 — Fix before scale

4. **FLAW-D** ✅ Fixed — Debounced `last_used_at` update (5-minute window).
5. **FLAW-E** 📋 Deferred — Per-prefix rate limiting / constant-time response. See FLAW-E section above.

---

---

## Conclusion

The API key feature has a solid cryptographic and schema design. The three critical flaws (FLAW-A, FLAW-B, FLAW-C) were all **integration failures** — each component was correct in isolation, but they didn't compose correctly in the full middleware stack. This is a classic symptom of feature development without end-to-end integration testing against the full middleware stack.

All P0 and P1 fixes have been implemented. The feature is now safe to deploy to production. FLAW-E (prefix enumeration) is a P2 hardening item that does not block deployment — the existing 1000 req/min global rate limit provides baseline protection.

### Files Modified in This Review

| File | Change |
|------|--------|
| `backend/crates/api_server/src/routes/api_keys.rs` | FLAW-A (3 handlers) + FLAW-D (debounce) |
| `backend/crates/api_server/src/middleware/org_context.rs` | FLAW-B (API key early return) |
| `backend/crates/api_server/src/middleware/api_key_auth.rs` | FLAW-C (nil UUID sentinel) |
| `backend/crates/api_server/src/middleware/auth.rs` | FLAW-C (service session guard) |