# EIAA × OAuth 2.0 Authorization Server — Deep Research & Integration Blueprint

**Date:** 2025-07-09  
**Scope:** How to build an RFC-compliant OAuth 2.0 Authorization Server that preserves EIAA's identity-only JWT invariant, capsule-based authorization, and per-request risk evaluation.  
**Method:** RFC 6749 / 7636 / 9126 analysis cross-referenced with every relevant IDaaS codebase file.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State: What Exists](#2-current-state-what-exists)
3. [Gap: What an OAuth 2.0 AS Requires](#3-gap-what-an-oauth-20-as-requires)
4. [The EIAA Tension: Identity-Only Tokens vs OAuth Scopes](#4-the-eiaa-tension-identity-only-tokens-vs-oauth-scopes)
5. [Proposed Architecture: EIAA-Aware OAuth 2.0 AS](#5-proposed-architecture-eiaa-aware-oauth-20-as)
6. [Endpoint Specification](#6-endpoint-specification)
7. [Grant Types & Flows](#7-grant-types--flows)
8. [Token Strategy](#8-token-strategy)
9. [Consent & Authorization UI](#9-consent--authorization-ui)
10. [EIAA Capsule Integration Points](#10-eiaa-capsule-integration-points)
11. [Database Schema Requirements](#11-database-schema-requirements)
12. [Security Considerations](#12-security-considerations)
13. [Implementation Roadmap](#13-implementation-roadmap)

---

## 1. Executive Summary
 
### Current Reality

The IDaaS platform has **two halves** of OAuth 2.0 but is missing the middle:

| Role | Status | Evidence |
|------|--------|----------|
| **OAuth 2.0 Client** (consuming external IdPs) | ✅ Production-ready | `sso.rs` + `oauth_service.rs`: Authorization Code + PKCE + AES-256-GCM token encryption |
| **Application Registry** (client management) | ✅ Implemented | `app_service.rs`: client_id/secret generation, redirect_uri validation, allowed_flows config |
| **OAuth 2.0 Authorization Server** (issuing tokens to third parties) | ❌ **Not implemented** | No `/oauth/authorize`, no `/oauth/token`, no authorization code issuance |

### What Needs to Be Built

A standards-compliant OAuth 2.0 Authorization Server that:

1. **Issues authorization codes** after the user completes the EIAA authentication flow
2. **Exchanges codes for tokens** at the `/oauth/token` endpoint with client authentication
3. **Respects EIAA's fundamental invariant**: JWTs carry identity only — authorization is computed per-request by capsules
4. **Integrates capsule execution** at the authorization decision point (consent + policy)
5. **Supports PKCE** (RFC 7636) — mandatory for public clients, recommended for all
6. **Leverages the existing App Registry** — `client_id`, `client_secret_hash`, `redirect_uris`, `allowed_flows`, `enforce_pkce` already in the database

### The Core Design Decision

> **How do OAuth 2.0 scopes coexist with EIAA capsule-based authorization?**

**Answer: Scopes are hints, capsules are authority.**

OAuth scopes (`openid profile email`) tell the client what *categories* of access it might receive. But the EIAA capsule at the resource server determines whether the actual request is allowed — factoring in real-time risk score, AAL level, device trust, and policy rules that scopes cannot express.

This is not a compromise — it's a security upgrade. Traditional OAuth AS implementations embed authorization in the token (scopes = permissions). EIAA separates the concern: the token carries identity + requested scopes, the capsule decides actual access.

---

## 2. Current State: What Exists

### 2.1 Application Model (Already Built)

**File:** `backend/crates/org_manager/src/models/mod.rs`

```rust
pub struct Application {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub r#type: String,                    // "web" | "mobile" | "api"
    pub client_id: String,                 // "client_{nanoid(20)}"
    pub client_secret_hash: Option<String>, // SHA-256(secret), skip_serializing
    pub redirect_uris: serde_json::Value,  // ["https://app.example.com/callback"]
    pub allowed_flows: serde_json::Value,  // ["authorization_code", "refresh_token", "client_credentials"]
    pub public_config: serde_json::Value,  // {"enforce_pkce": true, "allowed_origins": [...]}
}
```

**What this means:** The database already stores everything RFC 6749 §2 requires for client registration. The `allowed_flows` field directly maps to OAuth grant types. `enforce_pkce` maps to RFC 7636 enforcement.

### 2.2 Client Authentication (Already Built)

**File:** `backend/crates/org_manager/src/services/app_service.rs`

- Client secrets are generated as `URL_SAFE_NO_PAD.encode(random_32_bytes)` — 256-bit entropy
- Stored as `SHA-256(client_secret)` — hash-at-rest
- Verification: hash the presented secret and compare (needs constant-time upgrade)
- Secret rotation via `rotate_secret()` — generates new secret, updates hash

### 2.3 Auth Flow (Already Built — Needs Bridge)

**File:** `backend/crates/api_server/src/routes/auth_flow.rs`

The EIAA 4-step flow already authenticates users:
```
init → identify → submit (password/TOTP/passkey) → complete
```

The `complete` step currently:
1. Validates all required capabilities are satisfied
2. Executes an EIAA capsule for `auth:login`
3. Creates a session with AAL level + decision_ref
4. Issues a JWT + sets httpOnly cookies
5. Redirects to the frontend

**What's missing:** The `complete` step doesn't know about OAuth. It doesn't issue an authorization code, doesn't check redirect_uri, doesn't validate client_id, and doesn't present a consent screen.

### 2.4 JWT Service (Already Built — Identity-Only)

**File:** `backend/crates/auth_core/src/jwt.rs`

```rust
pub struct Claims {
    pub sub: String,       // user_id
    pub sid: String,       // session_id
    pub tenant_id: String,
    pub session_type: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    // INVARIANT: NO roles, permissions, scopes, entitlements
}
```

**Unit test enforces this:**
```rust
#[test]
fn test_claims_do_not_contain_authority() {
    let json = serde_json::to_string(&claims).unwrap();
    assert!(!json.contains("role"));
    assert!(!json.contains("permission"));
    assert!(!json.contains("scope"));
    assert!(!json.contains("entitlement"));
}
```

### 2.5 Risk Engine + Capsule Runtime (Already Built)

The EIAA middleware in `eiaa_authz.rs` already performs per-request authorization:
1. Verify JWT → extract identity
2. Evaluate risk score (0-100) via Risk Engine
3. Load + execute WASM capsule with `RuntimeContext` {subject_id, risk_score, AAL, verified_capabilities}
4. Verify Ed25519 attestation on decision
5. Check nonce replay protection
6. Audit the decision (decision_ref)

This **continues to work unchanged** for resource server protection. OAuth tokens issued by our AS will still be subject to capsule authorization at the resource server.

---

## 3. Gap: What an OAuth 2.0 AS Requires

### 3.1 Required Endpoints (RFC 6749 §3)

| Endpoint | RFC Section | Purpose | Current Status |
|----------|-------------|---------|----------------|
| `GET /oauth/authorize` | §3.1 | Authorization endpoint — redirects user to login, shows consent | ❌ Not implemented |
| `POST /oauth/token` | §3.2 | Token endpoint — exchanges grants for access tokens | ❌ Not implemented |
| `GET /oauth/userinfo` | OIDC Core §5.3 | Returns user claims for `openid` scope | ❌ Not implemented |
| `POST /oauth/revoke` | RFC 7009 | Token revocation | ❌ Not implemented |
| `POST /oauth/introspect` | RFC 7662 | Token introspection | ❌ Not implemented |
| `GET /.well-known/openid-configuration` | OIDC Discovery | Server metadata | ❌ Not implemented |
| `GET /.well-known/jwks.json` | RFC 7517 | Public keys for token verification | ❌ Not implemented |

### 3.2 Required Grant Types

| Grant Type | RFC Section | `allowed_flows` Value | Use Case | Priority |
|------------|-------------|----------------------|----------|----------|
| Authorization Code | §4.1 | `authorization_code` | Web/mobile apps — user present | **P0** — Must have |
| Authorization Code + PKCE | RFC 7636 | `authorization_code` + `enforce_pkce` | Public clients (SPAs, native apps) | **P0** — Must have |
| Refresh Token | §6 | `refresh_token` | Long-lived sessions | **P0** — Must have |
| Client Credentials | §4.4 | `client_credentials` | Machine-to-machine (no user) | **P1** — Important |
| ~~Implicit~~ | ~~§4.2~~ | ~~N/A~~ | ~~Deprecated by OAuth 2.1~~ | **Skip** |
| ~~Resource Owner Password~~ | ~~§4.3~~ | ~~N/A~~ | ~~Anti-pattern~~ | **Skip** |

### 3.3 Required Behaviors

| Behavior | RFC Reference | Description |
|----------|---------------|-------------|
| Client Authentication | §2.3 | Verify `client_id` + `client_secret` at token endpoint |
| Redirect URI Validation | §3.1.2 | Exact string match against registered URIs |
| Authorization Code Binding | §4.1.3 | Code bound to client_id + redirect_uri, single-use, max 10-min lifetime |
| State Parameter | §10.12 | CSRF protection — echo back `state` from authorize request |
| Scope Validation | §3.3 | Validate requested scopes against client's allowed scopes |
| Error Responses | §4.1.2.1, §5.2 | Standard error codes: `invalid_request`, `unauthorized_client`, `access_denied`, etc. |
| Cache-Control Headers | §5.1 | `Cache-Control: no-store` and `Pragma: no-cache` on token responses |
| PKCE Enforcement | RFC 7636 §4 | S256 code_challenge at /authorize, code_verifier at /token |

---

## 4. The EIAA Tension: Identity-Only Tokens vs OAuth Scopes

### 4.1 The Problem

RFC 6749 §3.3 defines scopes as a mechanism for **limiting token authority**:
> "The authorization and token endpoints allow the client to specify the scope of the access request."

Traditional OAuth AS implementations embed scopes into access tokens. Resource servers then check `token.scope.includes("read:users")` to decide access.

**But EIAA says: tokens MUST NOT carry authorization.** The `test_claims_do_not_contain_authority()` test explicitly rejects `scope` in Claims.

### 4.2 The Resolution: Two-Layer Authorization

```
┌─────────────────────────────────────────────────────┐
│                   OAuth 2.0 Layer                    │
│                                                      │
│  Client requests: scope=openid profile email         │
│  AS issues token: {sub, sid, tenant_id, aud, ...}    │
│  Token carries: identity + granted_scopes metadata   │
│                                                      │
│  Scopes define: what CATEGORIES of access were       │
│  consented to by the user                            │
└──────────────────────┬──────────────────────────────┘
                       │ Token presented to Resource Server
                       ▼
┌─────────────────────────────────────────────────────┐
│                    EIAA Layer                         │
│                                                      │
│  Middleware extracts JWT → identity claims            │
│  Risk Engine evaluates: score, device trust, etc.    │
│  Capsule executes with: {subject_id, risk_score,     │
│    AAL, capabilities, requested_action, scope_hint}  │
│  Capsule returns: Allow / Deny + attestation         │
│                                                      │
│  Capsule can CHECK scopes as a CONDITION but is      │
│  not BOUND by them — it can deny even with valid     │
│  scope if risk is too high or policy forbids it      │
└─────────────────────────────────────────────────────┘
```

### 4.3 Implementation Strategy

**Access tokens issued by our AS:** Will be ES256-signed JWTs containing:

```json
{
  "sub": "usr_abc123",
  "iss": "https://idaas.example.com",
  "aud": "client_xyz789",
  "exp": 1720000000,
  "iat": 1719999100,
  "nbf": 1719999100,
  "sid": "ses_def456",
  "tenant_id": "org_ghi789",
  "session_type": "end_user",
  "client_id": "client_xyz789",
  "scope": "openid profile email"
}
```

**Wait — doesn't `scope` in the JWT violate the EIAA invariant?**

No. Here's why:
- EIAA's invariant says: **no roles, permissions, or entitlements in the JWT**
- OAuth scopes are **user consent metadata**, not authorization grants
- The scope field records *what the user agreed the client could ask for*
- It does NOT mean the resource server must grant access based on scope alone
- The EIAA capsule at the resource server uses scope as an **input signal** alongside risk, AAL, device trust
- The capsule can deny `read:users` even if the token has that scope (e.g., risk too high, AAL insufficient)

**The unit test `test_claims_do_not_contain_authority()` will need to be updated** to allow `scope` but continue blocking `role`, `permission`, `entitlement`. Scope is consent metadata, not authority. Or better: use a separate `OAuthClaims` struct that extends `Claims` with `client_id` and `scope`.

### 4.4 Token Architecture Decision

**Option A: Single JWT struct, add optional OAuth fields** (simpler)
```rust
pub struct Claims {
    // ... existing identity fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}
```

**Option B: Separate OAuthAccessToken struct** (cleaner EIAA separation) ← **RECOMMENDED**
```rust
// Internal platform tokens (unchanged)
pub struct Claims { sub, sid, tenant_id, session_type, iss, aud, exp, iat, nbf }

// OAuth AS-issued tokens (new)
pub struct OAuthAccessTokenClaims {
    // Identity (from Claims)
    pub sub: String,
    pub iss: String,
    pub aud: String,      // audience = client_id
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub sid: String,
    pub tenant_id: String,
    
    // OAuth-specific
    pub client_id: String,
    pub scope: String,     // Space-separated scope list
    pub token_type: String, // "oauth_access_token"
}
```

Option B preserves the invariant: `Claims` (internal) never has scope. `OAuthAccessTokenClaims` (external) has scope as consent metadata. The EIAA middleware can distinguish between internal and OAuth tokens via the `token_type` field.

---

## 5. Proposed Architecture: EIAA-Aware OAuth 2.0 AS

### 5.1 Authorization Code Flow (with EIAA)

```
Third-Party App                    IDaaS OAuth AS                      User Browser
      │                                  │                                  │
      │ ─── (1) GET /oauth/authorize ──> │                                  │
      │      ?response_type=code         │                                  │
      │      &client_id=client_xyz       │                                  │
      │      &redirect_uri=https://...   │                                  │
      │      &scope=openid profile       │                                  │
      │      &state=abc123               │                                  │
      │      &code_challenge=K2-lt...    │                                  │
      │      &code_challenge_method=S256 │                                  │
      │                                  │                                  │
      │                                  │ ── (2) Validate client_id,       │
      │                                  │     redirect_uri, scope          │
      │                                  │                                  │
      │                                  │ ── (3) Store OAuth context       │
      │                                  │     in Redis (10-min TTL)        │
      │                                  │                                  │
      │                                  │ ── (4) Redirect to EIAA ──────> │
      │                                  │     login page with             │
      │                                  │     ?oauth_flow_id=xxx          │
      │                                  │                                  │
      │                                  │                   (5) User completes EIAA flow:
      │                                  │                       init → identify → submit → complete
      │                                  │                                  │
      │                                  │ <─ (6) EIAA flow complete ───── │
      │                                  │     User authenticated,          │
      │                                  │     capsule approved             │
      │                                  │                                  │
      │                                  │ ── (7) Show consent screen ──> │
      │                                  │     "App X wants to access      │
      │                                  │      your profile and email"    │
      │                                  │                                  │
      │                                  │ <─ (8) User grants consent ──── │
      │                                  │                                  │
      │                                  │ ── (9) Execute EIAA capsule     │
      │                                  │     for "oauth:authorize"       │
      │                                  │     with RuntimeContext {        │
      │                                  │       risk_score, AAL,          │
      │                                  │       requested_scopes,         │
      │                                  │       client_id                 │
      │                                  │     }                           │
      │                                  │                                  │
      │                                  │ ── (10) Generate auth code      │
      │                                  │      (256-bit random,           │
      │                                  │       bound to client_id,       │
      │                                  │       redirect_uri, scope,      │
      │                                  │       code_challenge,           │
      │                                  │       user_id, session_id)      │
      │                                  │                                  │
      │ <── (11) 302 Redirect ────────── │                                  │
      │     to redirect_uri              │                                  │
      │     ?code=SplxlOBe...           │                                  │
      │     &state=abc123                │                                  │
      │                                  │                                  │
      │ ─── (12) POST /oauth/token ───> │                                  │
      │     grant_type=authorization_code│                                  │
      │     code=SplxlOBe...            │                                  │
      │     redirect_uri=https://...     │                                  │
      │     code_verifier=dBjft...       │                                  │
      │     client_id=client_xyz         │                                  │
      │     client_secret=sec_...        │                                  │
      │                                  │                                  │
      │                                  │ ── (13) Validate:               │
      │                                  │   - client_id + secret match    │
      │                                  │   - code exists, not expired    │
      │                                  │   - code bound to this client   │
      │                                  │   - redirect_uri matches        │
      │                                  │   - PKCE: S256(verifier)==challenge
      │                                  │   - code is single-use (delete) │
      │                                  │                                  │
      │ <── (14) 200 OK ─────────────── │                                  │
      │     {                            │                                  │
      │       "access_token": "eyJ...",  │                                  │
      │       "token_type": "Bearer",    │                                  │
      │       "expires_in": 900,         │                                  │
      │       "refresh_token": "rft_...",│                                  │
      │       "scope": "openid profile"  │                                  │
      │     }                            │                                  │
```

### 5.2 Client Credentials Flow (Machine-to-Machine)

```
Service Client                     IDaaS OAuth AS
      │                                  │
      │ ─── POST /oauth/token ────────> │
      │     grant_type=client_credentials│
      │     client_id=client_xyz         │
      │     client_secret=sec_...        │
      │     scope=api:read               │
      │                                  │
      │                                  │ ── Authenticate client
      │                                  │ ── Verify "client_credentials" in allowed_flows
      │                                  │ ── Execute capsule for "oauth:client_credentials"
      │                                  │ ── Issue access token (NO refresh token per RFC §4.4.3)
      │                                  │
      │ <── 200 OK ──────────────────── │
      │     {                            │
      │       "access_token": "eyJ...",  │
      │       "token_type": "Bearer",    │
      │       "expires_in": 3600,        │
      │       "scope": "api:read"        │
      │     }                            │
```

---

## 6. Endpoint Specification

### 6.1 `GET /oauth/authorize` — Authorization Endpoint

**RFC 6749 §3.1**

**Request Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | MUST be `code` (we skip implicit/token) |
| `client_id` | Yes | Must match a registered Application |
| `redirect_uri` | Yes | Must exactly match one of Application.redirect_uris |
| `scope` | No | Space-separated scopes (default: `openid`) |
| `state` | Recommended | CSRF token, echoed back in redirect |
| `code_challenge` | Conditional | Required if Application.public_config.enforce_pkce = true |
| `code_challenge_method` | Conditional | Must be `S256` (we reject `plain`) |

**Server Processing:**

1. **Validate `client_id`** — look up Application by client_id + tenant_id from request context
2. **Validate `redirect_uri`** — exact string match against `Application.redirect_uris[]` (RFC §3.1.2.3)
3. **Validate `response_type`** — must be `code`; check `authorization_code` is in `Application.allowed_flows`
4. **Validate scope** — against a tenant-level scope registry (or accept-all for MVP)
5. **Enforce PKCE** — if `Application.public_config.enforce_pkce`, require `code_challenge` + `code_challenge_method=S256`
6. **Store OAuth context in Redis** — key: `oauth_authz:{flow_id}`, TTL: 10 min
   ```json
   {
     "client_id": "client_xyz",
     "redirect_uri": "https://app.example.com/callback",
     "scope": "openid profile",
     "state": "abc123",
     "code_challenge": "K2-lt...",
     "code_challenge_method": "S256",
     "tenant_id": "org_001"
   }
   ```
7. **Redirect to EIAA login UI** — `302` to `/u/{tenant}/login?oauth_flow_id={flow_id}`

**Error Handling (RFC §4.1.2.1):**
- Missing/invalid/mismatching `redirect_uri` → display error to user, do NOT redirect
- Other errors → redirect to `redirect_uri` with `?error=invalid_request&error_description=...&state=...`

### 6.2 `POST /oauth/token` — Token Endpoint

**RFC 6749 §3.2**

**Common Parameters:**

| Parameter | Description |
|-----------|-------------|
| `grant_type` | `authorization_code`, `refresh_token`, or `client_credentials` |
| `client_id` | Client identifier |
| `client_secret` | Client secret (confidential clients) |

**Grant-specific handling — see [Section 7](#7-grant-types--flows).**

**Response (RFC §5.1):**

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiY2QifQ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "rft_a1b2c3d4e5f6...",
  "scope": "openid profile email"
}
```

**Error Response (RFC §5.2):**

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8

{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired"
}
```

### 6.3 `GET /oauth/userinfo` — UserInfo Endpoint (OIDC)

**Protected by Bearer token.** Returns claims based on granted scopes.

| Scope | Claims Returned |
|-------|----------------|
| `openid` | `sub` |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `updated_at` |
| `email` | `email`, `email_verified` |

### 6.4 `POST /oauth/revoke` — Token Revocation (RFC 7009)

Accepts `token` + `token_type_hint` (access_token or refresh_token). Invalidates the token. Always returns 200 OK (even if token doesn't exist — per spec).

### 6.5 `POST /oauth/introspect` — Token Introspection (RFC 7662)

Accepts `token`. Returns `{ "active": true/false, "sub": "...", "client_id": "...", "scope": "...", "exp": ... }`. Requires client authentication.

### 6.6 `GET /.well-known/openid-configuration` — Discovery

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

### 6.7 `GET /.well-known/jwks.json` — JSON Web Key Set

Exposes the ES256 public key for token verification by resource servers.

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "abcd1234",
      "use": "sig",
      "alg": "ES256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

---

## 7. Grant Types & Flows

### 7.1 Authorization Code Grant (RFC 6749 §4.1)

**At `/oauth/authorize`:**
1. Validate request params (client_id, redirect_uri, scope, response_type=code)
2. If PKCE required: validate code_challenge present with method=S256
3. Store OAuth context in Redis
4. Redirect user to EIAA login UI

**After EIAA flow completes:**
1. User is authenticated (session exists with AAL + capabilities)
2. Present consent screen (unless prior consent exists for this client+scope)
3. Execute EIAA capsule `oauth:authorize` with RuntimeContext
4. If capsule allows: generate authorization code

**Authorization Code Generation:**
```rust
let code = generate_id("oac"); // "oac_{nanoid(32)}" — RFC §10.10: ≥128-bit entropy
let code_hash = sha256(&code);

// Store in Redis with 10-min TTL (RFC §4.1.2: max lifetime 10 minutes)
redis.set_ex(
    format!("oauth_code:{}", code_hash),
    json!({
        "client_id": ctx.client_id,
        "redirect_uri": ctx.redirect_uri,
        "scope": ctx.scope,
        "user_id": session.user_id,
        "session_id": session.id,
        "tenant_id": ctx.tenant_id,
        "code_challenge": ctx.code_challenge,
        "code_challenge_method": ctx.code_challenge_method,
        "created_at": now,
        "decision_ref": capsule_decision_ref,
    }),
    600, // 10 minutes
)?;
```

**At `/oauth/token` (grant_type=authorization_code):**

Additional parameters: `code`, `redirect_uri`, `code_verifier`

1. **Authenticate client** — `client_id` + `client_secret` via HTTP Basic or POST body
2. **Look up authorization code** — hash the presented code, look up in Redis
3. **Validate code binding:**
   - `code.client_id == request.client_id`
   - `code.redirect_uri == request.redirect_uri`
4. **Validate PKCE** — `BASE64URL(SHA256(code_verifier)) == code.code_challenge`
5. **Delete code from Redis** — single-use enforcement (RFC §4.1.2: "MUST NOT use more than once")
6. **Issue tokens:**
   - Access token: ES256 JWT with `OAuthAccessTokenClaims`
   - Refresh token: opaque string stored in DB with metadata

### 7.2 Refresh Token Grant (RFC 6749 §6)

**At `/oauth/token` (grant_type=refresh_token):**

1. **Authenticate client** — same as above
2. **Look up refresh token** in database
3. **Validate:** token not revoked, not expired, bound to this client_id
4. **Rotate refresh token** — issue new refresh token, revoke the old one (one-time use)
5. **Issue new access token** — same scope as original (or subset if requested)

**Refresh Token Storage:**
```sql
CREATE TABLE oauth_refresh_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,      -- SHA-256(token)
    client_id TEXT NOT NULL REFERENCES applications(client_id),
    user_id TEXT NOT NULL REFERENCES users(id),
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    replaced_by TEXT,                      -- Points to new token (rotation chain)
    decision_ref TEXT                       -- EIAA audit trail
);
```

### 7.3 Client Credentials Grant (RFC 6749 §4.4)

**At `/oauth/token` (grant_type=client_credentials):**

1. **Authenticate client** — REQUIRED (§4.4: "MUST only be used by confidential clients")
2. **Verify** `client_credentials` is in `Application.allowed_flows`
3. **Validate scope** — must be within the client's pre-configured allowed scopes
4. **Execute capsule** `oauth:client_credentials` — machine-to-machine policy evaluation
5. **Issue access token** — NO refresh token (RFC §4.4.3: "A refresh token SHOULD NOT be included")
6. **Set `session_type` to `service`** — distinguishes M2M from user tokens

---

## 8. Token Strategy

### 8.1 Access Tokens

| Property | Value | Rationale |
|----------|-------|-----------|
| Format | ES256 JWT | Same as internal tokens, verifiable by resource servers without AS roundtrip |
| Lifetime | 15 minutes (900s) | Short-lived, limits blast radius. Configurable per tenant |
| Signing Key | Same EC key pair as internal JWTs | Single JWKS endpoint. Can use separate kid if needed |
| Audience | `client_id` of requesting app | Resource servers verify `aud` claim |
| Issuer | IDaaS instance URL | Verified by resource servers |

### 8.2 Refresh Tokens

| Property | Value | Rationale |
|----------|-------|-----------|
| Format | Opaque string (`rft_{nanoid(40)}`) | Not self-contained — requires DB lookup = revocable |
| Lifetime | 30 days | Configurable per client. Absolute expiry |
| Storage | SHA-256 hash in `oauth_refresh_tokens` table | Hash-at-rest, same pattern as client_secret |
| Rotation | One-time use, rotated on each exchange | RFC §10.4: limits replay window. Rotation chain tracked |
| Binding | client_id + user_id + tenant_id | Cannot be used by different client |

### 8.3 Authorization Codes

| Property | Value | Rationale |
|----------|-------|-----------|
| Format | `oac_{nanoid(32)}` | ≥128-bit entropy (RFC §10.10) |
| Lifetime | 10 minutes | RFC §4.1.2: "maximum lifetime of 10 minutes is RECOMMENDED" |
| Storage | Redis with TTL | Ephemeral, single-use — hash as key for O(1) lookup |
| Binding | client_id + redirect_uri + scope + user_id + code_challenge | Full context for validation at /token |

### 8.4 EIAA Token Differentiation

The EIAA middleware needs to distinguish internal platform tokens from OAuth-issued tokens:

```rust
// In eiaa_authz.rs middleware:
fn classify_token(claims: &serde_json::Value) -> TokenType {
    if claims.get("client_id").is_some() && claims.get("scope").is_some() {
        TokenType::OAuthAccessToken
    } else {
        TokenType::InternalPlatform
    }
}

// For OAuth tokens, the capsule's RuntimeContext gains additional fields:
pub struct OAuthRuntimeContext {
    // From RuntimeContext
    pub subject_id: i64,
    pub risk_score: i32,
    pub assurance_level: u8,
    pub verified_capabilities: Vec<String>,
    
    // OAuth-specific
    pub client_id: String,
    pub granted_scopes: Vec<String>,
    pub token_type: String,  // "oauth_access_token"
}
```

---

## 9. Consent & Authorization UI

### 9.1 Consent Flow

After the user completes EIAA authentication, the OAuth flow presents a consent screen:

```
┌────────────────────────────────────────────┐
│  "Example App" wants to access your account│
│                                            │
│  This application is requesting:           │
│                                            │
│  ☐ Access your profile information         │
│    (name, profile picture)                 │
│                                            │
│  ☐ Access your email address               │
│    (email, email verification status)      │
│                                            │
│  ┌──────────────┐  ┌──────────────┐        │
│  │    Deny      │  │   Authorize  │        │
│  └──────────────┘  └──────────────┘        │
│                                            │
│  This will allow Example App to access     │
│  this information on your behalf.          │
└────────────────────────────────────────────┘
```

### 9.2 Consent Storage

```sql
CREATE TABLE oauth_consents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,           -- Consented scopes (space-separated)
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    decision_ref TEXT,             -- EIAA capsule decision that approved consent
    
    UNIQUE(user_id, client_id, tenant_id)  -- One consent record per user-client pair
);
```

### 9.3 Consent Skip Logic

Re-consent is skipped when:
1. A non-revoked consent record exists for this user + client_id
2. The previously consented scopes are a superset of the currently requested scopes
3. The client is a first-party app (marked as `trusted` in Application config)

Re-consent is forced when:
1. New scopes are requested beyond what was previously consented
2. The consent record was revoked by the user
3. Tenant policy requires re-consent (e.g., regulatory)

---

## 10. EIAA Capsule Integration Points

### 10.1 Capsule Actions for OAuth

| Capsule Action | Trigger | Context | Purpose |
|---------------|---------|---------|---------|
| `oauth:authorize` | User grants consent at /oauth/authorize | {subject_id, risk_score, AAL, client_id, scopes} | Policy: should this user be allowed to authorize this client? E.g., block if risk > 60, require AAL2 for sensitive scopes |
| `oauth:client_credentials` | POST /oauth/token with client_credentials | {client_id, scopes, ip, user_agent} | Policy: should this M2M client get these scopes? E.g., restrict by IP range, time-of-day |
| `oauth:token_exchange` | POST /oauth/token with authorization_code | {subject_id, client_id, scopes, risk_score} | Optional: re-evaluate at token issuance time (defense in depth) |
| `{action}` (resource server) | Bearer token access to protected resource | {subject_id, risk_score, AAL, client_id, scopes, action} | Standard EIAA per-request authorization — now with OAuth context |

### 10.2 Extended RuntimeContext for OAuth

The existing `RuntimeContext` gains OAuth awareness:

```rust
pub struct RuntimeContext {
    // Existing fields
    pub subject_id: i64,
    pub risk_score: i32,
    pub factors_satisfied: Vec<i32>,
    pub verifications_satisfied: Vec<String>,
    pub assurance_level: u8,
    pub verified_capabilities: Vec<String>,
    pub context_values: HashMap<String, i32>,
    
    // New OAuth fields
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Vec<String>,
    pub oauth_grant_type: Option<String>, // "authorization_code", "client_credentials", "refresh_token"
}
```

### 10.3 Capsule Policy Examples

**Example 1: Block high-risk users from authorizing third-party apps**
```json
{
  "steps": [
    {"type": "VerifyIdentity", "source": "Primary"},
    {"type": "EvaluateRisk"},
    {"type": "Conditional", "condition": {"type": "RiskLevel", "operator": "gt", "value": 60},
      "then": [{"type": "Deny", "reason": "Risk too high for OAuth authorization"}]},
    {"type": "AuthorizeAction", "action": "oauth:authorize", "resource": "third_party_app"},
    {"type": "Allow"}
  ]
}
```

**Example 2: Require AAL2 for scopes that access sensitive data**
```json
{
  "steps": [
    {"type": "VerifyIdentity", "source": "Primary"},
    {"type": "EvaluateRisk"},
    {"type": "Conditional", "condition": {"type": "Context", "key": "scope_contains_sensitive", "operator": "eq", "value": 1},
      "then": [
        {"type": "RequireFactor", "factor": "Totp"},
        {"type": "Conditional", "condition": {"type": "AssuranceLevel", "operator": "lt", "value": 2},
          "then": [{"type": "Deny", "reason": "AAL2 required for sensitive scopes"}]}
      ]},
    {"type": "AuthorizeAction", "action": "oauth:authorize", "resource": "app"},
    {"type": "Allow"}
  ]
}
```

---

## 11. Database Schema Requirements

### 11.1 New Tables

```sql
-- Authorization codes (Redis is primary, DB is backup/audit)
-- Actually: Redis-only with 10-min TTL is sufficient for codes

-- Refresh tokens
CREATE TABLE oauth_refresh_tokens (
    id TEXT PRIMARY KEY DEFAULT 'ort_' || nanoid(20),
    token_hash TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    replaced_by TEXT REFERENCES oauth_refresh_tokens(id),
    decision_ref TEXT,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX idx_ort_token_hash ON oauth_refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_ort_user_client ON oauth_refresh_tokens(user_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_ort_expires ON oauth_refresh_tokens(expires_at) WHERE revoked_at IS NULL;

-- User consents
CREATE TABLE oauth_consents (
    id TEXT PRIMARY KEY DEFAULT 'ocs_' || nanoid(20),
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    decision_ref TEXT,
    
    CONSTRAINT uq_user_client_tenant UNIQUE(user_id, client_id, tenant_id)
);

CREATE INDEX idx_ocs_user ON oauth_consents(user_id) WHERE revoked_at IS NULL;

-- Optional: OAuth scope definitions (tenant-scoped)
CREATE TABLE oauth_scopes (
    id TEXT PRIMARY KEY DEFAULT 'osc_' || nanoid(20),
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,           -- "profile", "email", "api:read"
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    requires_aal INT DEFAULT 1,   -- Minimum AAL to grant this scope
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT uq_scope_tenant UNIQUE(tenant_id, name)
);
```

### 11.2 Application Model Updates

The existing `Application` model needs:

```sql
-- Add to applications table
ALTER TABLE applications ADD COLUMN IF NOT EXISTS allowed_scopes JSONB DEFAULT '["openid", "profile", "email"]';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS is_first_party BOOLEAN DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS token_lifetime_secs INT DEFAULT 900;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS refresh_token_lifetime_secs INT DEFAULT 2592000; -- 30 days
```

---

## 12. Security Considerations

### 12.1 OWASP & RFC Security Requirements

| Threat | Mitigation | Implementation |
|--------|-----------|----------------|
| Authorization Code Interception (RFC §10.5) | PKCE (S256) mandatory for public clients | `code_challenge` + `code_verifier` verification |
| CSRF on Authorization Endpoint (RFC §10.12) | `state` parameter echoed back | Store in Redis, validate on redirect |
| Code Injection (RFC §10.14) | Input validation on all params | URL parsing, scope allowlisting, redirect_uri exact match |
| Open Redirector (RFC §10.15) | Exact redirect_uri match | String comparison against registered URIs (no patterns) |
| Token Leakage | Short-lived access tokens (15 min), httpOnly cookies | ES256 JWT with `exp`, `Cache-Control: no-store` |
| Refresh Token Theft | One-time use, rotation on exchange | `replaced_by` chain, detect reuse anomaly |
| Client Impersonation (RFC §10.2) | Client secret verification + PKCE | SHA-256 hash comparison + code_verifier proof |
| Clickjacking (RFC §10.13) | `X-Frame-Options: DENY` on consent page | Response header on authorization endpoint |
| Token Replay | Nonce in EIAA attestation, `nbf` + `exp` in JWT | Existing EIAA nonce store + JWT validation |
| Brute Force on Token Endpoint | Rate limiting per client_id + IP | Middleware rate limiter |
| Timing Attacks | Constant-time comparison for secrets | `subtle::ConstantTimeEq` for client_secret verification |

### 12.2 PKCE Enforcement Policy

| Client Type | `enforce_pkce` | Behavior |
|------------|----------------|----------|
| `web` (confidential) | `false` (default) | PKCE optional but recommended |
| `web` (confidential) | `true` | PKCE required |
| `mobile` (public) | Always `true` | PKCE mandatory — reject if no code_challenge |
| `api` (M2M) | N/A | Uses client_credentials, no authorization code |

### 12.3 Refresh Token Rotation & Reuse Detection

```
Token Chain:  RT1 → RT2 → RT3 → RT4 (current)
                                      │
If attacker replays RT2: ─────────────┘ (RT2 already revoked)
  → Detect reuse: RT2.replaced_by = RT3 (exists)
  → REVOKE ENTIRE CHAIN: RT1, RT2, RT3, RT4 all revoked
  → User must re-authenticate
```

This is a critical security feature: if a revoked refresh token is presented, the entire token family is compromised. Revoke everything and force re-authentication.

---

## 13. Implementation Roadmap

### Phase 1: Core OAuth 2.0 AS (P0)

| Step | Component | Files to Create/Modify | Dependencies |
|------|-----------|----------------------|-------------|
| 1.1 | Authorization Code storage | New: `backend/crates/auth_core/src/oauth_code.rs` | Redis |
| 1.2 | OAuth token types | New: `backend/crates/auth_core/src/oauth_claims.rs` | `jwt.rs` |
| 1.3 | `/oauth/authorize` endpoint | New: `backend/crates/api_server/src/routes/oauth.rs` | App Registry, Redis, EIAA flow |
| 1.4 | `/oauth/token` endpoint | Same file as 1.3 | Client auth, code validation |
| 1.5 | PKCE validation | In `/oauth/token` handler | SHA-256, base64url |
| 1.6 | Client authentication helper | New: `backend/crates/auth_core/src/client_auth.rs` | `app_service.rs` |
| 1.7 | Refresh token storage | Migration + new: `oauth_refresh_tokens` table | DB |
| 1.8 | Refresh token grant | In `/oauth/token` handler | Rotation logic |
| 1.9 | EIAA flow integration | Modify: `auth_flow.rs` complete step | OAuth context awareness |
| 1.10 | Consent screen | New frontend: `ConsentPage.tsx` | Consent storage |
| 1.11 | DB migration | New: `oauth_refresh_tokens`, `oauth_consents` tables | Migrator |

### Phase 2: Discovery & Metadata (P0)

| Step | Component | Files |
|------|-----------|-------|
| 2.1 | `/.well-known/openid-configuration` | In `oauth.rs` |
| 2.2 | `/.well-known/jwks.json` | In `oauth.rs`, reads EC public key |
| 2.3 | `/oauth/userinfo` | In `oauth.rs`, scope-based claim filtering |

### Phase 3: Token Lifecycle (P1)

| Step | Component | Files |
|------|-----------|-------|
| 3.1 | `/oauth/revoke` | In `oauth.rs` |
| 3.2 | `/oauth/introspect` | In `oauth.rs` |
| 3.3 | Refresh token reuse detection | In refresh token grant handler |
| 3.4 | Token cleanup job | Background cron: remove expired refresh tokens |

### Phase 4: Client Credentials & M2M (P1)

| Step | Component | Files |
|------|-----------|-------|
| 4.1 | Client credentials grant | In `/oauth/token` handler |
| 4.2 | M2M capsule action | New capsule: `oauth:client_credentials` |
| 4.3 | Service token claims | `OAuthAccessTokenClaims` with `session_type: "service"` |

### Phase 5: Capsule Integration (P1)

| Step | Component | Files |
|------|-----------|-------|
| 5.1 | `oauth:authorize` capsule action | Define + compile default capsule |
| 5.2 | Extended RuntimeContext | Modify `wasm_host.rs` RuntimeContext struct |
| 5.3 | OAuth scope as capsule input | Pipe `granted_scopes` into context_values |
| 5.4 | Resource server middleware update | Modify `eiaa_authz.rs` to extract OAuth token fields |

### Phase 6: Frontend (P1)

| Step | Component | Files |
|------|-----------|-------|
| 6.1 | Consent page UI | New: `frontend/src/pages/ConsentPage.tsx` |
| 6.2 | OAuth error pages | Error display for invalid_client, access_denied, etc. |
| 6.3 | Consent management UI | User settings: view/revoke app authorizations |

---

## Appendix A: File Inventory — What Already Exists

| Component | File | Reuse Level |
|-----------|------|-------------|
| App model (client_id, secret, redirects, flows) | `org_manager/src/models/mod.rs` | **100%** — use as-is |
| App CRUD + secret rotation | `org_manager/src/services/app_service.rs` | **100%** — use as-is |
| Admin app API (PublicApplication DTO) | `api_server/src/routes/admin/apps.rs` | **100%** — use as-is |
| JWT generation (ES256) | `auth_core/src/jwt.rs` | **90%** — add OAuthAccessTokenClaims |
| Session creation | `identity_engine/src/services/user_service.rs` | **80%** — add OAuth session type |
| Risk Engine | `risk_engine/src/` | **100%** — called from capsule middleware |
| Capsule compiler | `capsule_compiler/src/lib.rs` | **100%** — compile OAuth policy capsules |
| Capsule runtime | `capsule_runtime/src/wasm_host.rs` | **90%** — extend RuntimeContext |
| EIAA middleware | `api_server/src/middleware/eiaa_authz.rs` | **90%** — add OAuth token classification |
| PKCE implementation | `identity_engine/src/services/oauth_service.rs` | **80%** — reuse S256 logic |
| Redis state management | `oauth_service.rs` + `auth_flow.rs` | **80%** — same pattern for auth codes |

## Appendix B: Relevant RFCs

| RFC | Title | Relevance |
|-----|-------|-----------|
| RFC 6749 | The OAuth 2.0 Authorization Framework | Core spec — endpoints, grants, tokens |
| RFC 6750 | Bearer Token Usage | How to send access tokens in requests |
| RFC 7636 | PKCE | Code challenge/verifier for public clients |
| RFC 7009 | Token Revocation | /oauth/revoke endpoint |
| RFC 7662 | Token Introspection | /oauth/introspect endpoint |
| RFC 8414 | Authorization Server Metadata | .well-known/oauth-authorization-server |
| RFC 9126 | Pushed Authorization Requests (PAR) | Future: client pushes auth params directly |
| RFC 9449 | DPoP | Future: proof-of-possession tokens |
| OIDC Core | OpenID Connect Core 1.0 | /userinfo, id_token, standard scopes |
| OIDC Discovery | OpenID Connect Discovery 1.0 | .well-known/openid-configuration |

## Appendix C: Key Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Token format | JWT (ES256) | Consistent with internal tokens, stateless verification at resource server |
| Scope in JWT? | Yes, as consent metadata | Not authority — capsule still decides. Needed for OIDC compliance |
| EIAA invariant test | Update to allow `scope`, block `role`/`permission`/`entitlement` | Or use separate `OAuthAccessTokenClaims` struct (preferred) |
| Refresh token format | Opaque (not JWT) | Must be revocable via DB lookup |
| Auth code storage | Redis (10-min TTL) | Ephemeral, single-use, auto-expire |
| Client secret verification | Constant-time SHA-256 comparison | Timing attack prevention |
| PKCE for public clients | Mandatory (reject without code_challenge) | RFC 7636, OAuth Security BCP |
| Implicit grant | Not implemented | Deprecated by OAuth 2.1, security risk |
| Resource Owner Password grant | Not implemented | Anti-pattern, security risk |
| Refresh token rotation | One-time use with reuse detection | Family revocation on replay |
| Consent storage | PostgreSQL with EIAA decision_ref | Audit trail for consent decisions |
