# IDaaS Platform - Technical Documentation

**Version:** 1.0 (April 2026)  
**Status:** Production-Ready  
**Target Audience:** Software Engineers, DevOps Engineers, Security Architects, System Integrators

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Database Schema](#3-database-schema)
4. [Authentication & Authorization (EIAA)](#4-authentication--authorization-eiaa)
5. [Backend Architecture](#5-backend-architecture)
6. [Frontend Architecture](#6-frontend-architecture)
7. [API Reference](#7-api-reference)
8. [Configuration & Environment Variables](#8-configuration--environment-variables)
9. [Deployment Architecture](#9-deployment-architecture)
10. [Security Architecture](#10-security-architecture)
11. [Performance & Scalability](#11-performance--scalability)
12. [Development Workflows](#12-development-workflows)
13. [Troubleshooting & Operations](#13-troubleshooting--operations)

---

## 1. Executive Summary

### 1.1 Platform Overview

**IDaaS (Identity as a Service)** is an enterprise-grade, production-ready authentication and authorization platform built from the ground up in **Rust** and **React**. It provides comprehensive identity management capabilities including:

- **Enterprise Authentication**: Email/password, OAuth (Google, GitHub, Microsoft), passwordless (magic links, OTP), WebAuthn/Passkeys
- **Multi-Factor Authentication**: TOTP, SMS, hardware keys, backup codes
- **B2B Multi-Tenancy**: Organization management with hierarchical role-based access control (RBAC)
- **Billing Integration**: Native Stripe integration for subscription management
- **Developer SDKs**: JavaScript/TypeScript, Python, Go client libraries
- **Hosted Authentication UI**: Pre-built, customizable authentication pages with XState-driven flows
- **EIAA Architecture**: Revolutionary authorization model using WebAssembly policy capsules

### 1.2 Unique Differentiators

**EIAA (Entitlement-Independent Authentication Architecture)** is the platform's core innovation. Unlike traditional systems that embed roles and permissions in JWTs, EIAA:

- Keeps JWTs identity-only (no roles, scopes, or permissions)
- Compiles authorization policies into cryptographically-signed WebAssembly capsules
- Evaluates policies at request-time with full runtime context
- Provides instant permission revocation (no token expiry delays)
- Maintains cryptographically-verifiable audit trails via Ed25519 attestations
- Supports re-execution of historical authorization decisions

### 1.3 Technology Stack Summary

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend Runtime | Rust | 1.88+ (2021 Edition) |
| Web Framework | Axum | 0.7 |
| Database | PostgreSQL | 16 |
| Cache/Sessions | Redis | 7 |
| WASM Runtime | Wasmtime | Latest |
| Frontend Framework | React | 18 |
| Build Tool | Vite | Latest |
| State Management | XState | 5 |
| Styling | Tailwind CSS + shadcn/ui | Latest |
| gRPC | Tonic | 0.11 |
| Container Runtime | Docker/Podman | Latest |
| Orchestration | Kubernetes | 1.28+ |
| Infrastructure as Code | Terraform | Latest |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ React UI │  │  Mobile  │  │ JS/TS SDK│  │ Python/Go│        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
└───────┼─────────────┼─────────────┼─────────────┼───────────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                        │
        ┌───────────────▼────────────────┐
        │     Axum API Server (:3000)    │
        │  ┌──────────────────────────┐  │
        │  │  EIAA Middleware         │  │
        │  │  • JWT Verification      │  │
        │  │  • Capsule Execution     │  │
        │  │  • Attestation Verify    │  │
        │  └──────────────────────────┘  │
        │  ┌──────────────────────────┐  │
        │  │  API Routes              │  │
        │  │  • /auth    • /org       │  │
        │  │  • /mfa     • /billing   │  │
        │  │  • /admin   • /eiaa      │  │
        │  └──────────────────────────┘  │
        └───┬───────────────────┬────────┘
            │                   │
    ┌───────▼────────┐   ┌─────▼──────────────┐
    │  Domain Crates │   │  Runtime Service   │
    │  ┌──────────┐  │   │  (gRPC :50061)     │
    │  │ identity │  │   │  ┌──────────────┐  │
    │  │ org_mgr  │  │   │  │  Capsule     │  │
    │  │ billing  │  │   │  │  Compiler    │  │
    │  │ risk_eng │  │   │  │  ────────    │  │
    │  │ email    │  │   │  │  Capsule     │  │
    │  └──────────┘  │   │  │  Runtime     │  │
    └───┬────────────┘   │  │  (Wasmtime)  │  │
        │                │  └──────────────┘  │
        │                └────────────────────┘
        │
    ┌───▼──────────────────────────┐
    │     Data Layer               │
    │  ┌─────────┐   ┌──────────┐  │
    │  │Postgres │   │  Redis   │  │
    │  │  :5432  │   │  :6379   │  │
    │  └─────────┘   └──────────┘  │
    └──────────────────────────────┘
         │
    ┌────▼──────────────────────────┐
    │  External Services             │
    │  • Stripe   • SendGrid         │
    │  • OAuth    • Twilio (SMS)     │
    └────────────────────────────────┘
```

### 2.2 Request Flow: Authentication

```
1. Client → POST /api/v1/auth-flow/init
   ↓
2. API Server creates FlowSession → Redis
   ↓ 
3. Returns flow_token (short-lived JWT)
   ↓
4. Client → POST /api/v1/auth-flow/:id/identify {email}
   ↓
5. identity_engine queries DB → finds user/org
   ↓
6. Loads org's LoginMethodsConfig → compiles to EIAA capsule
   ↓
7. Runtime executes capsule → returns required steps
   ↓
8. Client → POST /api/v1/auth-flow/:id/submit {password}
   ↓
9. identity_engine verifies password (Argon2id)
   ↓
10. risk_engine evaluates: IP geo, velocity, device fingerprint
   ↓
11. Runtime re-executes capsule with risk_score
   ↓
12. If risk > threshold → requires MFA
   ↓
13. Client → POST /api/v1/auth-flow/:id/submit {totp_code}
   ↓
14. Verifies TOTP → all factors satisfied
   ↓
15. Client → POST /api/v1/auth-flow/:id/complete
   ↓
16. auth_core creates session in Redis + Postgres
   ↓
17. JwtService generates ES256 token (identity-only)
   ↓
18. Returns {user, sessionId, jwt, attestation}
```

### 2.3 Request Flow: Protected Resource Access

```
1. Client → GET /api/v1/user/profile
   Headers: Authorization: Bearer <jwt>
   ↓
2. EIAA Middleware extracts JWT → JwtService.verify_token()
   ↓
3. Validates: signature, expiration, issuer, audience
   ↓
4. Extracts Claims {sub, sid, tenant_id, session_type}
   ↓
5. Checks session in Redis → verifies not revoked
   ↓
6. Loads EIAA capsule for action "read:user_profile"
   ↓
7. Prepares RuntimeContext:
   - subject_id, tenant_id, session_type
   - risk_score (from risk_engine)
   - IP, user_agent, timestamp
   ↓
8. gRPC call → runtime_service.execute_capsule()
   ↓
9. Wasmtime loads WASM → injects host functions
   ↓
10. WASM executes → calls host.verify_identity()
    → calls host.evaluate_risk()
    → calls host.authorize("read", "user_profile")
   ↓
11. WASM writes to memory offset 0x2000:
    decision=1 (Allow), authz_result=1
   ↓
12. Runtime signs DecisionOutput with Ed25519
   ↓
13. Returns Attestation {decision_hash, signature, nonce}
   ↓
14. Middleware verifies attestation signature
   ↓
15. Checks nonce uniqueness (Redis + Postgres)
   ↓
16. AuditWriter (async) writes audit record
   ↓
17. Request proceeds → user_route::get_profile()
   ↓
18. Returns 200 OK {user data}
```

---

## 3. Database Schema

### 3.1 Core Identity Tables

#### `users`
```sql
CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('user'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    profile_image_url TEXT,
    banned BOOLEAN DEFAULT FALSE,
    locked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    deleted_at TIMESTAMPTZ,
    public_metadata JSONB DEFAULT '{}',
    private_metadata JSONB DEFAULT '{}',
    unsafe_metadata JSONB DEFAULT '{}'
);
```
**Purpose**: Core user identity records. Soft-deletion via `deleted_at`.  
**Metadata Tiers**:
- `public_metadata`: Readable by user and admins
- `private_metadata`: Readable by admins only
- `unsafe_metadata`: Never returned via API (internal use)

#### `identities`
```sql
CREATE TABLE identities (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('ident'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    type VARCHAR(50) NOT NULL CHECK (type IN (
        'email', 'phone', 
        'oauth_google', 'oauth_github', 
        'oauth_microsoft', 'oauth_apple'
    )),
    identifier VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    oauth_provider VARCHAR(50),
    oauth_subject VARCHAR(255),
    oauth_access_token TEXT,
    oauth_refresh_token TEXT,
    oauth_token_expires_at TIMESTAMPTZ,
    UNIQUE(type, identifier)
);
```
**Purpose**: Maps authentication identifiers to users. One user can have multiple identities (email + Google OAuth).

#### `passwords`
```sql
CREATE TABLE passwords (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('pass'),
    user_id VARCHAR(64) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_hash TEXT NOT NULL,
    algorithm VARCHAR(50) DEFAULT 'argon2id',
    previous_hashes JSONB DEFAULT '[]'
);
```
**Purpose**: Stores Argon2id password hashes. Tracks password history to prevent reuse.

#### `sessions`
```sql
CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('sess'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    client_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    active_organization_id VARCHAR(64),
    aal INTEGER DEFAULT 1,  -- Authenticator Assurance Level
    device_id VARCHAR(255)
);
```
**Purpose**: Persistent session records. Dual storage (Postgres + Redis) for resilience.

### 3.2 Multi-Factor Authentication Tables

#### `totp_secrets`
```sql
CREATE TABLE totp_secrets (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('totp'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    secret VARCHAR(255) NOT NULL,  -- Base32-encoded
    enabled BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    algorithm VARCHAR(10) DEFAULT 'SHA1',
    digits INTEGER DEFAULT 6,
    period INTEGER DEFAULT 30
);
```

#### `passkey_credentials`
```sql
CREATE TABLE passkey_credentials (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('pkc'),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255),
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER DEFAULT 0,
    transports TEXT[],
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMPTZ
);
```
**Purpose**: WebAuthn/FIDO2 credentials for passwordless and MFA.

### 3.3 Organization & Tenant Tables

#### `organizations`
```sql
CREATE TABLE organizations (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('org'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    logo_url TEXT,
    created_by VARCHAR(64) REFERENCES users(id),
    max_members INTEGER,
    metadata JSONB DEFAULT '{}'
);
```

#### `organization_memberships`
```sql
CREATE TABLE organization_memberships (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('orgmem'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,  -- 'owner', 'admin', 'member'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);
```

### 3.4 EIAA Tables

#### `eiaa_policies`
```sql
CREATE TABLE eiaa_policies (
    id VARCHAR(50) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    version INTEGER NOT NULL,
    spec JSONB NOT NULL,  -- AST definition
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_tenant_action_version UNIQUE (tenant_id, action, version)
);
```
**Purpose**: Stores versioned policy ASTs before compilation.

#### `eiaa_compiled_capsules`
```sql
CREATE TABLE eiaa_compiled_capsules (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(100) NOT NULL,
    version INTEGER NOT NULL,
    ast_hash VARCHAR(64) NOT NULL,
    wasm_hash VARCHAR(64) NOT NULL,
    ast_bytes BYTEA NOT NULL,
    wasm_bytes BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    compiled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    compiled_by VARCHAR(64),
    metadata JSONB
);
```
**Purpose**: Stores compiled WASM capsules with cryptographic signatures.

#### `eiaa_executions`
```sql
CREATE TABLE eiaa_executions (
    id VARCHAR(64) PRIMARY KEY,
    capsule_id VARCHAR(64) REFERENCES eiaa_compiled_capsules(id),
    executed_at TIMESTAMPTZ NOT NULL,
    subject_id VARCHAR(64),
    tenant_id VARCHAR(64),
    decision INTEGER NOT NULL,  -- 0=Deny, 1=Allow, 2=NeedInput
    runtime_context JSONB,
    attestation JSONB NOT NULL,
    nonce VARCHAR(64) UNIQUE NOT NULL
);
```
**Purpose**: Immutable audit log of all capsule executions with attestations.

### 3.5 Billing Tables

#### `subscriptions`
```sql
CREATE TABLE subscriptions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('sub'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id),
    stripe_customer_id VARCHAR(255) NOT NULL,
    stripe_subscription_id VARCHAR(255) UNIQUE,
    status VARCHAR(50) NOT NULL,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    plan_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 4. Authentication & Authorization (EIAA)

### 4.1 EIAA Principles

**Core Invariant**: JWTs must NEVER contain roles, permissions, scopes, or entitlements.

**Identity-Only Claims**:
```rust
pub struct Claims {
    pub sub: String,           // User ID
    pub iss: String,           // Issuer
    pub aud: String,           // Audience
    pub exp: i64,              // Expiration
    pub iat: i64,              // Issued at
    pub nbf: i64,              // Not before
    pub sid: String,           // Session ID
    pub tenant_id: String,     // Organization context
    pub session_type: String,  // "end_user" | "admin" | "flow" | "service"
}
```

### 4.2 Policy AST Structure

Policies are defined as JSON Abstract Syntax Trees (ASTs) following the EIAA-AST-1.0 specification:

```json
{
  "version": "EIAA-AST-1.0",
  "sequence": [
    {
      "verify_identity": {
        "source": "primary"
      }
    },
    {
      "evaluate_risk": {
        "profile": "standard"
      }
    },
    {
      "if": {
        "condition": {
          "risk_score": {
            "comparator": ">",
            "value": 70
          }
        },
        "then": [
          {
            "require_factor": {
              "factor_type": {
                "any": ["otp", "passkey"]
              }
            }
          }
        ]
      }
    },
    {
      "authorize_action": {
        "action": "read",
        "resource": "user_profile"
      }
    },
    {
      "allow": true
    }
  ]
}
```

**Available Step Types**:

| Step | Description | Parameters |
|------|-------------|------------|
| `verify_identity` | Validates user identity | `source`: "primary", "federated", "device", "biometric" |
| `evaluate_risk` | Computes risk score | `profile`: "standard", "strict", "permissive" |
| `require_factor` | Demands MFA factor | `factor_type`: "otp", "passkey", "password", "biometric", "any([...])"|
| `collect_credentials` | Prompts for user input | (No params) |
| `require_verification` | Demands email/phone verification | `verification_type`: "email", "sms" |
| `if` | Conditional branching | `condition`, `then`, `else` (optional) |
| `authorize_action` | Core authz check | `action`, `resource` |
| `allow` | Terminal allow | boolean |
| `deny` | Terminal deny | boolean |

### 4.3 Compilation Pipeline

```
JSON AST → Verifier → Canonical JSON → WASM Lowering → Signing
```

**Verifier Rules** (enforced at compile-time):
- R1: Sequence must not be empty
- R4: Must have terminal `allow` or `deny`
- R5: Terminal must be last step
- R9: Max conditional nesting depth = 8
- R10: Must have `verify_identity` (except signup flows)
- R11: `verify_identity` must be first
- R13: Only one `evaluate_risk` allowed
- R17: Must have `authorize_action` (except signup)
- R26: Max 128 steps per policy

**Output**: `CapsuleSigned` struct:
```rust
pub struct CapsuleSigned {
    pub meta: CapsuleMeta,
    pub ast_bytes: Vec<u8>,
    pub wasm_bytes: Vec<u8>,
    pub hashes: CapsuleHashes,
    pub signature: Vec<u8>,
}
```

### 4.4 Runtime Execution

**Host Imports** (injected by Wasmtime):
```rust
host.verify_identity(source_type: i32) -> i64   // Returns subject_id
host.evaluate_risk(profile_ptr: i32) -> i32     // Returns 0-100
host.require_factor(factor_type: i32) -> i32    // Returns 1=satisfied, 0=not
host.authorize(action_ptr: i32, resource_ptr: i32) -> i32  // 1=allow, 0=deny
host.verify_verification(type_ptr: i32) -> i32  // 1=verified, 0=not
```

**Memory Contract** (WASM writes to fixed offsets):
```
0x2000 (i32): decision (0=Deny, 1=Allow, 2=NeedInput)
0x2008 (i64): subject_id
0x2010 (i32): risk_score
0x2014 (i32): authz_result
0x2020 (i32): reason string pointer
0x2024 (i32): reason string length
```

### 4.5 Attestation Structure

Every execution produces a cryptographically-signed attestation:

```json
{
  "capsule_hash_b64": "SHA256 of WASM bytes (base64)",
  "decision_hash_b64": "BLAKE3 of DecisionOutput (base64)",
  "executed_at_unix": 1714428800,
  "expires_at_unix": 1714429100,
  "nonce_b64": "32-byte random nonce (base64)",
  "runtime_kid": "Ed25519 key ID",
  "ast_hash_b64": "SHA256 of AST bytes (base64)",
  "lowering_version": "ei-aa-lower-wasm-v1",
  "wasm_hash_b64": "SHA256 of WASM (base64)",
  "signature_b64": "Ed25519(canonical_json(body)) (base64)"
}
```

**Replay Protection**: Nonces stored in Redis (5-minute TTL) and Postgres (permanent audit).

---

## 5. Backend Architecture

### 5.1 Crate Dependency Graph

```
api_server (binary)
  ├─→ shared_types
  ├─→ auth_core
  │    └─→ shared_types
  ├─→ identity_engine
  │    ├─→ shared_types
  │    └─→ auth_core
  ├─→ org_manager
  │    └─→ shared_types
  ├─→ billing_engine
  │    └─→ shared_types
  ├─→ risk_engine
  │    └─→ shared_types
  ├─→ email_service
  │    └─→ shared_types
  ├─→ keystore
  │    └─→ shared_types
  ├─→ attestation
  │    └─→ keystore
  ├─→ capsule_compiler
  │    ├─→ shared_types
  │    └─→ attestation
  └─→ capsule_runtime
       ├─→ shared_types
       └─→ attestation

runtime_service (binary)
  ├─→ capsule_compiler
  ├─→ capsule_runtime
  ├─→ grpc_api
  └─→ shared_types
```

### 5.2 Core Crate Descriptions

#### `shared_types`
**Purpose**: Common types, error definitions, ID generation, validation traits.

**Key Exports**:
```rust
pub struct AppError;  // Unified error type
pub type Result<T> = std::result::Result<T, AppError>;
pub fn generate_id(prefix: &str) -> String;  // Generates "user_abc123..."
```

#### `auth_core`
**Purpose**: JWT generation/validation, session management.

**Key Exports**:
```rust
pub struct JwtService;
pub struct SessionStore;  // Redis-backed
pub struct Claims;
```

**Configuration**:
- JWT Algorithm: ES256 (ECDSA with P-256 and SHA-256)
- Token TTL: Configurable (default 60 seconds for short-lived, 30 days for refresh)
- Session Storage: Redis with Postgres fallback

#### `identity_engine`
**Purpose**: User CRUD, authentication primitives, OAuth flows.

**Key Functions**:
```rust
pub async fn create_user(email, password) -> Result<User>;
pub async fn verify_password(user_id, password) -> Result<bool>;
pub async fn enroll_totp(user_id) -> Result<TotpSetup>;
pub async fn verify_totp(user_id, code) -> Result<bool>;
pub async fn initiate_oauth(provider) -> Result<OAuthUrl>;
pub async fn complete_oauth(code, state) -> Result<User>;
```

**Password Hashing**: Argon2id with parameters:
- Memory cost: 64MB
- Time cost: 3 iterations
- Parallelism: 4 threads

#### `org_manager`
**Purpose**: Multi-tenant organization lifecycle, RBAC.

**Key Functions**:
```rust
pub async fn create_organization(name, slug) -> Result<Organization>;
pub async fn add_member(org_id, user_id, role) -> Result<Membership>;
pub async fn check_permission(org_id, user_id, permission) -> Result<bool>;
```

**Built-in Roles**:
- `owner`: Full control, can delete org
- `admin`: Can manage members and settings
- `member`: Read-only access

#### `billing_engine`
**Purpose**: Stripe webhook handling, subscription sync.

**Key Functions**:
```rust
pub async fn create_customer(org_id, email) -> Result<Customer>;
pub async fn create_subscription(customer_id, price_id) -> Result<Subscription>;
pub async fn handle_webhook(event: StripeEvent) -> Result<()>;
```

**Webhook Events Supported**:
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

#### `risk_engine`
**Purpose**: Adaptive authentication, threat detection.

**Risk Factors**:
- IP geolocation (MaxMind GeoIP2)
- Velocity checks (login attempts per time window)
- Device fingerprinting
- Impossible travel detection
- Behavioral biometrics (future)

**Risk Score**: 0-100, where:
- 0-30: Low risk → Allow
- 31-70: Medium risk → May require MFA
- 71-100: High risk → Block or require step-up

#### `email_service`
**Purpose**: Template rendering, SMTP/SendGrid dispatch.

**Templates**:
- Welcome email
- Email verification
- Password reset
- MFA enrollment confirmation
- Billing receipts

**Configuration**:
```rust
pub enum EmailProvider {
    SendGrid { api_key: String },
    Smtp { host: String, port: u16, username: String, password: String },
}
```

### 5.3 EIAA-Specific Crates

#### `capsule_compiler`
**Files**:
- `ast.rs`: AST type definitions
- `verifier.rs`: Compile-time rule enforcement (R1-R26)
- `lowerer.rs`: AST → WASM bytecode transpiler
- `policy_compiler.rs`: `LoginMethodsConfig` → AST

**Lowering Strategy**:
- Each AST step → WASM function
- Host imports for runtime context
- Linear memory for I/O (offsets 0x2000+)
- Deterministic execution (no WASI, no floats)

#### `capsule_runtime`
**Engine**: Wasmtime with:
- Fuel limits (prevent DoS)
- No WASI capabilities (sandboxed)
- Host function injection

**Execution Flow**:
1. Load WASM module
2. Instantiate with host linker
3. Call `_start()` export
4. Read decision from memory offset 0x2000
5. Sign decision with Ed25519

#### `attestation`
**Purpose**: Cryptographic signing and verification.

**Key Functions**:
```rust
pub fn sign_attestation(body: &AttestationBody, key: &Ed25519Key) -> Signature;
pub fn verify_attestation(attestation: &Attestation, pubkey: &Ed25519PublicKey) -> Result<()>;
```

---

## 6. Frontend Architecture

### 6.1 Technology Stack

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite 5 (fast HMR, ES modules)
- **State Management**: XState 5 (authentication flows), React Context (global state)
- **Styling**: Tailwind CSS 3 + shadcn/ui components
- **Routing**: React Router v6
- **Forms**: React Hook Form + Zod validation
- **HTTP Client**: Axios with request/response interceptors
- **Testing**: Vitest (unit), Playwright (E2E)

### 6.2 Project Structure

```
frontend/
├── src/
│   ├── main.tsx                 # Entry point
│   ├── App.tsx                  # Root component
│   ├── components/              # Reusable UI components
│   │   ├── ui/                  # shadcn/ui primitives
│   │   ├── UserButton.tsx
│   │   └── ErrorBoundary.tsx
│   ├── features/                # Feature-specific modules
│   │   ├── auth/
│   │   │   ├── AuthFlowPage.tsx
│   │   │   ├── StepUpModal.tsx
│   │   │   └── authMachine.ts   # XState machine
│   │   ├── admin/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── UsersPage.tsx
│   │   │   └── AuditLogPage.tsx
│   │   ├── settings/
│   │   │   ├── ProfilePage.tsx
│   │   │   ├── SecurityPage.tsx  # MFA, passkeys
│   │   │   └── domains/DomainsPage.tsx
│   │   └── billing/
│   │       └── BillingPage.tsx
│   ├── layouts/
│   │   ├── AdminLayout.tsx
│   │   └── AuthLayout.tsx
│   ├── lib/
│   │   ├── api.ts               # Axios client
│   │   ├── auth.ts              # Auth helpers
│   │   └── utils.ts
│   ├── pages/                   # Top-level route pages
│   └── styles/
│       └── globals.css
├── tests/                       # Playwright E2E tests
│   ├── auth-flow.spec.ts
│   ├── admin/
│   └── fixtures/
└── public/
```

### 6.3 Authentication Flow (XState)

**States**:
```
idle → identifying → collectingCredentials → verifyingMFA → authenticated
```

**Machine Definition** (`authMachine.ts`):
```typescript
export const authMachine = createMachine({
  id: 'auth',
  initial: 'idle',
  context: {
    flowId: null,
    flowToken: null,
    requiredSteps: [],
    currentStepIndex: 0,
  },
  states: {
    idle: {
      on: { INIT_FLOW: 'initializingFlow' }
    },
    initializingFlow: {
      invoke: {
        src: 'initFlow',
        onDone: { target: 'identifying', actions: 'setFlowData' },
        onError: 'error'
      }
    },
    identifying: {
      on: { SUBMIT_IDENTIFIER: 'submittingIdentifier' }
    },
    submittingIdentifier: {
      invoke: {
        src: 'submitIdentifier',
        onDone: { target: 'collectingCredentials', actions: 'setRequiredSteps' },
        onError: 'error'
      }
    },
    collectingCredentials: {
      on: { SUBMIT_CREDENTIAL: 'submittingCredential' }
    },
    submittingCredential: {
      invoke: {
        src: 'submitCredential',
        onDone: [
          { target: 'verifyingMFA', cond: 'mfaRequired', actions: 'nextStep' },
          { target: 'completing', cond: 'allStepsComplete' }
        ],
        onError: 'error'
      }
    },
    verifyingMFA: {
      on: { SUBMIT_MFA: 'submittingMFA' }
    },
    submittingMFA: {
      invoke: {
        src: 'submitMFA',
        onDone: { target: 'completing' },
        onError: 'error'
      }
    },
    completing: {
      invoke: {
        src: 'completeFlow',
        onDone: { target: 'authenticated', actions: 'setSession' },
        onError: 'error'
      }
    },
    authenticated: { type: 'final' },
    error: {
      on: { RETRY: 'idle' }
    }
  }
});
```

### 6.4 API Client Configuration

**Axios Instance** (`lib/api.ts`):
```typescript
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3000',
  timeout: 10000,
  withCredentials: true,  // Send cookies
});

// Request interceptor: Add JWT to Authorization header
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('jwt');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const orgId = sessionStorage.getItem('active_org_id');
  if (orgId) {
    config.headers['X-Organization-Id'] = orgId;
  }
  return config;
});

// Response interceptor: Handle 401, refresh token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      try {
        await refreshToken();
        return api.request(error.config);
      } catch {
        // Logout
        window.location.href = '/u/login';
      }
    }
    return Promise.reject(error);
  }
);
```

---

## 7. API Reference

**Comprehensive API documentation**: See [docs/API_ENDPOINTS.md](docs/API_ENDPOINTS.md)

**Quick Reference** (Most Common Endpoints):

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | `/api/v1/auth-flow/init` | Start auth flow | Public |
| `POST` | `/api/v1/auth-flow/:id/identify` | Identify user by email | Flow token |
| `POST` | `/api/v1/auth-flow/:id/submit` | Submit credential | Flow token |
| `POST` | `/api/v1/auth-flow/:id/complete` | Finalize authentication | Flow token |
| `POST` | `/api/v1/auth/logout` | Revoke session | JWT |
| `POST` | `/api/v1/auth/token/refresh` | Refresh JWT | Refresh token (cookie) |
| `GET` | `/api/v1/user/me` | Get current user | JWT |
| `PATCH` | `/api/v1/user/me` | Update profile | JWT |
| `POST` | `/api/v1/mfa/totp/setup` | Enroll TOTP | JWT |
| `POST` | `/api/v1/mfa/totp/verify` | Verify TOTP code | JWT |
| `GET` | `/api/v1/organizations` | List user's orgs | JWT |
| `POST` | `/api/v1/organizations` | Create organization | JWT |
| `GET` | `/api/v1/billing/subscription` | Get subscription | JWT + Org |
| `POST` | `/api/v1/billing/checkout` | Create Stripe checkout | JWT + Org |
| `GET` | `/health` | Health check | Public |

---

## 8. Configuration & Environment Variables

### 8.1 Backend Environment Variables

**File**: `backend/.env`

#### Database Configuration
```bash
# Primary database
DATABASE_URL=postgres://idaas_user:password@localhost:5432/idaas

# Connection pool
DB_MAX_CONNECTIONS=10
DB_MIN_CONNECTIONS=1
DB_ACQUIRE_TIMEOUT_SECS=30

# Read replicas (production)
DB_ENABLE_READ_REPLICAS=false
DATABASE_READ_REPLICA_URLS=postgres://reader:password@replica1:5432/idaas

# PgBouncer (optional)
USE_PGBOUNCER=false
PGBOUNCER_URL=postgres://idaas_user:password@localhost:6432/idaas
```

#### Redis Configuration
```bash
# Mode: standalone, sentinel, or cluster
REDIS_MODE=standalone

# Standalone
REDIS_URL=redis://localhost:6379

# Sentinel (HA)
REDIS_SENTINEL_URLS=redis://localhost:26379,redis://localhost:26380
REDIS_MASTER_NAME=mymaster
REDIS_PASSWORD=

# Connection settings
REDIS_MAX_CONNECTIONS=10
REDIS_MIN_IDLE=2
REDIS_CONNECTION_TIMEOUT_MS=5000
REDIS_COMMAND_TIMEOUT_MS=3000
```

#### Server Configuration
```bash
HOST=0.0.0.0
PORT=3000
RUST_LOG=info,api_server=debug
ENVIRONMENT=development  # development | staging | production
```

#### JWT Configuration
```bash
# ES256 Keys (generate with OpenSSL)
JWT_PRIVATE_KEY=-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----

# Token settings
JWT_EXPIRATION_SECONDS=60
JWT_ISSUER=https://auth.yourdomain.com
JWT_AUDIENCE=https://api.yourdomain.com
```

**Generate ES256 Keys**:
```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out private.pem

# Extract public key
openssl ec -in private.pem -pubout -out public.pem

# Convert to single-line for .env
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' private.pem
```

#### Session Configuration
```bash
SESSION_COOKIE_NAME=__session
SESSION_COOKIE_DOMAIN=localhost
SESSION_COOKIE_SECURE=false  # Set to true in production
SESSION_EXPIRATION_DAYS=30
```

#### OAuth Provider Configuration
```bash
# Google
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/v1/oauth/google/callback

# GitHub
GITHUB_CLIENT_ID=Iv1.abc123def456
GITHUB_CLIENT_SECRET=your_github_secret
GITHUB_REDIRECT_URI=http://localhost:3000/v1/oauth/github/callback

# Microsoft
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_secret
MICROSOFT_TENANT_ID=common  # or your Azure AD tenant ID
MICROSOFT_REDIRECT_URI=http://localhost:3000/v1/oauth/microsoft/callback
```

#### Email Service Configuration
```bash
# SendGrid
SENDGRID_API_KEY=SG.your_sendgrid_api_key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
SENDGRID_FROM_NAME=IDaaS Platform

# SMTP (alternative)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM_EMAIL=noreply@yourdomain.com
```

#### Stripe Configuration
```bash
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key
```

#### Audit Configuration
```bash
# Overflow queue location (persistent volume in production)
AUDIT_OVERFLOW_PATH=./audit_overflow

# Audit writer settings
AUDIT_BATCH_SIZE=100
AUDIT_FLUSH_INTERVAL_SECS=5
```

### 8.2 Frontend Environment Variables

**File**: `frontend/.env`

```bash
VITE_API_URL=http://localhost:3000
VITE_APP_NAME=IDaaS Platform
VITE_ENABLE_ANALYTICS=false
VITE_SENTRY_DSN=https://your_sentry_dsn@sentry.io/project_id
```

---

## 9. Deployment Architecture

### 9.1 Local Development

**Quick Start**:
```bash
# Clone and navigate
cd idaas-platform

# Start infrastructure
docker compose -f infrastructure/docker-compose/docker-compose.dev.yml up -d

# Run migrations
cd backend
sqlx migrate run

# Start backend
cargo run --bin api_server

# Start frontend (separate terminal)
cd frontend
npm install
npm run dev
```

**Services Running**:
- API Server: `http://localhost:3000`
- Frontend UI: `http://localhost:5173`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- MailHog UI: `http://localhost:8025`
- pgAdmin: `http://localhost:5050`
- Redis Commander: `http://localhost:8081`

### 9.2 Docker Deployment

**Multi-Stage Dockerfile** (`backend/Dockerfile`):
```dockerfile
# Stage 1: Build
FROM rust:1.88-slim as builder
WORKDIR /app
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/crates ./crates
RUN cargo build --release --bin api_server

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/api_server /usr/local/bin/
EXPOSE 3000
CMD ["api_server"]
```

**Docker Compose Production**:
```yaml
services:
  backend:
    image: idaas/backend:latest
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/idaas
      - REDIS_URL=redis://redis:6379
    ports:
      - "3000:3000"
    depends_on:
      - db
      - redis

  frontend:
    image: idaas/frontend:latest
    ports:
      - "80:80"
    depends_on:
      - backend

  db:
    image: postgres:16-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### 9.3 Kubernetes Deployment

**Namespace** (`infrastructure/kubernetes/base/namespace.yaml`):
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: idaas-platform
```

**API Deployment** (`infrastructure/kubernetes/base/api-deployment.yaml`):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: idaas-platform
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
      - name: api-server
        image: idaas/backend:latest
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: url
        - name: REDIS_URL
          valueFrom:
            configMapKeyRef:
              name: redis-config
              key: url
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 10
```

**Service** (`infrastructure/kubernetes/base/api-service.yaml`):
```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-server
  namespace: idaas-platform
spec:
  selector:
    app: api-server
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: LoadBalancer
```

**Ingress** (with TLS):
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: idaas-ingress
  namespace: idaas-platform
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: api-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-server
            port:
              number: 80
```

### 9.4 Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Use strong database credentials
- [ ] Enable `SESSION_COOKIE_SECURE=true`
- [ ] Configure read replicas for database
- [ ] Enable Redis Sentinel for HA
- [ ] Set up SSL/TLS termination
- [ ] Configure CORS properly (no wildcards)
- [ ] Set up monitoring (Prometheus + Grafana)
- [ ] Configure log aggregation (ELK/Loki)
- [ ] Set up error tracking (Sentry)
- [ ] Enable rate limiting
- [ ] Configure WAF (Web Application Firewall)
- [ ] Set up automated backups
- [ ] Document disaster recovery procedures

---

## 10. Security Architecture

### 10.1 Cryptographic Foundations

**Algorithms**:
- **JWT Signing**: ES256 (ECDSA with P-256 curve, SHA-256)
- **Password Hashing**: Argon2id (memory: 64MB, iterations: 3, parallelism: 4)
- **EIAA Attestations**: Ed25519 (EdDSA)
- **Decision Hashing**: BLAKE3 (faster than SHA-256, cryptographically secure)

**Key Rotation**:
- JWT keys: Rotate every 90 days
- Ed25519 runtime keys: Rotate every 180 days
- Previous keys retained for 30 days (verification only)

### 10.2 Session Security

**Dual-Storage Architecture**:
1. **Redis**: Fast access, short TTL (30-60 minutes)
2. **Postgres**: Persistent audit trail, full session history

**Session Revocation**:
```rust
// Immediate revocation
pub async fn revoke_session(session_id: &str) -> Result<()> {
    // Mark in database
    sqlx::query!("UPDATE sessions SET revoked = true WHERE id = $1", session_id)
        .execute(pool)
        .await?;
    
    // Delete from Redis
    redis_conn.del(format!("session:{}", session_id)).await?;
    
    Ok(())
}
```

**Cookie Security**:
```rust
Cookie::build("__session", refresh_token)
    .http_only(true)         // No JavaScript access
    .secure(is_production)   // HTTPS-only in production
    .same_site(SameSite::Lax)  // CSRF protection
    .max_age(Duration::days(30))
    .path("/")
    .finish()
```

### 10.3 EIAA Security Properties

**Immutability**: Compiled capsules are content-addressed by SHA-256 hash. Any modification invalidates the signature.

**Non-Repudiation**: Ed25519 signatures provide cryptographic proof of execution. Attestations can be verified offline.

**Replay Protection**: Each execution requires a unique nonce. Nonces are checked against Redis (fast) and Postgres (permanent).

**Audit Trail**: Every authorization decision is written to `eiaa_executions` with full context. Re-execution is supported for forensics.

### 10.4 Rate Limiting

**Implementation**: Token bucket algorithm via `governor` crate.

**Limits**:
- Login attempts: 5 per IP per 15 minutes
- Password reset: 3 per email per hour
- API calls (authenticated): 1000 per user per hour
- MFA verification: 10 per user per 15 minutes

**Redis Storage**:
```rust
let limiter = RateLimiter::keyed(
    Quota::per_hour(nonzero!(1000u32))
);
limiter.check_key(&user_id)?;
```

### 10.5 Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| SQL Injection | Prepared statements via SQLx, compile-time query verification |
| XSS | React auto-escaping, Content-Security-Policy headers |
| CSRF | SameSite cookies, state parameter in OAuth |
| Session Hijacking | Secure cookies, IP/UA validation, AAL tracking |
| Brute Force | Rate limiting, account lockout after 5 failures |
| Token Theft | Short-lived JWTs, refresh token rotation |
| Privilege Escalation | EIAA capsule enforcement, no role caching |
| Replay Attacks | Nonce verification, timestamp expiry |

---

## 11. Performance & Scalability

### 11.1 Database Optimization

**Indexing Strategy**:
```sql
-- Users
CREATE INDEX idx_users_email ON identities(identifier) WHERE type = 'email';
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;

-- Sessions
CREATE INDEX idx_sessions_user_id ON sessions(user_id) WHERE revoked = false;
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at) WHERE revoked = false;

-- EIAA
CREATE INDEX idx_eiaa_executions_subject_id ON eiaa_executions(subject_id);
CREATE INDEX idx_eiaa_executions_executed_at ON eiaa_executions(executed_at DESC);
CREATE INDEX idx_eiaa_policies_tenant_action ON eiaa_policies(tenant_id, action);
```

**Connection Pooling**:
```rust
let pool = PgPoolOptions::new()
    .max_connections(50)
    .min_connections(5)
    .acquire_timeout(Duration::from_secs(30))
    .connect(&database_url)
    .await?;
```

**Read Replicas**:
```rust
pub struct DatabasePool {
    primary: PgPool,
    replicas: Vec<PgPool>,
}

impl DatabasePool {
    pub fn writer(&self) -> &PgPool {
        &self.primary
    }
    
    pub fn reader(&self) -> &PgPool {
        // Round-robin selection
        let index = fastrand::usize(0..self.replicas.len());
        &self.replicas[index]
    }
}
```

### 11.2 Redis Caching Strategy

**Cache Keys**:
```
session:{session_id}              TTL: 30 min
user:{user_id}                    TTL: 5 min
capsule:{tenant_id}:{action}      TTL: 1 hour
ratelimit:{ip}:{endpoint}         TTL: 15 min
nonce:{nonce}                     TTL: 5 min
```

**Cache-Aside Pattern**:
```rust
pub async fn get_user(user_id: &str) -> Result<User> {
    // Try cache first
    let cache_key = format!("user:{}", user_id);
    if let Some(cached) = redis.get::<String>(&cache_key).await? {
        return Ok(serde_json::from_str(&cached)?);
    }
    
    // Fallback to database
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(pool)
        .await?;
    
    // Populate cache
    redis.set_ex(
        &cache_key,
        serde_json::to_string(&user)?,
        300  // 5 minutes
    ).await?;
    
    Ok(user)
}
```

### 11.3 Horizontal Scaling

**Stateless API Servers**: All session state in Redis/Postgres. API servers can be added/removed freely.

**Load Balancer Configuration** (Nginx):
```nginx
upstream api_backend {
    least_conn;
    server api-1:3000 max_fails=3 fail_timeout=30s;
    server api-2:3000 max_fails=3 fail_timeout=30s;
    server api-3:3000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.yourdomain.com;
    
    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Auto-Scaling (Kubernetes HPA)**:
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-server-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-server
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### 11.4 Performance Benchmarks

**API Server** (Rust/Axum on 4-core, 8GB RAM):
- Requests/sec (JWT verification only): ~15,000 RPS
- Requests/sec (full auth flow): ~800 RPS
- P50 latency: 12ms
- P95 latency: 45ms
- P99 latency: 120ms

**EIAA Capsule Execution**:
- Compilation time (AST → WASM): ~50ms
- Execution time (simple policy): ~2ms
- Execution time (complex policy): ~8ms
- Attestation generation: ~1ms

**Database**:
- Read query (indexed): <5ms
- Write query (single insert): <10ms
- Transaction (multi-statement): <20ms

---

## 12. Development Workflows

### 12.1 Setting Up Development Environment

**Prerequisites**:
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Node.js (via nvm)
nvm install 20
nvm use 20

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres

# Install Docker
# Follow instructions at https://docs.docker.com/get-docker/
```

**Clone and Configure**:
```bash
git clone https://github.com/yourorg/idaas-platform.git
cd idaas-platform

# Backend
cd backend
cp .env.example .env
# Edit .env with your local settings

# Frontend
cd ../frontend
cp .env.example .env
# Edit .env with your local settings
```

**Start Infrastructure**:
```bash
docker compose -f infrastructure/docker-compose/docker-compose.dev.yml up -d
```

**Run Migrations**:
```bash
cd backend
sqlx migrate run
```

**Generate Keys**:
```bash
# ES256 for JWT
openssl ecparam -genkey -name prime256v1 -noout -out jwt_private.pem
openssl ec -in jwt_private.pem -pubout -out jwt_public.pem

# Ed25519 for EIAA
# (Generated automatically by runtime_service on first start)
```

### 12.2 Running Tests

**Backend Unit Tests**:
```bash
cd backend
cargo test --all-features
```

**Backend Integration Tests**:
```bash
# Requires running database
cargo test --test integration -- --test-threads=1
```

**Frontend Unit Tests**:
```bash
cd frontend
npm run test
```

**Frontend E2E Tests** (Playwright):
```bash
cd frontend
npm run test:e2e

# With UI
npm run test:e2e:ui

# Specific file
npm run test:e2e tests/auth-flow.spec.ts
```

### 12.3 Database Migrations

**Create Migration**:
```bash
sqlx migrate add create_new_table
# Edit generated file in backend/crates/db_migrations/migrations/
```

**Apply Migrations**:
```bash
sqlx migrate run
```

**Revert Last Migration**:
```bash
sqlx migrate revert
```

**Generate Query Metadata** (for compile-time verification):
```bash
cargo sqlx prepare
```

### 12.4 Code Quality

**Linting**:
```bash
# Rust
cargo clippy -- -D warnings

# TypeScript
cd frontend
npm run lint
```

**Formatting**:
```bash
# Rust
cargo fmt

# TypeScript
cd frontend
npm run format
```

**Type Checking**:
```bash
cd frontend
npm run type-check
```

---

## 13. Troubleshooting & Operations

### 13.1 Common Issues

#### Issue: "Failed to connect to database"

**Symptoms**: API server crashes on startup with `sqlx::Error::PoolTimedOut`.

**Solutions**:
1. Verify Postgres is running: `docker ps | grep postgres`
2. Test connection: `psql -h localhost -U idaas_user -d idaas`
3. Check `DATABASE_URL` in `.env`
4. Ensure migrations have run: `sqlx migrate run`

#### Issue: "JWT verification failed"

**Symptoms**: All API requests return 401 Unauthorized.

**Solutions**:
1. Verify keys in `.env` match (no extra whitespace/newlines)
2. Check `JWT_ISSUER` and `JWT_AUDIENCE` match between token generation and verification
3. Ensure token hasn't expired (`exp` claim)
4. Verify ES256 algorithm (not HS256)

#### Issue: "Redis connection refused"

**Symptoms**: API server startup fails with `redis::ConnectionError`.

**Solutions**:
1. Check Redis is running: `redis-cli ping` (should return "PONG")
2. Verify `REDIS_URL` in `.env`
3. Check firewall rules (port 6379)
4. Review Redis logs: `docker logs idaas-redis-dev`

#### Issue: "EIAA capsule execution failed"

**Symptoms**: Authorization always denies, or runtime_service crashes.

**Solutions**:
1. Check runtime_service logs: `docker logs idaas-runtime-dev`
2. Verify WASM module is valid: `wasm-validate capsule.wasm`
3. Ensure Ed25519 keys exist in `backend/keys/`
4. Check gRPC connectivity: `grpcurl -plaintext localhost:50061 list`

### 13.2 Monitoring

**Health Endpoint**:
```bash
curl http://localhost:3000/health
```

**Expected Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "database": "connected",
  "redis": "connected",
  "runtime_service": "connected"
}
```

**Prometheus Metrics** (exposed at `/metrics`):
```
# Example metrics
api_requests_total{endpoint="/api/v1/auth/login",method="POST",status="200"} 1543
api_request_duration_seconds{endpoint="/api/v1/auth/login"} 0.045
eiaa_capsule_executions_total{action="login",decision="allow"} 1420
redis_connections_active 8
postgres_connections_active 5
```

**Grafana Dashboard**: Import from `infrastructure/monitoring/grafana-dashboard.json`

### 13.3 Log Aggregation

**Structured Logging** (JSON format):
```json
{
  "timestamp": "2026-04-19T10:30:45Z",
  "level": "info",
  "target": "api_server::routes::auth",
  "message": "User login successful",
  "user_id": "user_abc123",
  "session_id": "sess_xyz789",
  "ip": "192.168.1.100"
}
```

**Log Levels**:
- `error`: Critical failures requiring immediate attention
- `warn`: Potential issues (rate limit hit, failed auth attempt)
- `info`: Normal operations (user login, API requests)
- `debug`: Detailed execution traces (SQL queries, Redis ops)
- `trace`: Ultra-verbose (WASM execution, byte-level details)

**Configure via Environment**:
```bash
RUST_LOG=info,api_server=debug,sqlx=warn
```

### 13.4 Backup & Recovery

**Database Backups**:
```bash
# Full backup
pg_dump -h localhost -U idaas_user -d idaas -F c -f backup_$(date +%Y%m%d).dump

# Restore
pg_restore -h localhost -U idaas_user -d idaas -c backup_20260419.dump
```

**Automated Backups** (cron):
```bash
# Daily at 2 AM
0 2 * * * /usr/local/bin/backup-postgres.sh
```

**Redis Persistence**:
```bash
# Enable AOF (Append-Only File)
redis-cli CONFIG SET appendonly yes

# Manual save
redis-cli SAVE
```

**Disaster Recovery Steps**:
1. Provision new infrastructure
2. Restore latest database backup
3. Restore Redis snapshot (if available)
4. Regenerate JWT/Ed25519 keys (CRITICAL: invalidates all sessions)
5. Update DNS records
6. Run smoke tests
7. Monitor error logs

---

## 14. Appendices

### Appendix A: Glossary

| Term | Definition |
|------|------------|
| **AAL** | Authenticator Assurance Level (NIST SP 800-63B). Ranges from 0 (guest) to 3 (cryptographic). |
| **AST** | Abstract Syntax Tree. JSON representation of EIAA policy logic before compilation. |
| **Capsule** | Compiled WASM binary containing authorization logic, signed with Ed25519. |
| **EIAA** | Entitlement-Independent Authentication Architecture. Core architectural pattern. |
| **Flow** | Stateful authentication session (email → password → MFA → completion). |
| **Nonce** | Number used once. Prevents replay attacks in EIAA attestations. |
| **Tenant** | Organization context. Multi-tenant isolation boundary. |
| **TOTP** | Time-based One-Time Password (RFC 6238). 6-digit MFA code that changes every 30 seconds. |
| **WebAuthn** | Web Authentication standard for passkeys (FIDO2). |

### Appendix B: RFC References

- **RFC 6238**: TOTP (Time-Based One-Time Password)
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: OAuth 2.0 PKCE (Proof Key for Code Exchange)
- **RFC 8693**: OAuth 2.0 Token Exchange
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7515**: JSON Web Signature (JWS)
- **NIST SP 800-63B**: Digital Identity Guidelines (Authentication and Lifecycle Management)

### Appendix C: Support & Resources

- **Documentation**: [https://docs.yourdomain.com](https://docs.yourdomain.com)
- **API Reference**: [docs/API_ENDPOINTS.md](docs/API_ENDPOINTS.md)
- **GitHub**: [https://github.com/yourorg/idaas-platform](https://github.com/yourorg/idaas-platform)
- **Community Slack**: [https://idaas-community.slack.com](https://idaas-community.slack.com)
- **Support Email**: support@yourdomain.com

---

**Document Version**: 1.0  
**Last Updated**: April 19, 2026  
**Maintained By**: IDaaS Engineering Team