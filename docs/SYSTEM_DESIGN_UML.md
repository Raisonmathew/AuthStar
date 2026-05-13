# IDaaS System Design UML Diagrams

This document captures the IDaaS platform as a set of UML-style Mermaid diagrams. It is intended to complement [ARCHITECTURE.md](ARCHITECTURE.md) and [TECHNICAL_DOCUMENTATION.md](../TECHNICAL_DOCUMENTATION.md) with a more visual system-design view.

## Design Principles

- JWTs are identity-only. They carry identity context such as subject, session, tenant, and session type, but never roles, permissions, scopes, or entitlements.
- Authorization is evaluated at request time by EIAA policy capsules.
- Web/API clients do not make privileged authorization decisions locally.
- Sessions, policy executions, nonce replay protection, and audit records are server-side concerns.
- Protocol surfaces such as OAuth 2.0, OIDC, SAML, SCIM, API keys, and webhooks remain protocol-compliant while preserving the EIAA invariant.

## 1. System Context Diagram

```mermaid
flowchart TB
    subgraph ClientLayer[Client Layer]
        ReactUI[React Hosted UI]
        AdminConsole[Admin Console]
        JsSdk[JavaScript / TypeScript SDK]
        PyGoSdk[Python / Go SDKs]
        MobileApps[Mobile Applications]
        EnterpriseApps[Enterprise Applications]
    end

    subgraph EdgeLayer[Edge / API Layer]
        ApiServer[Axum API Server\nHTTP :3000]
        SecurityMiddleware[Security Middleware\nCORS, CSRF, Rate Limit, Headers]
        EiaaMiddleware[EIAA Authorization Middleware\nJWT Verify + Capsule Decision]
    end

    subgraph ProtocolLayer[Identity Protocol Surfaces]
        AuthFlow[Hosted Auth Flow\nPassword, MFA, Passkeys]
        OAuthAs[OAuth 2.0 / OIDC AS]
        SamlIdp[SAML IdP]
        Scim[SCIM 2.0]
        ApiKeys[API Keys]
        Webhooks[Webhooks]
    end

    subgraph DomainLayer[Domain Services / Rust Crates]
        AuthCore[auth_core\nJWT + Sessions]
        IdentityEngine[identity_engine\nUsers + Credentials + MFA]
        OrgManager[org_manager\nOrganizations + Memberships]
        BillingEngine[billing_engine\nSubscriptions + Stripe Sync]
        RiskEngine[risk_engine\nRisk Scoring]
        EmailService[email_service\nTransactional Email]
    end

    subgraph EiaaLayer[EIAA Capsule System]
        PolicyBuilder[Policy Builder\nTemplates + AST]
        CapsuleCompiler[capsule_compiler\nAST Verify + WASM Lowering]
        RuntimeService[runtime_service\ngRPC :50061]
        CapsuleRuntime[capsule_runtime\nWasmtime Sandbox]
        Attestation[attestation\nDecision Hash + Ed25519]
    end

    subgraph DataLayer[Data Layer]
        Postgres[(PostgreSQL\nIdentity, Orgs, Sessions, Policies, Audit)]
        Redis[(Redis\nSessions, Nonces, Rate Limits, Capsule Cache)]
        Overflow[(Audit Overflow Queue\nLocal durable fallback)]
    end

    subgraph ExternalSystems[External Systems]
        OAuthProviders[OAuth Providers\nGoogle, GitHub, Microsoft]
        Stripe[Stripe]
        MailProvider[SendGrid / SMTP]
        SmsProvider[Twilio / SMS]
        EnterpriseIdp[Enterprise IdP\nSAML / OIDC]
    end

    ReactUI --> ApiServer
    AdminConsole --> ApiServer
    JsSdk --> ApiServer
    PyGoSdk --> ApiServer
    MobileApps --> ApiServer
    EnterpriseApps --> OAuthAs
    EnterpriseApps --> SamlIdp
    EnterpriseApps --> Scim

    ApiServer --> SecurityMiddleware
    SecurityMiddleware --> EiaaMiddleware
    ApiServer --> ProtocolLayer
    ApiServer --> DomainLayer
    EiaaMiddleware --> RuntimeService

    AuthFlow --> IdentityEngine
    OAuthAs --> AuthCore
    OAuthAs --> EiaaMiddleware
    SamlIdp --> IdentityEngine
    Scim --> IdentityEngine
    ApiKeys --> AuthCore
    Webhooks --> BillingEngine

    IdentityEngine --> AuthCore
    IdentityEngine --> RiskEngine
    IdentityEngine --> OrgManager
    BillingEngine --> Stripe
    EmailService --> MailProvider
    IdentityEngine --> SmsProvider
    IdentityEngine --> OAuthProviders
    OAuthAs --> EnterpriseIdp
    SamlIdp --> EnterpriseIdp

    PolicyBuilder --> CapsuleCompiler
    CapsuleCompiler --> RuntimeService
    RuntimeService --> CapsuleRuntime
    CapsuleRuntime --> Attestation
    Attestation --> Postgres

    AuthCore --> Postgres
    AuthCore --> Redis
    IdentityEngine --> Postgres
    OrgManager --> Postgres
    BillingEngine --> Postgres
    RiskEngine --> Redis
    EiaaMiddleware --> Redis
    EiaaMiddleware --> Postgres
    EiaaMiddleware --> Overflow
```

## 2. Backend Component Diagram

```mermaid
flowchart LR
    subgraph ApiServer[api_server binary]
        Router[Router]
        Handlers[Route Handlers]
        AuthMw[Auth Middleware]
        EiaaMw[EIAA Authz Layer]
        Extractors[Extractors]
        AuditWriter[Audit Writer]
    end

    subgraph CoreLibraries[Core Libraries]
        SharedTypes[shared_types\nErrors, IDs, validation]
        AuthCore[auth_core\nClaims, JWT, SessionStore]
        Keystore[keystore\nES256 + Ed25519 keys]
        GrpcApi[grpc_api\nTonic generated bindings]
    end

    subgraph DomainCrates[Domain Crates]
        IdentityEngine[identity_engine]
        OrgManager[org_manager]
        BillingEngine[billing_engine]
        EmailService[email_service]
        RiskEngine[risk_engine]
    end

    subgraph EiaaCrates[EIAA Crates]
        CapsuleCompiler[capsule_compiler]
        CapsuleRuntime[capsule_runtime]
        Attestation[attestation]
        RuntimeService[runtime_service binary]
    end

    subgraph Storage[Storage]
        Pg[(PostgreSQL)]
        Redis[(Redis)]
    end

    Router --> Handlers
    Router --> AuthMw
    Router --> EiaaMw
    Handlers --> Extractors
    Handlers --> DomainCrates
    AuthMw --> AuthCore
    EiaaMw --> AuthCore
    EiaaMw --> RiskEngine
    EiaaMw --> RuntimeService
    EiaaMw --> AuditWriter

    RuntimeService --> GrpcApi
    RuntimeService --> CapsuleCompiler
    RuntimeService --> CapsuleRuntime
    CapsuleRuntime --> Attestation
    CapsuleCompiler --> Attestation
    Attestation --> Keystore

    IdentityEngine --> AuthCore
    IdentityEngine --> SharedTypes
    OrgManager --> SharedTypes
    BillingEngine --> SharedTypes
    EmailService --> SharedTypes
    RiskEngine --> SharedTypes

    AuthCore --> Pg
    AuthCore --> Redis
    IdentityEngine --> Pg
    OrgManager --> Pg
    BillingEngine --> Pg
    RiskEngine --> Redis
    AuditWriter --> Pg
    AuditWriter --> Redis
```

## 3. EIAA Protected Request Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant API as Axum API Server
    participant Auth as Auth Middleware / JwtService
    participant Sess as Session Store
    participant EIAA as EIAA Authz Layer
    participant Risk as Risk Engine
    participant Runtime as Runtime Service gRPC
    participant Wasm as Wasmtime Capsule Runtime
    participant Att as Attestation Verifier
    participant Audit as Audit Writer
    participant Handler as Protected Handler

    Client->>API: Request protected resource with Bearer JWT
    API->>Auth: Verify JWT signature, issuer, audience, exp
    Auth-->>API: Identity-only Claims
    API->>Sess: Check session by sid
    Sess-->>API: Active session or revoked/expired
    API->>EIAA: Evaluate action with Claims and request context
    EIAA->>Risk: Compute contextual risk score
    Risk-->>EIAA: Risk score and signals
    EIAA->>Runtime: Execute capsule(action, tenant, subject, context)
    Runtime->>Wasm: Load signed WASM, inject host functions, execute
    Wasm-->>Runtime: DecisionOutput allow/deny/need_input
    Runtime-->>EIAA: Decision + attestation + nonce
    EIAA->>Att: Verify signature, decision hash, nonce uniqueness
    Att-->>EIAA: Verified or rejected
    EIAA->>Audit: Persist decision, context, attestation
    alt Decision is Allow
        EIAA->>Handler: Continue request
        Handler-->>Client: 2xx response
    else Decision is Deny
        EIAA-->>Client: 403 Forbidden
    else Step-up required
        EIAA-->>Client: 403 AUTH_STEP_UP_REQUIRED
    end
```

## 4. Authentication Flow Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as React Hosted UI
    participant API as Auth Flow API
    participant Identity as identity_engine
    participant Risk as risk_engine
    participant Compiler as capsule_compiler
    participant Runtime as runtime_service
    participant AuthCore as auth_core
    participant DB as PostgreSQL
    participant Redis as Redis

    User->>UI: Start login
    UI->>API: POST /api/v1/auth-flow/init
    API->>Redis: Create FlowSession
    API-->>UI: flow_token
    UI->>API: Identify email or username
    API->>Identity: Resolve identity and organization context
    Identity->>DB: Query identities, users, memberships
    DB-->>Identity: Candidate user and tenant
    Identity->>Compiler: Build login policy AST from tenant config
    Compiler-->>Runtime: Signed capsule or cached capsule reference
    API->>Runtime: Execute login capsule with initial context
    Runtime-->>API: Required steps
    API-->>UI: Password, MFA, passkey, or verification steps
    UI->>API: Submit credentials and factors
    API->>Identity: Verify password / passkey / OTP
    Identity->>Risk: Evaluate login risk
    Risk-->>Identity: Risk score
    API->>Runtime: Re-execute capsule with satisfied factors and risk
    Runtime-->>API: Final allow/deny/need_input + attestation
    alt Authentication allowed
        API->>AuthCore: Create session and identity-only JWT
        AuthCore->>DB: Persist session
        AuthCore->>Redis: Cache session
        API-->>UI: user, sessionId, jwt, attestation
    else More input required
        API-->>UI: Next required step
    else Authentication denied
        API-->>UI: Authentication failure
    end
```

## 5. Protocol Surface Diagram

```mermaid
flowchart TB
    subgraph ProtocolClients[Protocol Clients]
        Browser[Browser / Hosted UI]
        OAuthClient[OAuth Client Application]
        OidcClient[OIDC Client]
        SamlSp[SAML Service Provider]
        ScimClient[SCIM Provisioning Client]
        ApiConsumer[Machine / API Consumer]
        StripeWebhook[Stripe Webhook Sender]
    end

    subgraph ProtocolEndpoints[IDaaS Protocol Endpoints]
        AuthFlow["/api/v1/auth-flow/*"]
        OAuth["/oauth/*"]
        WellKnown["/.well-known/*"]
        Saml["/api/saml/idp/*"]
        Scim["/scim/v2/*"]
        ApiKeyRoutes["/api/v1/api-keys/*"]
        BillingWebhook["/api/billing/v1/webhook"]
    end

    subgraph Enforcement[Enforcement Model]
        PublicRateLimit[Public rate limiting]
        JwtIdentity[Identity-only JWT validation]
        EiaaCapsule[EIAA capsule authorization]
        BearerScopeCapsule[OAuth bearer scope to EIAA action mapping]
        ScimTenant[SCIM token to tenant binding]
        ApiKeyScope[API key scopes as separate extension]
        SignatureVerify[Webhook signature verification]
    end

    Browser --> AuthFlow
    OAuthClient --> OAuth
    OidcClient --> WellKnown
    SamlSp --> Saml
    ScimClient --> Scim
    ApiConsumer --> ApiKeyRoutes
    StripeWebhook --> BillingWebhook

    AuthFlow --> PublicRateLimit
    AuthFlow --> EiaaCapsule
    OAuth --> PublicRateLimit
    OAuth --> BearerScopeCapsule
    WellKnown --> PublicRateLimit
    Saml --> JwtIdentity
    Saml --> EiaaCapsule
    Scim --> ScimTenant
    ApiKeyRoutes --> JwtIdentity
    ApiKeyRoutes --> ApiKeyScope
    ApiKeyRoutes --> EiaaCapsule
    BillingWebhook --> SignatureVerify

    JwtIdentity --> EiaaCapsule
    BearerScopeCapsule --> EiaaCapsule
```

## 6. Deployment Topology Diagram

> Reference topology. Local development runs a single PostgreSQL instance and a single Redis instance, without WAF, replicas, or Sentinel. The diagram below describes the production-grade target deployment.

```mermaid
flowchart TB
    subgraph Internet[Internet]
        Users[Users]
        EnterpriseTenants[Enterprise Tenants]
        ExternalApis[External APIs]
    end

    subgraph Edge[Ingress / Load Balancer]
        Ingress[TLS Ingress]
        Waf[WAF / Rate Limit Boundary]
    end

    subgraph AppCluster[Application Cluster]
        Frontend[Frontend Static Assets\nReact / Vite build]
        Api1[api_server replica 1]
        Api2[api_server replica 2]
        ApiN[api_server replica N]
        Runtime1[runtime_service replica 1]
        Runtime2[runtime_service replica 2]
    end

    subgraph DataPlane[Data Plane]
        PgPrimary[(PostgreSQL Primary)]
        PgReplica[(PostgreSQL Read Replica)]
        RedisPrimary[(Redis Primary)]
        RedisReplica[(Redis Replica / Sentinel)]
        AuditOverflow[(Audit Overflow Volume)]
    end

    subgraph Observability[Observability]
        Logs[Structured Logs]
        Metrics[Prometheus Metrics]
        Traces[Request IDs / Traces]
        Grafana[Grafana Dashboards]
    end

    Users --> Ingress
    EnterpriseTenants --> Ingress
    ExternalApis --> Ingress
    Ingress --> Waf
    Waf --> Frontend
    Waf --> Api1
    Waf --> Api2
    Waf --> ApiN

    Api1 --> Runtime1
    Api2 --> Runtime1
    ApiN --> Runtime2
    Api1 --> PgPrimary
    Api2 --> PgPrimary
    ApiN --> PgReplica
    Api1 --> RedisPrimary
    Api2 --> RedisPrimary
    ApiN --> RedisReplica
    Runtime1 --> PgPrimary
    Runtime2 --> PgPrimary
    Api1 --> AuditOverflow
    Api2 --> AuditOverflow
    ApiN --> AuditOverflow

    Api1 --> Logs
    Api2 --> Logs
    ApiN --> Logs
    Runtime1 --> Logs
    Runtime2 --> Logs
    Api1 --> Metrics
    Api2 --> Metrics
    ApiN --> Metrics
    Runtime1 --> Metrics
    Runtime2 --> Metrics
    Logs --> Grafana
    Metrics --> Grafana
    Traces --> Grafana
```

## 7. Core Data Ownership Diagram

```mermaid
erDiagram
    USERS ||--o{ IDENTITIES : owns
    USERS ||--o{ SESSIONS : creates
    USERS ||--o{ MEMBERSHIPS : joins
    ORGANIZATIONS ||--o{ MEMBERSHIPS : contains
    ORGANIZATIONS ||--o{ SUBSCRIPTIONS : bills
    ORGANIZATIONS ||--o{ EIAA_POLICIES : defines
    EIAA_POLICIES ||--o{ EIAA_EXECUTIONS : executes
    SESSIONS ||--o{ EIAA_EXECUTIONS : authorizes_with
    USERS ||--o{ MFA_FACTORS : enrolls
    USERS ||--o{ USER_FACTORS : risk_state
    USERS ||--o{ PASSKEY_CREDENTIALS : registers
    ORGANIZATIONS ||--o{ API_KEYS : owns
    ORGANIZATIONS ||--o{ SCIM_TOKENS : provisions_with

    USERS {
        string id PK
        string first_name
        string last_name
        boolean banned
        boolean locked
        timestamp deleted_at
    }

    IDENTITIES {
        string id PK
        string user_id FK
        string type
        string identifier
        boolean verified
    }

    SESSIONS {
        string id PK
        string user_id FK
        string active_organization_id
        integer aal
        boolean revoked
        timestamp expires_at
    }

    ORGANIZATIONS {
        string id PK
        string name
        string slug
        jsonb metadata
    }

    MEMBERSHIPS {
        string id PK
        string organization_id FK
        string user_id FK
        string role
    }

    EIAA_POLICIES {
        string id PK
        string tenant_id
        string action
        integer version
        jsonb spec
        string ast_hash
        string wasm_hash
        bytes signature
        bytes capsule_bytes
    }

    EIAA_EXECUTIONS {
        string id PK
        string capsule_id FK
        string subject_id
        string tenant_id
        integer decision
        jsonb runtime_context
        jsonb attestation
        string nonce
    }

    SUBSCRIPTIONS {
        string id PK
        string organization_id FK
        string stripe_customer_id
        string stripe_subscription_id
        string status
        string plan_id
    }

    MFA_FACTORS {
        string id PK
        string user_id FK
        string factor_type
        boolean enabled
        boolean verified
    }

    USER_FACTORS {
        string id PK
        string user_id FK
        string factor_type
        jsonb risk_state
        timestamp last_used_at
    }

    PASSKEY_CREDENTIALS {
        string id PK
        string user_id FK
        bytes credential_id
        bytes public_key
        integer sign_count
    }

    API_KEYS {
        string id PK
        string organization_id FK
        string user_id FK
        string key_prefix
        string status
    }

    SCIM_TOKENS {
        string id PK
        string organization_id FK
        string token_hash
        timestamp expires_at
        boolean revoked
    }
```

> Note: compiled capsule artifacts (AST hash, WASM hash, Ed25519 signature, capsule bytes) live as columns on `eiaa_policies` together with the `policy_activations` table; there is no separate `eiaa_compiled_capsules` table.

## 8. EIAA Capsule Lifecycle State Diagram

```mermaid
stateDiagram-v2
    [*] --> PolicyDraft
    PolicyDraft --> AstValidation: submit JSON AST
    AstValidation --> Rejected: verifier rule failure
    AstValidation --> CanonicalAst: rules R1-R26 pass
    CanonicalAst --> WasmLowering: deterministic lowering
    WasmLowering --> Signing: compute AST and WASM hashes
    Signing --> CapsuleStored: Ed25519 signature added
    CapsuleStored --> CapsuleCached: cache by tenant and action
    CapsuleCached --> ExecutionRequested: protected request arrives
    ExecutionRequested --> RuntimeEvaluation: load WASM in Wasmtime
    RuntimeEvaluation --> DecisionAllow: allow
    RuntimeEvaluation --> DecisionDeny: deny
    RuntimeEvaluation --> DecisionNeedInput: step-up or factor required
    DecisionAllow --> Attested
    DecisionDeny --> Attested
    DecisionNeedInput --> Attested
    Attested --> Audited: store nonce, decision hash, signature
    Audited --> ReExecutable: historical forensic replay
    Rejected --> [*]
    ReExecutable --> [*]
```

## 9. Frontend Runtime Diagram

```mermaid
flowchart TB
    subgraph Browser[Browser]
        Router[React Router]
        AuthProvider[AuthContext\nIn-memory access token]
        ApiClient[Axios API Client\nAuthorization header + refresh handling]
        AuthMachine[XState Auth Machine\nplanned - dependency installed, not yet wired]
        AdminLayout[AdminLayout\nServer-side admin probe]
        StepUpModal[StepUpModal]
        Pages[User, Admin, Billing, Security Pages]
    end

    subgraph BrowserStorage[Browser Storage]
        MemoryOnly[(Memory-only JWT)]
        HttpOnlyCookie[(HttpOnly refresh cookie)]
        SessionOrg[(sessionStorage active_org_id)]
    end

    subgraph Backend[Backend APIs]
        AuthFlowApi[Auth Flow API]
        RefreshApi[Token Refresh API]
        AdminWhoami[Admin whoami probe\n/api/admin/v1/whoami]
        ProtectedApis[Protected APIs]
        StepUpApi[Step-up API]
    end

    Router --> AuthProvider
    AuthProvider --> ApiClient
    AuthProvider --> MemoryOnly
    AuthProvider --> HttpOnlyCookie
    AuthProvider --> SessionOrg
    AuthMachine --> AuthFlowApi
    ApiClient --> ProtectedApis
    ApiClient --> RefreshApi
    AdminLayout --> AdminWhoami
    StepUpModal --> StepUpApi
    Pages --> ApiClient
    AdminWhoami --> ProtectedApis
```

## Reading Guide

- Use the system context diagram for executive and architecture discussions.
- Use the backend component diagram when changing Rust crates or middleware boundaries.
- Use the protected request sequence when reviewing EIAA correctness.
- Use the authentication sequence when debugging login, MFA, passkeys, or step-up flows.
- Use the protocol surface diagram when auditing OAuth, OIDC, SAML, SCIM, API keys, or webhooks.
- Use the data ownership diagram when adding migrations or changing persistence contracts.
