# IDaaS Platform - Technical Architecture

A production-grade Identity-as-a-Service platform featuring enterprise authentication, B2B organization management, and Stripe billing integration.

## System Overview

```mermaid
flowchart TB
    subgraph Clients["Client Layer"]
        Web["React Frontend"]
        SDK["Client SDKs\n(JS/TS, Python, Go)"]
        Mobile["Mobile Apps"]
    end

    subgraph Gateway["API Gateway"]
        API["Axum API Server\n:3000"]
    end

    subgraph Services["Backend Microservices (Rust Crates)"]
        AuthCore["auth_core\nSession & JWT"]
        IdentityEngine["identity_engine\nUsers, MFA, OAuth"]
        OrgManager["org_manager\nB2B Orgs & RBAC"]
        BillingEngine["billing_engine\nStripe Integration"]
        EmailService["email_service\nSendGrid/SMTP"]
        RiskEngine["risk_engine\nThreat Detection"]
        RuntimeService["runtime_service\nCapsule Execution"]
    end

    subgraph Data["Data Layer"]
        PG[(PostgreSQL 16)]
        Redis[(Redis 7)]
    end

    subgraph External["External Services"]
        Stripe["Stripe API"]
        OAuth["OAuth Providers\n(Google, GitHub, MS)"]
        SendGrid["SendGrid"]
    end

    Clients --> API
    API --> Services
    AuthCore --> PG & Redis
    IdentityEngine --> PG
    OrgManager --> PG
    BillingEngine --> Stripe
    EmailService --> SendGrid
    RiskEngine --> Redis
    IdentityEngine --> OAuth
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Backend** | Rust 2021/1.88, Axum 0.7 | High-performance API server |
| **Database** | PostgreSQL 16, SQLx | Persistent data storage |
| **Cache** | Redis 7 | Sessions, rate limiting, MFA tokens |
| **Frontend** | React 18, TypeScript, Vite | Hosted authentication UI |
| **Styling** | Tailwind CSS, shadcn/ui | Modern, accessible components |
| **Auth Flows** | XState 5 | State machine-driven authentication |
| **Payments** | Stripe | Subscriptions, invoices, webhooks |
| **Email** | SendGrid / Lettre | Transactional email delivery |
| **gRPC** | Tonic 0.11 | Internal service communication |
| **Wasm** | Wasmtime | EIAA Capsule execution runtime |
| **Infra** | Docker, Kubernetes (EKS), Terraform | Container orchestration & IaC |

---

## Backend Crate Architecture

```mermaid
graph LR
    subgraph api_server["api_server (binary)"]
        Routes
        Handlers
        Middleware
    end

    subgraph Core["Core Libraries"]
        shared_types["shared_types\nCommon types & validation"]
        auth_core["auth_core\nJWT, Sessions"]
        keystore["keystore\nCrypto key management"]
    end

    subgraph Domain["Domain Services"]
        identity_engine["identity_engine\nUsers, MFA, OAuth"]
        org_manager["org_manager\nOrgs, Roles, RBAC"]
        billing_engine["billing_engine\nStripe sync"]
        email_service["email_service\nTemplates & delivery"]
        risk_engine["risk_engine\nThreat scoring"]
    end

    subgraph Infra["Infrastructure"]
        db_migrations["db_migrations\nSQLx migrations"]
        grpc_api["grpc_api\nInternal gRPC"]
    end

    subgraph CapsuleSystem["Capsule System"]
        capsule_compiler["capsule_compiler\nWasm Compilation"]
        capsule_runtime["capsule_runtime\nWasm Execution"]
        attestation["attestation\nRemote Attestation"]
        runtime_service["runtime_service\ngRPC Service"]
    end

    api_server --> Core
    api_server --> Domain
    Domain --> Core
    Domain --> Infra
    
    identity_engine --> attestation
    identity_engine --> capsule_runtime
    
    runtime_service --> capsule_compiler
    runtime_service --> capsule_runtime
    runtime_service --> grpc_api
    capsule_runtime --> attestation
```

### Crate Descriptions

| Crate | Description |
|-------|-------------|
| `api_server` | Main HTTP server binary, routes, middleware |
| `shared_types` | Common types, errors, validation, ID generation |
| `auth_core` | JWT creation/validation, session management |
| `identity_engine` | User CRUD, password hashing, MFA, OAuth flows |
| `org_manager` | Organization CRUD, memberships, roles, invitations |
| `billing_engine` | Stripe customer/subscription sync, webhooks |
| `email_service` | Email templates, SendGrid/SMTP integration |
| `risk_engine` | Adaptive authentication, threat scoring |
| `keystore` | Ed25519/ES256 key generation and signing |
| `db_migrations` | SQLx database migrations |
| `attestation` | Remote attestation & nonces |
| `capsule_compiler` | Wasm module compilation |
| `capsule_runtime` | Wasm execution environment (Wasmtime) |
| `runtime_service` | gRPC service for capsule execution |
| `grpc_api` | Shared gRPC definitions |
| `migrator` | Database migration runner |

---

## Installation Guide

### Prerequisites

- **Rust**: 1.88+ ([rustup.rs](https://rustup.rs))
- **Node.js**: 20+ ([nodejs.org](https://nodejs.org))
- **PostgreSQL**: 16
- **Redis**: 7
- **Docker / Podman**: For containerized infrastructure
- **sqlx-cli**: `cargo install sqlx-cli --no-default-features --features postgres`

### Quick Start (Automated)

**Windows (PowerShell)**:
```powershell
.\scripts\deploy.ps1 -Environment local
```

**Linux/macOS**:
```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh local
```

This starts PostgreSQL, Redis, MailHog, and MinIO via Docker Compose, waits for health checks, creates `.env` files from templates, runs database migrations, generates JWT keys, and installs frontend dependencies.

### Manual Setup

#### 1. Start Infrastructure

```bash
cd infrastructure/docker-compose
docker compose -f docker-compose.dev.yml up -d
```

This starts:
- PostgreSQL on `localhost:5432`
- Redis on `localhost:6379`
- MailHog on `localhost:8025` (email testing UI)
- MinIO on `localhost:9001` (S3-compatible storage console)
- pgAdmin on `localhost:5050` (database GUI)
- Redis Commander on `localhost:8081` (Redis GUI)

#### 2. Configure Environment

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env`:
```env
# Database
DATABASE_URL=postgres://idaas_user:dev_password_change_me@localhost:5432/idaas

# Redis
REDIS_URL=redis://localhost:6379

# JWT Keys (ES256) - Generate with OpenSSL (see step 3)
JWT_PRIVATE_KEY="-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# Frontend
FRONTEND_URL=http://localhost:5173
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
```

See `backend/.env.example` for the full list of configuration options.

#### 3. Generate JWT Keys

```bash
# Create keys directory
mkdir -p .keys

# Generate ES256 key pair
openssl ecparam -genkey -name prime256v1 -noout -out .keys/private.pem
openssl ec -in .keys/private.pem -pubout -out .keys/public.pem

# Copy to .env (escape newlines)
echo "JWT_PRIVATE_KEY=$(cat .keys/private.pem | sed ':a;N;$!ba;s/\n/\\n/g')"
echo "JWT_PUBLIC_KEY=$(cat .keys/public.pem | sed ':a;N;$!ba;s/\n/\\n/g')"
```

#### 4. Run Database Migrations

```bash
cd backend

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres

# Run migrations
sqlx migrate run --source crates/db_migrations/migrations
```

#### 5. Start Backend

```bash
cd backend
cargo run --bin api_server
```

The API will be available at `http://localhost:3000`.

#### 6. Start Runtime Service

```bash
cd backend
cargo run --bin runtime_service
```

The gRPC runtime service will listen on `localhost:50061`.

#### 7. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:5173`.

---

## Scripts Reference

| Script | Purpose |
|--------|---------|
| `scripts/deploy.ps1` | Unified deployment (local / staging / production) — PowerShell |
| `scripts/deploy.sh` | Unified deployment (local / staging / production) — Bash |
| `scripts/deploy-production.ps1` | Dedicated production K8s deploy — PowerShell |
| `scripts/deploy-production.sh` | Dedicated production K8s deploy — Bash |

---

## Database Schema

```mermaid
erDiagram
    users ||--o{ identities : has
    users ||--o{ sessions : has
    users ||--o{ mfa_factors : has
    users ||--o{ memberships : has

    organizations ||--o{ memberships : has
    organizations ||--o{ org_invitations : has
    organizations ||--o{ roles : has
    organizations ||--o{ subscriptions : has

    memberships }o--|| roles : has

    subscriptions ||--o{ subscription_items : has
    subscriptions ||--o{ invoices : has

    users {
        string id PK
        string first_name
        string last_name
        timestamp created_at
    }

    identities {
        string id PK
        string user_id FK
        string type
        string identifier
        boolean verified
    }

    organizations {
        string id PK
        string name
        string slug UK
        string stripe_customer_id
    }

    memberships {
        string user_id FK
        string org_id FK
        string role_id FK
    }

    sessions {
        string id PK
        string user_id FK
        string device_info
        timestamp expires_at
    }
```

---

## Security Features

### Authentication
- **Passwords**: Argon2id (64MB memory, 3 iterations)
- **JWT**: ES256 (ECDSA P-256), 15-minute expiry
- **Sessions**: HttpOnly cookies, 30-day expiry
- **MFA**: TOTP (RFC 6238), SMS, backup codes
- **Passkeys**: WebAuthn/FIDO2 (YubiKey, TouchID, FaceID)
- **SAML**: 2.0 Service Provider (SP) support

### Authorization
- **RBAC**: Role-based access control per organization
- **Permissions**: Fine-grained resource-level permissions
- **API Keys**: Scoped keys for programmatic access

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sign-up` | Create account |
| POST | `/api/v1/sign-in` | Authenticate |
| POST | `/api/v1/sign-out` | Revoke session |
| POST | `/api/v1/token/refresh` | Refresh JWT |
| GET | `/api/v1/user` | Get current user |

### Organizations
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/organizations` | Create org |
| GET | `/api/v1/organizations` | List user's orgs |
| GET | `/api/v1/organizations/:id/members` | List members |
| POST | `/api/v1/organizations/:id/invitations` | Invite member |

### Billing
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/billing/subscription` | Get subscription |
| POST | `/api/v1/billing/portal` | Create portal session |
| POST | `/api/v1/webhooks/stripe` | Stripe webhooks |

---

## Testing

```bash
# Run all backend tests
cd backend
cargo test --all-features

# Run specific crate tests
cargo test -p identity_engine

# Run frontend E2E tests (Playwright)
cd frontend
npm test
```

---

## Deployment

All deployment is handled through unified scripts in `scripts/`.

### Local (Docker Compose)

```powershell
# PowerShell
.\scripts\deploy.ps1 -Environment local

# Bash
./scripts/deploy.sh local
```

### Staging / Production (Kubernetes)

```powershell
# PowerShell
.\scripts\deploy.ps1 -Environment staging -Version 1.0.0 -Org your-org
.\scripts\deploy.ps1 -Environment production -Version 1.0.0 -Org your-org

# Bash
./scripts/deploy.sh staging --version 1.0.0 --org your-org
./scripts/deploy.sh production --version 1.0.0 --org your-org
```

Flags: `--skip-build` (reuse existing images), `--skip-migrations` (skip DB migration job).

### Docker Images

All images use multi-stage builds with `cargo-chef` for optimal layer caching:

| Image | Dockerfile | Description |
|-------|-----------|-------------|
| `backend` | `backend/Dockerfile` | API server (rust:1.88-slim → debian:bookworm-slim) |
| `runtime` | `backend/Dockerfile.runtime` | gRPC runtime service with grpc_health_probe |
| `frontend` | `frontend/Dockerfile` | Vite build → nginx:1.27-alpine |

### Kubernetes Architecture

Manifests use **Kustomize** with base + overlays:

```
infrastructure/kubernetes/
├── base/                    # Shared manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── backend-deployment.yaml
│   ├── frontend-deployment.yaml
│   ├── runtime-deployment.yaml
│   ├── db-migration-job.yaml
│   ├── configmap.yaml
│   ├── secrets.yaml         # ExternalSecrets for AWS Secrets Manager
│   ├── ingress.yaml
│   ├── cluster-issuer.yaml  # cert-manager TLS
│   ├── hpa.yaml
│   ├── pdb.yaml
│   ├── network-policy.yaml
│   ├── service-monitor.yaml # Prometheus metrics
│   └── distributed-services.yaml
├── overlays/
│   ├── staging/             # Staging-specific patches
│   └── production/          # Production-specific patches (higher replicas, resources)
```

### Terraform (AWS)

Infrastructure provisioned via modular Terraform:

```
infrastructure/terraform/
├── main.tf                  # Module composition + Helm releases
├── variables.tf
├── outputs.tf
├── environments/
│   ├── staging.tfvars
│   └── production.tfvars
└── modules/
    ├── vpc/                 # VPC, subnets, NAT, flow logs, endpoints (S3, STS, SecretsManager)
    ├── eks/                 # EKS 1.29, managed node groups, IRSA roles
    ├── rds/                 # PostgreSQL 16, multi-AZ, Performance Insights, KMS encryption
    ├── redis/               # ElastiCache Redis 7, replication group, encryption
    └── secrets/             # AWS Secrets Manager for app secrets
```

Helm charts deployed via Terraform: nginx-ingress, cert-manager, external-secrets, kube-prometheus-stack.

```bash
cd infrastructure/terraform
terraform init
terraform plan -var-file=environments/production.tfvars
terraform apply -var-file=environments/production.tfvars
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `REDIS_URL` | ✅ | Redis connection string |
| `JWT_PRIVATE_KEY` | ✅ | ES256 private key (PEM) |
| `JWT_PUBLIC_KEY` | ✅ | ES256 public key (PEM) |
| `STRIPE_SECRET_KEY` | ⚠️ | Stripe API key (for billing) |
| `SENDGRID_API_KEY` | ⚠️ | SendGrid API key (for email) |
| `GOOGLE_CLIENT_ID` | ⚠️ | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | ⚠️ | Google OAuth client secret |

---

## Support

- 📧 **Email**: support@idaas.example
- 📖 **Docs**: [Integration Guide](INTEGRATION_GUIDE.md)
- 💬 **Discord**: https://discord.gg/idaas

---

**Built with ❤️ using Rust and React**
