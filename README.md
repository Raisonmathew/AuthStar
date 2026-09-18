# AuthStar IDaaS — Identity & Authorization as a Service

An enterprise-grade, production-ready Identity-as-a-Service platform built in **Rust** and **React**, featuring **EIAA** (Entitlement-Independent Authentication Architecture) — a novel authorization model that compiles policies into cryptographically-signed WebAssembly capsules evaluated at request time.

## 🔑 Core Architecture: EIAA

**EIAA** is the platform's central design principle:

| Concept | Carrier | Content |
|---------|---------|---------|
| **Identity** | JWT (ES256) | *Who you are* — `sub`, `sid`, `tenant_id` only. No roles, permissions, or scopes. |
| **Authorization** | WASM Capsule + Attestation | *What you can do right now* — evaluated at runtime against a signed policy capsule. |

Every protected route executes a compiled WASM capsule via `EiaaAuthzLayer`. The runtime returns a cryptographically-signed attestation (Ed25519) and writes an immutable re-executable audit record. Authorization decisions can be replayed from stored context to produce forensic proof.

## 🤖 AI Agent Authorization

AuthStar extends EIAA to **non-human principals** — AI agents (Claude, GPT, custom models) can authenticate and have every tool call authorized by a WASM capsule before execution:

- **Agent registration**: `POST /api/v1/agents/register` — registers a model identity with allowed tools
- **Token issuance**: `POST /api/v1/agents/token` — issues a scoped, time-limited JWT for a task
- **Tool-call authorization**: `POST /api/v1/agents/:id/authorize` — runs the EIAA capsule per tool call
- **Execution recording**: `POST /api/v1/agents/:id/executions` — writes a tamper-evident execution record
- **Task chain audit**: `GET /api/v1/audit/task/:task_id` — reconstructs the full causal chain for a task
- **Token revocation**: `POST /api/v1/agents/:id/revoke` — immediately invalidates all active tokens

See [`sdks/python/idaas/agent.py`](sdks/python/idaas/agent.py) and [`sdks/typescript/agent/`](sdks/typescript/agent/) for drop-in agent SDK clients.

## 🚀 Features

- **Authentication**: Email/password, OAuth (Google, GitHub, Microsoft), passwordless (magic links, OTP), WebAuthn/Passkeys
- **Multi-Factor Authentication**: TOTP, SMS, backup codes, hardware keys
- **B2B Organizations**: Multi-tenant workspace management with hierarchical RBAC
- **SAML 2.0 SP**: XML-DSig, audience restriction, signed AuthnRequests
- **OAuth 2.0 AS**: RFC 6749, PKCE (RFC 7636), PAR (RFC 9126), Device Grant (RFC 8628), Dynamic Client Registration (RFC 7591), DPoP, mTLS
- **SCIM Provisioning**: Automated user lifecycle from identity providers
- **Billing**: Stripe integration with subscription management
- **EIAA Policy Engine**: WebAssembly capsule compiler, Wasmtime runtime, Ed25519 attestation, re-execution verification
- **AI Agent Authorization**: Non-human principal support with delegation chains and causal audit trails
- **Developer SDKs**: JavaScript/TypeScript, Python, Go, React

## 📁 Project Structure

```
AuthStar/
├── backend/          # Rust backend (Cargo workspace — 12 crates)
├── frontend/         # React/TypeScript admin console + hosted auth flows
├── sdks/             # Client SDKs (JS/TS, Python, Go, React, TypeScript Agent)
├── infrastructure/   # Terraform, Kubernetes manifests
├── docs/             # Architecture and integration docs
└── scripts/          # Setup and utility scripts
```

## 🛠️ Tech Stack

**Backend:**
- Rust 1.88+ with Axum 0.7 framework
- PostgreSQL 16 (with per-tenant Row-Level Security)
- Redis 7 for capsule caching, sessions, rate limiting
- Wasmtime for WASM capsule execution
- gRPC (Tonic) for runtime service communication
- Stripe for billing

**Frontend:**
- React 18 with TypeScript
- Vite build tool
- Tailwind CSS + shadcn/ui
- XState for authentication flow state machines
- JWT stored in memory only (never Web Storage)

## 🏃 Quick Start

### Prerequisites

- Rust 1.88+
- Node.js 20+
- PostgreSQL 16
- Redis 7
- Docker & Docker Compose

### Development Setup

```bash
# 1. Start infrastructure
docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml up -d

# 2. Run database migrations
cd backend
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run

# 3. Start backend
cargo run --bin api_server

# 4. Start frontend
cd ../frontend && npm install && npm run dev
```

The API will be available at `http://localhost:3000` and the frontend at `http://localhost:5173`.

## 🧪 Testing

```bash
# Backend tests
cd backend
cargo test --all-features

# Frontend tests
cd frontend
npm test

# Frontend lint (zero-warnings policy)
npm run lint
```

## 📚 Documentation

- [Technical Overview](docs/TECHNICAL_OVERVIEW.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [EIAA Compliance](docs/EIAA_COMPLIANCE.md)
- [Integration Guide](docs/INTEGRATION_GUIDE.md)

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
