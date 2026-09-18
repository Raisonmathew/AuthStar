# AuthStar IDaaS — DemoApp

A **Next.js 14** (App Router) reference implementation that consumes every AuthStar IDaaS SDK as a realistic customer application. Paired with a **FastAPI Python sidecar** for async Python SDK testing and **Playwright** E2E specs covering all 9 test suites.

---

## Project layout

```
DemoApp/
├── app/                         # Next.js 14 App Router pages
│   ├── layout.tsx               # IDaaSProvider wrapper (in-memory JWT, no sessionStorage)
│   ├── page.tsx                 # Landing page
│   ├── sign-in/page.tsx         # EIAA 5-step authentication flow
│   ├── sign-up/page.tsx         # New user registration
│   ├── dashboard/page.tsx       # Protected dashboard with AgentPanel
│   └── api/agent/               # Next.js route handlers (SDK proxies)
│       ├── authorize/route.ts   # POST  → AgentAuthzClient.authorizeToolCall()
│       ├── record/route.ts      # POST  → AgentAuthzClient.recordExecution()
│       └── history/route.ts     # GET   → AgentAuthzClient.getTaskChain()
├── components/
│   └── AgentPanel.tsx           # Interactive agent demo (register, token, authz, history)
├── lib/
│   ├── authstar.ts              # Server-side IDaaSServerClient singleton
│   └── agent-client.ts         # makeAgentClient() factory for AgentAuthzClient
├── py-agent-service/            # FastAPI async Python sidecar
│   ├── main.py                  # /py/* routes exercising AsyncAgentAuthz + IDaaSClient
│   └── requirements.txt
└── playwright/                  # Playwright E2E test suite
    ├── playwright.config.ts     # 7 projects: chromium, firefox, webkit, mobile, api, python-sdk, golden-path
    ├── global-setup.ts          # EIAA flow walker, AAL3 upgrade, risk state reset
    ├── package.json
    ├── tsconfig.json
    ├── fixtures/
    │   ├── test-utils.ts        # Extended test fixture: adminJwt, agent, agentJwt, taskId
    │   └── .auth/               # Saved auth state (gitignored)
    └── specs/
        ├── 01-human-auth/       # Sign-in, sign-up, token refresh, logout
        ├── 02-admin/            # Admin dashboard, user invite, API keys
        ├── 03-agent-registration/  # Register, lifecycle, input validation
        ├── 04-agent-token/      # Token issuance, JWT claims, token security
        ├── 05-tool-authz/       # Tool authorize, EIAA context injection
        ├── 06-audit/            # Task chain queries, agent history
        ├── 07-security/         # Token revocation, tenant isolation, edge cases
        ├── 08-sdk/              # TypeScript SDK, Python SDK, storage security
        └── 09-e2e-golden-path/  # Full lifecycle golden path
```

---

## Prerequisites

| Dependency | Version |
|------------|---------|
| Node.js    | ≥ 20    |
| Python     | ≥ 3.11  |
| Docker     | ≥ 24    |

---

## Quick start

### 1. Start the full AuthStar stack

```bash
# From the repo root
docker compose -f docker-compose-root.yml up -d
```

Ports used:

| Service     | Port  |
|-------------|-------|
| Backend     | 3000  |
| Frontend    | 8080  |
| DemoApp     | 4000  |
| PostgreSQL  | 5432  |
| Redis       | 6379  |
| MailHog     | 8025  |

### 2. Install DemoApp dependencies

```bash
cd DemoApp
npm install
```

### 3. Start the DemoApp

```bash
npm run dev   # starts Next.js on http://localhost:4000
```

### 4. Start the Python sidecar (optional — needed for suite 08-sdk)

```bash
cd DemoApp/py-agent-service
pip install -r requirements.txt
uvicorn main:app --port 8001 --reload
```

---

## Running the E2E tests

All Playwright commands are run from `DemoApp/playwright/`:

```bash
cd DemoApp/playwright
npm install
npx playwright install --with-deps
```

### Run all suites

```bash
npm test
```

### Run a single suite

```bash
# API-only tests (no browser needed)
npm run test:api

# Golden path only
npm run test:golden

# Security suites
npm run test:security

# Python SDK tests (requires sidecar)
npm run test:py
```

### Interactive mode

```bash
npm run test:ui      # Playwright UI
npm run test:headed  # Visible browser
npm run test:debug   # Step-through debugger
```

---

## Environment variables

Copy `.env.local` and adjust for your environment:

| Variable                    | Default                                      | Description                        |
|-----------------------------|----------------------------------------------|------------------------------------|
| `AUTHSTAR_BASE_URL`         | `http://localhost:3000`                      | AuthStar backend                   |
| `DEMO_APP_BASE_URL`         | `http://localhost:4000`                      | This DemoApp                       |
| `PYTHON_AGENT_SERVICE_URL`  | `http://localhost:8001`                      | FastAPI Python sidecar             |
| `ADMIN_EMAIL`               | `admin@example.com`                          | Bootstrap admin email              |
| `IDAAS_BOOTSTRAP_PASSWORD`  | `Admin@1234!DevOnly`                         | Bootstrap admin password           |
| `TEST_SEED_TOKEN`           | `dev-test-seed-token-change-for-staging`     | X-Test-Seed-Token header value     |
| `NEXT_PUBLIC_IDAAS_BASE_URL`| `http://localhost:3000`                      | Client-side SDK base URL           |
| `IDAAS_TENANT_ID`           | `system`                                     | Tenant ID for demo                 |

---

## Test suite overview

| Suite | File(s) | Tests | Coverage |
|-------|---------|-------|----------|
| 01 — Human Auth | `01-human-auth/` | 1.1–1.12 | Sign-in, sign-up, token refresh, logout |
| 02 — Admin | `02-admin/` | 2.1–2.6 | Dashboard, user invite, API keys |
| 03 — Agent Registration | `03-agent-registration/` | 3.1–3.18 | Register, lifecycle, validation |
| 04 — Agent Token | `04-agent-token/` | 4.1–4.12 | Issuance, JWT claims, token security |
| 05 — Tool Authz | `05-tool-authz/` | 5.1–5.12 | ALLOW/DENY, EIAA context, attestation |
| 06 — Audit | `06-audit/` | 6.1–6.12 | Task chain pagination, agent history |
| 07 — Security | `07-security/` | 7.1–7.18 | Revocation, tenant isolation, edge cases |
| 08 — SDK | `08-sdk/` | 8.1–8.19 | TS SDK, Python SDK, storage security (G-7) |
| 09 — Golden Path | `09-e2e-golden-path/` | 9.1–9.5 | Full lifecycle, concurrent authz |

**Total: 80+ test scenarios** across 9 suites.

---

## G-issue traceability

| Issue | Description | Covered by |
|-------|-------------|------------|
| G-1 | Python `get_task_chain()` / `get_agent_history()` | 8.11, 8.12, 9.3 |
| G-2 | Python `register_agent()` etc. in `IDaaSClient` | 8.13, 9.3 |
| G-3 | TypeScript `@idaas/agent` SDK created | 8.1–8.7 |
| G-4 | Python `authorize_tool_call()` missing `task_id` | 5.4, 8.9 |
| G-5 | Python `AsyncAgentAuthz` created | 8.8, 8.10 |
| G-6 | Python token TTL refresh (`_ensure_token`) | 8.14 |
| G-7 | `IDaaSProvider` sessionStorage JWT guard | 8.15–8.19 |
| G-8 | `seed_capsule_for_agent()` deduplication | Rust unit tests |

---

## Architecture decisions

### JWT in memory only (G-7)

Per `AGENTS.md`: JWTs are **never** written to `sessionStorage` or `localStorage`. The `IDaaSProvider` stores the token in a React ref (`useRef`). The **only** intentional `sessionStorage` write is `active_org_id` (sent as `X-Organization-Id`). Tests 8.15–8.19 enforce this invariant.

### EIAA mental model

Every agent tool-call authorization runs a compiled WASM capsule via the `EiaaAuthzLayer`. The JWT carries identity only (`sub`, `sid`, `tenant_id`, `agent_id`, `task_id`). Authorization is decided at request time by the capsule — never by claims in the JWT.

### Cursor pagination

Audit endpoints (`/audit/chain/:task_id`, `/:agent_id/history`) use `created_at` timestamp as cursor (`?cursor=<ISO8601>`), not offset. Tests 6.2 and 6.9 verify non-overlapping pages.
