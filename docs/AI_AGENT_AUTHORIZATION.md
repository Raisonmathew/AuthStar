# AI Agent Authorization — Feature Deep Dive

**AuthStar IDaaS — Extension for AI Agent Principals**  
**Status:** Planned — 8-week roadmap (Sprints A–D)  
**Feasibility verdict:** HIGHLY FEASIBLE — 95% of required infrastructure already exists  
**Last updated:** 2026-03-06

---

## Table of Contents

1. [What Is This Feature?](#1-what-is-this-feature)
2. [Why It Matters — The Strategic Problem](#2-why-it-matters--the-strategic-problem)
3. [How It Works — Architecture Overview](#3-how-it-works--architecture-overview)
4. [The Full Authorization Workflow](#4-the-full-authorization-workflow)
5. [What Changes — Component by Component](#5-what-changes--component-by-component)
6. [Sprint Breakdown — Sprint A: Non-Human Principal Support](#6-sprint-a--non-human-principal-support)
7. [Sprint Breakdown — Sprint B: Tool Call Authorization Capsules](#7-sprint-b--tool-call-authorization-capsules)
8. [Sprint Breakdown — Sprint C: Task Chain Audit Trail](#8-sprint-c--task-chain-audit-trail)
9. [Sprint Breakdown — Sprint D: SDK Integration](#9-sprint-d--sdk-integration)
10. [Integration Guide — Anthropic Claude](#10-integration-guide--anthropic-claude)
11. [Integration Guide — OpenAI GPT Actions](#11-integration-guide--openai-gpt-actions)
12. [New API Endpoints](#12-new-api-endpoints)
13. [Database Schema Changes](#13-database-schema-changes)
14. [Security Model](#14-security-model)
15. [Risk Assessment](#15-risk-assessment)
16. [Competitive Advantage](#16-competitive-advantage)
17. [Performance Targets](#17-performance-targets)
18. [Go-to-Market Strategy](#18-go-to-market-strategy)
19. [Effort Summary & Timeline](#19-effort-summary--timeline)
20. [What Already Works (No Changes Needed)](#20-what-already-works-no-changes-needed)

---

## 1. What Is This Feature?

**AI Agent Authorization** extends AuthStar's existing EIAA (Entitlement-Independent Authentication Architecture) to support *non-human principals* — AI models such as Claude, GPT-4o, and any LLM-based agent system that makes API calls on behalf of users.

Today AuthStar authenticates and authorizes **humans**. After this feature ships, it will do the same for **AI agents** — using the exact same WASM capsule engine, Ed25519 attestation chain, and audit trail that already powers human authorization.

### The one-sentence pitch

> **AuthStar becomes the authorization layer that proves what your AI agent was allowed to do — and can prove it again, forever.**

### What "AI agent authorization" means concretely

When a user asks Claude "book me a flight from NYC to SFO", Claude internally calls tools: `web_search`, `send_email`, possibly `make_payment`. Today, there is no cryptographic proof that those tool calls were authorized by the user's policy at the moment they happened.

With this feature:

- Every tool call is **pre-authorized by a WASM policy capsule** before it executes
- Every decision produces an **Ed25519-signed attestation** stored permanently
- Every action in a multi-step task is linked in a **queryable causal chain**
- Any decision can be **forensically re-executed** at any future time to prove what the agent was allowed to do

---

## 2. Why It Matters — The Strategic Problem

### The three gaps in current AI agent stacks

**Gap 1 — Human-only identity model.** AuthStar's `Claims` struct has `sub` (user ID), `sid` (session ID), and `tenant_id`. There is no concept of an `agent_id`, `model_id`, `task_id`, or `delegation_chain`. An AI agent calling the API looks identical to an unauthenticated request.

**Gap 2 — Authorization is synchronous and request-scoped.** The current EIAA capsule executes per HTTP request and returns allow/deny. AI agents operate in multi-step task chains — "book a flight" becomes 15 API calls across 4 services over 30 seconds. The authorization model needs to handle *delegated task scopes*: "this agent is authorized to call these tools, in this order, within this time window, on behalf of this user."

**Gap 3 — The audit trail has no causal chain.** `eiaa_executions` stores per-decision records. Re-execution works. But querying "show me every action this agent took in this task chain" requires joining across multiple tables with no `task_id` or `parent_action_id` linking them.

### Why both Anthropic and OpenAI need this

Both organizations face the same accountability problem:

> *"We have no cryptographic proof of what an agent was authorized to do at the moment it did it. If something goes wrong — a model hallucinates a destructive action, a plugin abuses its scope — we can't replay the authorization decision. We can't prove the agent was or wasn't authorized."*

AuthStar's EIAA capsule + re-execution verification is the exact primitive that solves this. The same WASM engine, same attestation chain, same audit trail — extended to a new class of principal.

---

## 3. How It Works — Architecture Overview

### Today (Human IDaaS)

```
Human → AuthStar → JWT → API → EIAA Capsule → Allow / Deny
```

### After this feature (AI Agent AuthZ)

```
User Intent
    │
    ▼
AI Model (Claude / GPT / any LLM)
    │  requests scoped agent token (POST /api/v1/agents/token)
    ▼
AuthStar evaluates: "Is this user allowed to delegate to this agent?"
    │  EIAA capsule execution — same engine, new policy type
    ▼
Agent JWT issued:
    {
      sub:             "agent:claude-3-5-sonnet",
      principal_type:  "ai_agent",
      agent_id:        "agt_abc123",
      model_id:        "claude-3-5-sonnet-20241022",
      task_id:         "task_xyz789",
      delegation_chain: ["usr_human123"],
      allowed_tools:   ["web_search", "send_email"],
      tenant_id:       "tenant_acme",
      exp:             now + 3600
    }
    │
    ▼
AI model calls tool (e.g., web_search)
    │
    ▼
BEFORE EXECUTION — AuthStar evaluates tool call capsule:
    - VerifyAgentIdentity (model_id matches)
    - CheckDelegationChain (depth ≤ max, human origin required)
    - EvaluateRisk (risk score computed)
    - CheckToolPermission (tool in allowed_tools)
    - AuthorizeToolCall (resource pattern check)
    - Allow or Deny
    │
    ▼
Ed25519-signed attestation returned
    │
    ▼
Tool executes (if allowed) / blocked (if denied)
    │
    ▼
Immutable audit record written:
    eiaa_executions { task_id, parent_action_id, agent_id, model_id,
                      tool_name, decision, attestation, input_context }
    │
    ▼
Full task chain queryable forever:
    GET /api/v1/audit/task/{task_id}
```

### The delegation model

```
Depth 0:  Human user (usr_human123)
          │ authenticates → human JWT
          │ requests agent token → EIAA capsule evaluates delegation
          ▼
Depth 1:  AI Agent (agt_abc123 / claude-3-5-sonnet)
          │ carries: agent JWT with delegation_chain = ["usr_human123"]
          │ calls tool → EIAA capsule evaluates tool call
          ▼
Depth 2:  Sub-agent (agt_def456 / code_interpreter)
          │ carries: agent JWT with delegation_chain = ["usr_human123", "agt_abc123"]
          │ max_delegation_depth enforced by capsule — cannot go deeper

Depth 3+: DENIED — delegation_chain length exceeds max_depth
```

---

## 4. The Full Authorization Workflow

### Step-by-step walkthrough: "Book a flight from NYC to SFO"

**Step 1 — User authenticates**

The human user signs in through the normal AuthStar EIAA flow and receives a human JWT:

```json
{
  "sub": "usr_human123",
  "principal_type": "human",
  "tenant_id": "acme",
  "session_type": "end_user",
  "exp": 1741262000
}
```

**Step 2 — User requests agent token**

The user's application delegates the task to Claude:

```http
POST /api/v1/agents/token
Authorization: Bearer <human_jwt>

{
  "agent_id": "agt_claude",
  "task_description": "Book flight NYC → SFO",
  "requested_tools": ["web_search", "send_email"],
  "ttl_seconds": 3600
}
```

AuthStar runs an EIAA capsule evaluating whether this user is allowed to delegate to this agent with these tools. If the capsule allows, an **agent JWT** is issued:

```json
{
  "sub": "agt_claude",
  "principal_type": "ai_agent",
  "agent_id": "agt_claude",
  "model_id": "claude-3-5-sonnet-20241022",
  "task_id": "task_xyz789",
  "delegation_chain": ["usr_human123"],
  "allowed_tools": ["web_search", "send_email"],
  "tenant_id": "acme",
  "exp": 1741265600
}
```

**Step 3 — Agent calls a tool**

Claude decides to call `web_search`. Before it executes, the SDK calls AuthStar:

```http
POST /api/v1/agents/authorize
Authorization: Bearer <agent_jwt>
X-Tool-Name: web_search
X-Tool-Args-Hash: sha256({"query": "flights NYC to SFO"})
```

**Step 4 — EIAA capsule evaluates the tool call**

The `EiaaAuthzLayer` middleware processes the request. Because `claims.principal_type == "ai_agent"`, it routes to the agent-specific capsule for action `agent:web_search`.

The capsule executes in Wasmtime:

```
VerifyAgentIdentity(model_id = "claude-3-5-sonnet-20241022") → ✅
CheckDelegationChain(max_depth = 2, require_human_origin = true) → ✅ (depth=1)
EvaluateRisk(profile = "agent_default") → risk_score = 12
if risk_score > 60 → Deny (not triggered)
CheckToolPermission("web_search") → ✅ (in allowed_tools)
Allow
```

**Step 5 — Attested decision returned**

```json
{
  "allowed": true,
  "decision_ref": "dec_001",
  "attestation": {
    "signature_b64": "Ed25519-signature...",
    "timestamp": "2026-03-06T10:00:10Z"
  }
}
```

**Step 6 — Tool executes and result is recorded**

```http
POST /api/v1/agents/record
Authorization: Bearer <agent_jwt>

{
  "tool_name": "web_search",
  "result_hash": "sha256(search_results...)"
}
```

An audit record is written to `eiaa_executions`:

```
task_id:          task_xyz789
parent_action_id: null  (first action in chain)
principal_type:   ai_agent
agent_id:         agt_claude
model_id:         claude-3-5-sonnet-20241022
tool_name:        web_search
decision:         { "allow": true }
risk_score:       12
attestation:      Ed25519 signed
input_context:    full JSON (for re-execution)
```

**Step 7 — Payment attempt is denied**

Later in the same task, Claude tries `make_payment`. Risk score spikes to 72:

```
CheckToolPermission("make_payment") → ✅ (in allowed_tools — different agent config)
EvaluateRisk → risk_score = 72
if risk_score > 60 → Deny
```

Response:

```json
{
  "allowed": false,
  "reason": "Risk score 72 exceeds threshold 60",
  "decision_ref": "dec_004",
  "attestation": { "signature_b64": "...", "timestamp": "2026-03-06T10:00:45Z" }
}
```

The tool call never executes. The denial is attested and stored.

**Step 8 — Query the full task chain**

At any time, an admin or the user can retrieve the complete causal record:

```http
GET /api/v1/audit/task/task_xyz789
Authorization: Bearer <human_or_admin_jwt>
```

Response:

```json
{
  "task_id": "task_xyz789",
  "human_user_id": "usr_human123",
  "agent_id": "agt_claude",
  "model_id": "claude-3-5-sonnet-20241022",
  "started_at": "2026-03-06T10:00:00Z",
  "completed_at": "2026-03-06T10:00:45Z",
  "total_actions": 4,
  "actions": [
    { "decision_ref": "dec_001", "tool_name": "web_search",  "decision": "ALLOWED", "risk_score": 12, "parent_action_id": null },
    { "decision_ref": "dec_002", "tool_name": "web_search",  "decision": "ALLOWED", "risk_score": 14, "parent_action_id": "dec_001" },
    { "decision_ref": "dec_003", "tool_name": "send_email",  "decision": "ALLOWED", "risk_score": 18, "parent_action_id": "dec_002" },
    { "decision_ref": "dec_004", "tool_name": "make_payment","decision": "DENIED",  "risk_score": 72, "reason": "Risk score 72 exceeds threshold 60", "parent_action_id": "dec_003" }
  ],
  "re_execution_verified": true,
  "attestation_chain_valid": true
}
```

---

## 5. What Changes — Component by Component

### Already working — zero changes required

| Component | File | Why no changes needed |
|-----------|------|-----------------------|
| WASM capsule compiler | `capsule_compiler/src/lib.rs` | AST extension is purely additive |
| WASM runtime (Wasmtime) | `capsule_runtime/src/wasm_host.rs` | Host function registration is additive |
| Ed25519 attestation | `runtime_service/src/main.rs` | Works for any principal type |
| Re-execution service | `services/reexecution_service.rs` | Already stores full `input_context` |
| Nonce replay protection | `services/nonce_store.rs` | Principal-agnostic |
| Audit writer | `services/audit_writer.rs` | Additive new fields only |
| Risk engine | `risk_engine/` | Context-agnostic scoring |
| Multi-tenancy / RLS | migrations | Agent principals are tenant-scoped |
| gRPC runtime client | `clients/runtime_client.rs` | No changes |

### Needs backward-compatible extension

| Component | File | Change |
|-----------|------|--------|
| JWT `Claims` struct | `auth_core/src/jwt.rs` | Add optional fields with `#[serde(default)]` |
| `RuntimeContext` | `capsule_runtime/src/wasm_host.rs` | Add optional fields with `#[serde(default)]` |
| EIAA capsule AST | `capsule_compiler/src/ast.rs` | Add new `Step` variants (old policies still compile) |
| `EiaaAuthzLayer` middleware | `middleware/eiaa_authz.rs` | Add `principal_type` routing branch |
| `AuditRecord` | `services/audit_writer.rs` | Add optional `task_id`, `agent_id`, etc. |

### Needs new implementation

| Component | Location | Description |
|-----------|----------|-------------|
| `agent_principals` table | Migration `043_agent_principals.sql` | Stores registered AI agents per tenant |
| Agent registration route | `routes/agents/register.rs` | `POST /api/v1/agents/register` |
| Agent token issuance route | `routes/agents/token.rs` | `POST /api/v1/agents/token` |
| Agent authorization route | `routes/agents/authorize.rs` | `POST /api/v1/agents/authorize` |
| Task chain audit route | `routes/admin/audit_task_chain.rs` | `GET /api/v1/audit/task/{id}` |
| Task chain schema | Migration `044_agent_task_chain.sql` | New columns on `eiaa_executions` |
| Python SDK | `sdks/python/authstar_agent/` | `pip install authstar-agent` |
| TypeScript SDK | `sdks/typescript/authstar-agent/` | `npm install @authstar/agent` |
| Webhook service | `services/webhook_service.rs` | Real-time event delivery |

---

## 6. Sprint A — Non-Human Principal Support

**Duration:** 2 weeks (8 days actual work)  
**Goal:** AuthStar can issue and verify identity tokens for AI agents, not just humans.

### Task A.1 — Extend JWT Claims structure

**File:** `backend/crates/auth_core/src/jwt.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub sid: String,
    pub tenant_id: String,
    pub session_type: String,

    // NEW — backward-compatible (all default to "human" / None / [])
    #[serde(default = "default_principal_type")]
    pub principal_type: String,          // "human" | "ai_agent" | "service"

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,        // "agt_abc123"

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,        // "claude-3-5-sonnet-20241022"

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,         // "task_xyz789"

    #[serde(default)]
    pub delegation_chain: Vec<String>,   // ["usr_human123", "agt_parent456"]

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>, // ["web_search", "send_email"]
}

fn default_principal_type() -> String { "human".to_string() }
```

All existing tokens without these fields deserialize correctly — `serde(default)` is applied. All old code continues to work unchanged. Effort: **2 days**.

### Task A.2 — Database schema: `agent_principals` table

**File:** `backend/crates/db_migrations/migrations/043_agent_principals.sql`

```sql
CREATE TABLE agent_principals (
    id               TEXT PRIMARY KEY DEFAULT ('agt_' || gen_random_uuid()::text),
    tenant_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    model_id         TEXT NOT NULL,       -- "claude-3-5-sonnet-20241022"
    model_version    TEXT NOT NULL,
    model_provider   TEXT NOT NULL,       -- "anthropic" | "openai" | "custom"
    allowed_tools    JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_delegation_depth INTEGER NOT NULL DEFAULT 1,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       TEXT NOT NULL
);

ALTER TABLE agent_principals ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_principals_tenant_isolation ON agent_principals
    USING (tenant_id = current_setting('app.current_org_id', true)::text);

CREATE INDEX idx_agent_principals_tenant ON agent_principals(tenant_id);
CREATE INDEX idx_agent_principals_model  ON agent_principals(model_id, model_version);
```

Effort: **1 day**.

### Task A.3 — Agent registration route

**Endpoint:** `POST /api/v1/agents/register`  
**EIAA action:** `agents:register`

```json
// Request
{
  "name": "Claude Assistant",
  "model_id": "claude-3-5-sonnet-20241022",
  "model_version": "20241022",
  "model_provider": "anthropic",
  "allowed_tools": ["web_search", "send_email", "read_file"],
  "max_delegation_depth": 2
}

// Response
{
  "agent_id": "agt_abc123",
  "name": "Claude Assistant",
  "model_id": "claude-3-5-sonnet-20241022",
  "created_at": "2026-03-06T10:00:00Z"
}
```

Effort: **2 days**.

### Task A.4 — Agent token issuance route

**Endpoint:** `POST /api/v1/agents/token`  
**Auth required:** Human JWT (`principal_type == "human"`)

```json
// Request (from user's application)
{
  "agent_id": "agt_abc123",
  "task_description": "Book a flight from NYC to SFO",
  "requested_tools": ["web_search", "send_email"],
  "ttl_seconds": 3600
}

// Response
{
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2026-03-06T11:00:00Z",
  "task_id": "task_xyz789"
}
```

The issuance flow runs an EIAA capsule before issuing the token. The capsule checks: Is this user's risk score acceptable? Does the user's subscription allow AI agent delegation? Are the requested tools within the registered agent's `allowed_tools`? Effort: **3 days**.

### Sprint A total: 8 days — FEASIBLE

---

## 7. Sprint B — Tool Call Authorization Capsules

**Duration:** 2 weeks (7 days actual work)  
**Goal:** Every AI agent tool call is authorized by a WASM capsule before execution.

### Task B.1 — Extend AST with agent-specific steps

**File:** `backend/crates/capsule_compiler/src/ast.rs`

Three new `Step` variants are added. Existing policies are unaffected (the compiler matches on exhaustive arms but all old variants are unchanged):

```rust
/// Verify the requesting principal is a known, registered AI agent
VerifyAgentIdentity {
    model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_version: Option<String>,
},

/// Enforce maximum delegation depth and optionally require human origin
CheckDelegationChain {
    max_depth: u8,
    #[serde(default)]
    require_human_origin: bool,
},

/// Assert a specific tool call is within the agent's scope
AuthorizeToolCall {
    tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_pattern: Option<String>,  // e.g., "email:*@company.com"
    #[serde(default)]
    require_user_confirmation: bool,
},

/// Check if the tool is in the agent's allowed_tools claim
CheckToolPermission {
    tool_name: String,
},
```

Effort: **1 day**.

### Task B.2 — Extend RuntimeContext for tool calls

**File:** `backend/crates/capsule_runtime/src/wasm_host.rs`

```rust
pub struct RuntimeContext {
    // --- existing fields ---
    pub subject_id: i64,
    pub risk_score: i32,
    pub factors_satisfied: Vec<i32>,
    pub assurance_level: u8,
    // ...

    // --- NEW: agent context (all optional, backward-compatible) ---
    pub principal_type: Option<String>,
    pub agent_id: Option<String>,
    pub model_id: Option<String>,
    pub task_id: Option<String>,
    pub delegation_chain: Vec<String>,

    // --- NEW: tool call context ---
    pub tool_name: Option<String>,
    pub tool_args_hash: Option<String>,  // SHA-256 of args JSON
    pub allowed_tools: Vec<String>,
}
```

Effort: **1 day**.

### Task B.3 — New WASM host functions

**File:** `backend/crates/capsule_runtime/src/wasm_host.rs`

Three new host functions are registered in the Wasmtime linker:

| Host function | Signature | What it checks |
|---------------|-----------|----------------|
| `verify_agent_identity` | `(model_id_ptr, len) → i32` | `context.model_id == expected_model_id` |
| `check_delegation_depth` | `(max_depth) → i32` | `delegation_chain.len() ≤ max_depth` |
| `check_tool_permission` | `(tool_name_ptr, len) → i32` | `tool_name ∈ allowed_tools` |

These follow the same host-function pattern as existing functions (`get_risk_score`, `get_assurance_level`, etc.). Effort: **2 days**.

### Task B.4 — EIAA middleware: agent routing

**File:** `backend/crates/api_server/src/middleware/eiaa_authz.rs`

In the `EiaaAuthzService::call()` method, after extracting claims:

```rust
// Route to agent-specific capsule when principal is an AI agent
let effective_action = match claims.principal_type.as_deref() {
    Some("ai_agent") => format!("agent:{}", action),
    _ => action.to_string(),
};

// Assemble RuntimeContext with agent fields
let runtime_ctx = RuntimeContext {
    // ... existing fields ...
    principal_type:   claims.principal_type.clone(),
    agent_id:         claims.agent_id.clone(),
    model_id:         claims.model_id.clone(),
    task_id:          claims.task_id.clone(),
    delegation_chain: claims.delegation_chain.clone(),
    tool_name:        req.headers().get("X-Tool-Name")
                         .and_then(|v| v.to_str().ok())
                         .map(|s| s.to_string()),
    tool_args_hash:   req.headers().get("X-Tool-Args-Hash")
                         .and_then(|v| v.to_str().ok())
                         .map(|s| s.to_string()),
    allowed_tools:    claims.allowed_tools.clone().unwrap_or_default(),
};
```

Effort: **2 days**.

### Task B.5 — Example agent scope policy template

The Policy Builder gains a new built-in template `agent_scope_default`. This is the JSON AST that gets compiled to WASM for agent tool-call authorization:

```json
{
  "version": "EIAA-AST-1.0",
  "sequence": [
    { "verify_agent_identity": { "model_id": "${model_id}" } },
    { "check_delegation_chain": { "max_depth": 2, "require_human_origin": true } },
    { "evaluate_risk": { "profile": "agent_default" } },
    {
      "if": {
        "condition": { "risk_score": { "comparator": ">", "value": 60 } },
        "then": [{ "deny": true }],
        "else": [
          { "check_tool_permission": { "tool_name": "${tool_name}" } },
          {
            "if": {
              "condition": { "authz_result": { "comparator": "==", "value": 1 } },
              "then": [{ "allow": true }],
              "else": [{ "deny": true }]
            }
          }
        ]
      }
    }
  ]
}
```

Effort: **1 day**.

### Sprint B total: 7 days — FEASIBLE

---

## 8. Sprint C — Task Chain Audit Trail

**Duration:** 1 week (4 days actual work)  
**Goal:** Every action in a multi-step agent task is linked in a queryable causal chain.

### Task C.1 — Extend `eiaa_executions` table

**File:** `backend/crates/db_migrations/migrations/044_agent_task_chain.sql`

```sql
ALTER TABLE eiaa_executions
    ADD COLUMN task_id          TEXT,
    ADD COLUMN parent_action_id TEXT,
    ADD COLUMN delegation_depth INTEGER DEFAULT 0,
    ADD COLUMN principal_type   TEXT    DEFAULT 'human',
    ADD COLUMN agent_id         TEXT,
    ADD COLUMN model_id         TEXT,
    ADD COLUMN tool_name        TEXT,
    ADD COLUMN tool_args_hash   TEXT;

-- Performance indexes
CREATE INDEX idx_eiaa_executions_task_chain      ON eiaa_executions(task_id, created_at);
CREATE INDEX idx_eiaa_executions_agent           ON eiaa_executions(agent_id, created_at);
CREATE INDEX idx_eiaa_executions_parent          ON eiaa_executions(parent_action_id);
CREATE INDEX idx_eiaa_executions_principal_type  ON eiaa_executions(principal_type, created_at);
```

All existing rows default to `principal_type = 'human'` and `delegation_depth = 0`. Existing queries are unaffected. Effort: **1 day**.

### Task C.2 — Extend AuditRecord structure

**File:** `backend/crates/api_server/src/services/audit_writer.rs`

```rust
pub struct AuditRecord {
    // --- existing fields ---
    pub decision_ref:                String,
    pub capsule_hash_b64:            String,
    pub action:                      String,
    pub tenant_id:                   String,
    pub input_context:               Option<String>,
    pub decision:                    AuditDecision,
    pub attestation_signature_b64:   String,
    // ...

    // --- NEW: task chain fields (all optional) ---
    pub task_id:          Option<String>,
    pub parent_action_id: Option<String>,
    pub delegation_depth: u8,              // default 0
    pub principal_type:   String,          // default "human"
    pub agent_id:         Option<String>,
    pub model_id:         Option<String>,
    pub tool_name:        Option<String>,
    pub tool_args_hash:   Option<String>,
}
```

Effort: **1 day**.

### Task C.3 — Task chain query route

**Endpoint:** `GET /api/v1/audit/task/{task_id}`  
**Auth:** JWT (human or admin)  
**EIAA action:** `audit:read`

Returns the full causal chain for a task — every tool call the agent made, in order, with decision, risk score, attestation reference, and parent link. Includes re-execution and attestation chain validity flags.

Also added: `GET /api/v1/audit/agent/{agent_id}` — returns all actions ever taken by a registered agent.

Effort: **2 days**.

### Sprint C total: 4 days — FEASIBLE

---

## 9. Sprint D — SDK Integration

**Duration:** 2 weeks (10 days actual work)  
**Goal:** Drop-in SDKs for Anthropic/OpenAI and a real-time webhook service.

### Python SDK (`authstar-agent`)

**Install:** `pip install authstar-agent`

```python
from authstar_agent import AgentAuthz

authz = AgentAuthz(
    tenant_id="acme",
    api_key="sk_live_...",
    agent_id="agt_abc123",
    task_id="task_xyz789",
    base_url="https://api.authstar.com"
)

# Before any tool call:
decision = authz.authorize_tool_call(
    tool_name="send_email",
    args={"to": "user@example.com", "body": "Flight booked!"}
)

if decision.allowed:
    result = send_email(...)
    authz.record_execution(
        tool_name="send_email",
        result_hash=hashlib.sha256(str(result).encode()).hexdigest()
    )
else:
    raise AgentAuthzDenied(decision.reason, decision.attestation)
```

Effort: **4 days**.

### TypeScript SDK (`@authstar/agent`)

**Install:** `npm install @authstar/agent`

```typescript
import { AgentAuthz } from '@authstar/agent';

const authz = new AgentAuthz({
  tenantId: 'acme',
  apiKey: 'sk_live_...',
  agentId: 'agt_abc123',
  taskId: 'task_xyz789',
  baseUrl: 'https://api.authstar.com'
});

const decision = await authz.authorizeToolCall({
  toolName: 'send_email',
  args: { to: 'user@example.com', body: 'Flight booked!' }
});

if (decision.allowed) {
  const result = await sendEmail(...);
  await authz.recordExecution({
    toolName: 'send_email',
    resultHash: sha256(JSON.stringify(result))
  });
} else {
  throw new AgentAuthzDenied(decision.reason, decision.attestation);
}
```

Effort: **4 days**.

### Webhook service

**File:** `backend/crates/api_server/src/services/webhook_service.rs`

Three event types are emitted in real-time to tenant-configured endpoints:

| Event | When fired |
|-------|-----------|
| `agent.action.authorized` | Tool call allowed |
| `agent.action.denied` | Tool call denied |
| `agent.task.completed` | Task chain ends (all tools resolved) |

Webhook payload includes: `event`, `timestamp`, `tenant_id`, `task_id`, `agent_id`, `model_id`, `tool_name`, `decision_ref`, `risk_score`, `attestation.signature_b64`.

The service implements exponential back-off retry with jitter, HMAC-SHA256 signature for payload verification (same model as Stripe webhooks), and dead-letter logging when max retries are exhausted. Effort: **2 days**.

### Sprint D total: 10 days — FEASIBLE

---

## 10. Integration Guide — Anthropic Claude

### Current flow (no AuthStar)

```
User → "Book me a flight from NYC to SFO"
  ↓
Claude chooses tools: [web_search, send_email]
  ↓
Tools execute directly — no authorization layer, no audit proof
```

### With AuthStar

```python
from anthropic import Anthropic
from authstar_agent import AgentAuthz

client = Anthropic(api_key="...")
authz = AgentAuthz(
    tenant_id="acme",
    api_key="sk_live_...",
    agent_id="agt_claude",
    task_id="task_xyz789"
)

def execute_tool_with_authz(tool_name: str, tool_args: dict):
    # 1. Pre-authorize
    decision = authz.authorize_tool_call(tool_name, tool_args)
    if not decision.allowed:
        raise ToolExecutionDenied(decision.reason)

    # 2. Execute
    result = execute_tool(tool_name, tool_args)

    # 3. Record (writes to audit trail)
    authz.record_execution(
        tool_name=tool_name,
        result_hash=hashlib.sha256(str(result).encode()).hexdigest()
    )
    return result

# Claude tool use loop
message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    tools=[
        {"name": "web_search",  "description": "Search the web", "input_schema": {...}},
        {"name": "send_email",  "description": "Send an email",  "input_schema": {...}},
    ],
    messages=[{"role": "user", "content": "Book me a flight from NYC to SFO"}]
)

for block in message.content:
    if block.type == "tool_use":
        try:
            result = execute_tool_with_authz(block.name, block.input)
        except ToolExecutionDenied as e:
            print(f"Blocked by AuthStar: {e.reason}")
            # Return denial to Claude as a tool_result
```

What this gives Anthropic:
- Every tool call has an Ed25519-attested authorization decision
- Risk score evaluated in real-time — a suddenly risky action is denied before it executes
- Full task chain queryable for compliance and incident response
- No changes required to the Claude model itself — authorization is in the SDK wrapper

---

## 11. Integration Guide — OpenAI GPT Actions

### Current flow (no AuthStar)

```
User → "Send an email to my team about the meeting"
  ↓
GPT calls send_email action via OAuth token / API key
  ↓
Email sent — no cryptographic proof of what was authorized
```

### With AuthStar

```typescript
import OpenAI from 'openai';
import { AgentAuthz } from '@authstar/agent';

const openai = new OpenAI({ apiKey: '...' });
const authz = new AgentAuthz({
  tenantId: 'acme',
  apiKey: 'sk_live_...',
  agentId: 'agt_gpt4o',
  taskId: 'task_xyz789'
});

async function executeActionWithAuthz(actionName: string, args: any) {
  const decision = await authz.authorizeToolCall({ toolName: actionName, args });

  if (!decision.allowed) {
    throw new ActionExecutionDenied(decision.reason, decision.attestation);
  }

  const result = await executeAction(actionName, args);

  await authz.recordExecution({
    toolName: actionName,
    resultHash: sha256(JSON.stringify(result))
  });

  return result;
}

const completion = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Send an email to my team about the meeting' }],
  tools: [{ type: 'function', function: { name: 'send_email', parameters: {...} } }]
});

for (const choice of completion.choices) {
  if (choice.message.tool_calls) {
    for (const toolCall of choice.message.tool_calls) {
      try {
        await executeActionWithAuthz(
          toolCall.function.name,
          JSON.parse(toolCall.function.arguments)
        );
      } catch (error) {
        if (error instanceof ActionExecutionDenied) {
          console.error(`AuthStar denied: ${error.reason}`);
          // Attestation proof available: error.attestation.signature_b64
        }
      }
    }
  }
}
```

What this gives OpenAI's Operator model:
- Dynamic, policy-driven scope enforcement — not static API keys
- Delegation chain proof: GPT acted on behalf of a specific human at a specific time
- Attestations available for SOC2 / ISO27001 compliance evidence
- Real-time webhook events for each authorized / denied action

---

## 12. New API Endpoints

All new endpoints require an active session JWT and are covered by EIAA capsule evaluation.

| Method | Path | Description | Auth | EIAA Action |
|--------|------|-------------|------|-------------|
| `POST` | `/api/v1/agents/register` | Register a new AI agent principal | Human JWT (Admin) | `agents:register` |
| `GET`  | `/api/v1/agents` | List registered agents | Human JWT | `agents:read` |
| `GET`  | `/api/v1/agents/:agent_id` | Get agent details | Human JWT | `agents:read` |
| `PUT`  | `/api/v1/agents/:agent_id` | Update agent (tools, depth) | Human JWT (Admin) | `agents:manage` |
| `DELETE` | `/api/v1/agents/:agent_id` | Deactivate agent | Human JWT (Admin) | `agents:manage` |
| `POST` | `/api/v1/agents/token` | Issue scoped agent JWT | Human JWT | `agents:delegate` |
| `POST` | `/api/v1/agents/authorize` | Authorize a tool call | Agent JWT | `agent:{tool_name}` |
| `POST` | `/api/v1/agents/record` | Record tool execution result | Agent JWT | `agents:record` |
| `GET`  | `/api/v1/audit/task/:task_id` | Get full task chain | Human or Admin JWT | `audit:read` |
| `GET`  | `/api/v1/audit/agent/:agent_id` | Get all actions by an agent | Human or Admin JWT | `audit:read` |

---

## 13. Database Schema Changes

### New table: `agent_principals`

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | `agt_` prefix + UUID |
| `tenant_id` | TEXT FK | Row-level security tenant scope |
| `name` | TEXT | Display name (e.g., "Claude Assistant") |
| `model_id` | TEXT | Model identifier (e.g., `claude-3-5-sonnet-20241022`) |
| `model_version` | TEXT | Version string |
| `model_provider` | TEXT | `anthropic` / `openai` / `custom` |
| `allowed_tools` | JSONB | Array of permitted tool names |
| `max_delegation_depth` | INTEGER | Max chain depth (default 1) |
| `is_active` | BOOLEAN | Soft delete flag |
| `created_by` | TEXT | Human user ID who registered |
| `created_at` | TIMESTAMPTZ | — |

RLS policy: `tenant_id = current_setting('app.current_org_id')`.

### Modified table: `eiaa_executions` (additive columns)

| New Column | Type | Default | Description |
|------------|------|---------|-------------|
| `task_id` | TEXT | NULL | Links all tool calls in one task |
| `parent_action_id` | TEXT | NULL | Previous `decision_ref` in the chain |
| `delegation_depth` | INTEGER | 0 | Depth in delegation chain |
| `principal_type` | TEXT | `'human'` | `human` / `ai_agent` / `service` |
| `agent_id` | TEXT | NULL | Registered agent ID |
| `model_id` | TEXT | NULL | Model identifier |
| `tool_name` | TEXT | NULL | Name of tool that was called |
| `tool_args_hash` | TEXT | NULL | SHA-256 of tool arguments JSON |

All existing rows retain `principal_type = 'human'`. No data is lost. No existing queries break.

---

## 14. Security Model

### Agent token constraints

- **Short TTL:** Default 1 hour, maximum configurable per tenant
- **Tool scope binding:** `allowed_tools` claim is verified by the capsule — an agent cannot call a tool not in its scope even with a valid token
- **Delegation depth cap:** `max_delegation_depth` enforced in the WASM capsule — runaway sub-agent chains are cryptographically blocked
- **Human origin requirement:** Policies can require `require_human_origin: true` — agent tokens not traceable to a human are denied
- **Revocation:** Agent tokens use the same session ID mechanism as human sessions — revoking via `DELETE /api/admin/v1/sessions/:session_id` invalidates the agent token immediately
- **Risk gate:** Agent capsules evaluate the same risk engine as human requests — a spike in IP risk score or geo-anomaly can deny tool calls in real-time

### Cryptographic guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| Agent token integrity | ES256 JWT signed with the same key as human tokens |
| Tool call authorization proof | Ed25519 attestation on every EIAA decision |
| Tamper-evident policy | WASM capsule is signed; runtime verifies signature before execution |
| Replay protection | Nonce store (Redis + PostgreSQL) — identical request cannot be replayed |
| Re-execution forensics | `input_context` (full JSON) stored with every audit record — any decision is re-playable |
| Causal chain integrity | `parent_action_id` creates a linked chain — deletions would break the chain hash |

### What an attacker cannot do

1. **Forge a tool authorization** — The decision is Ed25519-signed by the EIAA runtime. Without the private key (held by the runtime service, never exposed), a signature cannot be forged.
2. **Replay a past authorization** — Nonces are single-use. A captured valid response cannot be replayed for a different tool call.
3. **Expand tool scope** — The `allowed_tools` claim is inside the signed JWT. An agent cannot modify this claim without invalidating the signature.
4. **Deepen the delegation chain** — The capsule checks `delegation_chain.len() ≤ max_depth`. A forged chain would require forging the JWT.
5. **Escape audit** — Every call to `/api/v1/agents/authorize` writes an `AuditRecord` regardless of the decision. Denial is audited as thoroughly as approval.

---

## 15. Risk Assessment

### Technical risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Backward compatibility break in Claims | Low | High | `#[serde(default)]` on all new fields; existing token test suite runs unchanged |
| Performance regression | Low | Medium | Agent tokens use the same ES256 JWT signing — no new crypto overhead |
| WASM host function bugs | Medium | Medium | Reuse existing host function patterns; unit test every new function |
| Database migration failure | Low | High | Staging test; all new columns are nullable with defaults |
| SDK adoption friction | Medium | Low | Comprehensive examples for Anthropic and OpenAI patterns |

### Operational risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Audit volume explosion (AI agents call APIs at high frequency) | High | Medium | Backpressure monitoring already in place (GAP-2 fix); scale async channel |
| Task chain query performance with large chains | Medium | Medium | Indexes on `task_id`, `agent_id`, `parent_action_id`; pagination |
| Agent token abuse (leaked token used by malicious party) | Medium | High | Short TTL; revocation via session invalidation; IP binding option |
| Delegation chain attack (agent tries to spawn deeper sub-agents) | Low | High | `max_depth` enforced in WASM capsule; cannot be bypassed without forging JWT |

---

## 16. Competitive Advantage

### Why no current competitor offers this

| Competitor | What they have | What they lack vs AuthStar |
|------------|---------------|---------------------------|
| **Auth0 / Okta** | Human identity, OAuth, RBAC | No WASM capsule, no Ed25519 attestation, no re-executable audit, no AI agent model |
| **AWS Cognito** | Human identity, static IAM | No policy capsule, no re-execution, no agent model |
| **Permit.io / Oso** | Policy engines | No cryptographic attestation, no re-execution proof, no agent token model |
| **OpenFGA** | Graph-based authorization | No WASM, no attestation, no AI agent principal concept |
| **Clerk / Stytch** | Developer-friendly auth | No EIAA, no capsule, no audit re-execution |

### AuthStar's unique combination for AI agents

| Capability | Available after Sprint A–D |
|------------|---------------------------|
| Non-human principal tokens | ✅ Sprint A |
| WASM-compiled policy capsules | ✅ Already working |
| Ed25519 cryptographic attestation per decision | ✅ Already working |
| Re-executable audit trail (forensic proof) | ✅ Already working |
| Risk-aware authorization (real-time risk score) | ✅ Already working |
| Task chain causal audit | ✅ Sprint C |
| Delegation chain depth enforcement | ✅ Sprint B |
| Tool-call scope enforcement | ✅ Sprint B |
| Python + TypeScript SDKs | ✅ Sprint D |
| Real-time webhook events | ✅ Sprint D |

---

## 17. Performance Targets

| Metric | Target | How measured |
|--------|--------|-------------|
| Agent token issuance latency | < 100 ms p99 | `POST /api/v1/agents/token` end-to-end |
| Tool call authorization latency | < 50 ms p99 | `POST /api/v1/agents/authorize` end-to-end |
| Audit record write latency | < 10 ms p99 | Time from `record()` to async channel enqueue |
| Task chain query latency | < 200 ms p99 | `GET /api/v1/audit/task/{id}` with 100 actions |
| Re-execution verification success rate | > 99.9% | % of audit records that re-execute to same decision |
| Attestation verification success rate | 100% | % of attestations with valid Ed25519 signatures |
| Webhook delivery latency (p99) | < 500 ms | Time from event to first webhook delivery attempt |

These targets are achievable because the core EIAA pipeline — capsule cache lookup, gRPC runtime execution, attestation verification, nonce check, audit write — already meets sub-50 ms p99 for human requests. Agent requests reuse the same pipeline.

---

## 18. Go-to-Market Strategy

### Phase 1 — Pilot with Anthropic (Months 1–3)

**Goal:** Validate AuthStar agent authorization with Claude tool use in production.

- Python SDK (`authstar-agent`) integrated with Anthropic's Claude SDK
- 3 pilot customers using Claude + AuthStar for tool authorization
- Case study: "How [Customer] achieved SOC2 compliance for AI agent actions"
- Success criteria: > 100K agent tool calls/day, zero unauthorized executions, < 50 ms p99 latency

### Phase 2 — Expand to OpenAI (Months 4–6)

**Goal:** Integrate AuthStar with OpenAI GPT Actions and Operator model.

- TypeScript SDK (`@authstar/agent`) integrated with OpenAI's Actions framework
- Webhook integration for real-time action notifications
- 10 enterprise customers using GPT + AuthStar
- Success criteria: > 500K agent tool calls/day, partnership announcement

### Phase 3 — Open Ecosystem (Months 7–12)

**Goal:** Position AuthStar as the de facto authorization layer for the AI agent economy.

- SDKs for LangChain, AutoGPT, CrewAI, Semantic Kernel, Vercel AI SDK
- Public self-service onboarding
- Policy marketplace: pre-built agent authorization templates
- Success criteria: > 10M agent tool calls/day, 100+ customers

---

## 19. Effort Summary & Timeline

| Sprint | Goal | Days | Weeks | Confidence |
|--------|------|------|-------|------------|
| **Sprint A** | Non-Human Principal Support | 8 | 1.6 | 95% |
| **Sprint B** | Tool Call Authorization Capsules | 7 | 1.4 | 90% |
| **Sprint C** | Task Chain Audit Trail | 4 | 0.8 | 95% |
| **Sprint D** | SDK Integration | 10 | 2.0 | 85% |
| **Total planned** | | **29** | **5.8** | **91%** |
| **Buffer (38%)** | | 11 | 2.2 | — |
| **Total estimate** | | **40** | **8.0** | **95%** |

The 8-week estimate is **conservative and achievable**. The 38% buffer accounts for integration testing, security review, and SDK documentation polish.

### 3-day proof-of-concept to validate assumptions

Before committing to the full roadmap, a 3-day PoC validates the core assumptions:

- **Day 1:** Extend `Claims` with agent fields → issue agent token → verify Claims extraction
- **Day 2:** Extend `RuntimeContext` → create simple `VerifyAgentIdentity + Allow` policy → compile to WASM → execute with agent context → verify decision
- **Day 3:** Add `task_id` to `AuditRecord` → write audit record with task_id → query `eiaa_executions WHERE task_id = X` → verify results

If the PoC succeeds, the full roadmap is validated. Sprint A kicks off the following week.

---

## 20. What Already Works (No Changes Needed)

The following components require **zero changes** to support AI agent authorization:

| Component | Why it works unchanged |
|-----------|----------------------|
| `capsule_compiler/src/lib.rs` | New AST variants are additive; old policies compile unchanged |
| `capsule_runtime/src/wasm_host.rs` | New host functions are additive registrations |
| `services/attestation_verifier.rs` | Verifies Ed25519 signatures — principal-type agnostic |
| `services/nonce_store.rs` | Redis + PostgreSQL nonce store is principal-agnostic |
| `services/audit_writer.rs` | Async batch writer; new fields are additive |
| `services/reexecution_service.rs` | Already stores full `input_context`; works for any record |
| `risk_engine/` | Evaluates context signals; agent context feeds in via RuntimeContext |
| RLS (PostgreSQL row-level security) | Agent principals are tenant-scoped — same isolation model |
| `clients/runtime_client.rs` | Singleton gRPC client with circuit breaker — unchanged |
| `services/capsule_cache.rs` | Redis capsule cache — unchanged |

**Conclusion:** 95% of the infrastructure already exists. The 8-week roadmap is architectural extension, not ground-up development.

---

## Related Documents

- [`AI_AGENT_AUTHZ_TECHNICAL_FEASIBILITY.md`](../AI_AGENT_AUTHZ_TECHNICAL_FEASIBILITY.md) — Full technical feasibility analysis with complete Rust/Python/TypeScript code samples
- [`CEO_STRATEGIC_ANALYSIS.md`](../CEO_STRATEGIC_ANALYSIS.md) — Strategic context: what Anthropic and OpenAI would ask for
- [`EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md`](../EIAA_DEEP_RESEARCH_AND_GAP_ANALYSIS.md) — Current EIAA implementation status and gaps
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — Current system architecture
- [`docs/API_ENDPOINTS.md`](API_ENDPOINTS.md) — Current API endpoint reference

---

*Document authored from technical feasibility analysis — IBM Bob, Senior Technical Leader*  
*Date: 2026-03-06*
