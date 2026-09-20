# User Stories — E4: Agent Consent Flow

> **Epic:** [E4 — Agent Consent Flow](epic-e4-consent-flow.md)
> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R2 · **Priority:** P1
> **Stories:** 5 · ordered by dependency

---

## Story Map

```
US-01  Consent flow init (backend API + redirect URL)
  └── US-02  Consent screen UI (what the user sees and acts on)
       └── US-03  Token exchange (app receives agent JWT after grant)
US-04  Delegations management (user reviews + revokes active consents)   ← parallel
US-05  Consent record in audit chain (compliance linkage)                ← parallel after US-03
```

---

## US-01 — Consent Flow Initiation (Backend)

**As a** developer building an application that uses AI agents,
**I want to** initiate a consent flow for my user with a single API call,
**so that** I can redirect them to a hosted consent screen without building my own consent UI.

### Acceptance Criteria

- [ ] `POST /api/v1/consent/init` accepts: `agent_id` (string), `requested_tools` (string[]), `ttl_seconds` (integer, 1–86400), `redirect_uri` (string, must match a pre-registered URI for the tenant)
- [ ] Returns: `{ flow_id: string, consent_url: string, expires_at: ISO8601 }` — flow expires in 10 minutes if not completed
- [ ] `consent_url` is of the form `https://auth.authstar.dev/consent/:flow_id` — absolute URL, ready to redirect to
- [ ] `redirect_uri` validation: must match one of the tenant's pre-registered redirect URIs (configured in Admin → Settings → Allowed Redirect URIs); unregistered URIs return `400 ERR_INVALID_REDIRECT_URI`
- [ ] Flow state stored in Redis with 10-minute TTL: `consent_flow:{flow_id}` → `{ tenant_id, agent_id, requested_tools, ttl_seconds, redirect_uri, user_id: null }`
- [ ] `requested_tools` must be a subset of the agent's `allowed_tools` — tools not in `allowed_tools` return `400 ERR_TOOL_NOT_PERMITTED`
- [ ] Endpoint protected by tenant API key authentication (same as `authorize()`) — not user JWT

### Technical Notes

- New route: `POST /api/v1/consent/init` — behind `EiaaAuthzLayer` with `user:manage_factors` action (re-use existing; or add `consent:init` as a new action string)
- `flow_id` generated with `nanoid` — 21 chars, URL-safe
- Redirect URI pre-registration: add `allowed_redirect_uris TEXT[]` column to `organizations` table (new migration `078_consent_redirect_uris.sql`)
- Flow expiry: Redis key TTL = 600 seconds; if consent screen is not completed in 10 minutes, `GET /consent/:flow_id` returns `410 Gone`

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Unit tests: `requested_tools` subset check, redirect URI validation, flow_id uniqueness
- [ ] Integration test: valid init → `consent_url` returned → `GET :consent_url` renders consent screen (US-02)
- [ ] Integration test: unregistered `redirect_uri` → `400 ERR_INVALID_REDIRECT_URI`
- [ ] Migration `078_consent_redirect_uris.sql` applied forward-only

---

## US-02 — Consent Screen UI

**As an** end user,
**I want to** see a clear, understandable screen showing exactly what an AI agent is asking permission to do,
**so that** I can make an informed decision to grant or deny before the agent acts on my behalf.

### Acceptance Criteria

- [ ] `GET /consent/:flow_id` renders the hosted consent screen (server-rendered HTML — no client-side JS required to read or interact)
- [ ] Screen shows all of the following before any action button:
  - Tenant logo (from branding settings, or AuthStar default)
  - Agent name and model identity (e.g. "Research Agent — Claude 3.5 Sonnet")
  - List of requested tools with plain-English descriptions (e.g. `web_search` → "Search the web on your behalf")
  - Permission duration (e.g. "Valid for 1 hour" or "Until you revoke it")
  - A clear statement: "By clicking Grant, you authorise this agent to perform the above actions on your behalf."
- [ ] If the user is not authenticated, they are redirected to the tenant's sign-in page with `?return_to=/consent/:flow_id` — after sign-in they are returned to the consent screen
- [ ] **Grant** button: labelled "Grant Access"; green; requires one deliberate click (no double-click prevention needed for R2)
- [ ] **Deny** button: labelled "Deny"; secondary/outline style; positioned below Grant with clear visual separation
- [ ] Screen renders correctly on mobile (375px viewport minimum) — tool list wraps gracefully; buttons are full-width on mobile
- [ ] WCAG 2.1 AA: all interactive elements keyboard-navigable; tool list items have `aria-label`; Grant/Deny buttons have explicit `role="button"`
- [ ] If `flow_id` is expired or not found, render a clear error page: "This authorisation request has expired. Please return to [app name] and try again."
- [ ] `consent_screen_shown` instrumentation event fires on render with `tenant_id`, `agent_id`, `tool_count`

### Technical Notes

- Consent screen is a new route in the frontend at `/consent/:flow_id` — server-rendered via React SSR or a separate lightweight HTML template (decision for engineering; SSR preferred for performance)
- Plain-English tool descriptions stored per-tenant in `agent_tools_metadata` (new table in migration `079_agent_tool_metadata.sql`): `tenant_id`, `tool_name`, `display_name`, `description` — fallback to `tool_name` if no metadata exists
- Tenant logo loaded from existing `OrganizationBranding` settings
- Flow data fetched from Redis on page load: `GET /api/v1/consent/:flow_id/details` (new unauthenticated endpoint — only returns non-sensitive flow metadata: agent name, tools, ttl)

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Renders in ≤ 500ms (measured against p95 in staging)
- [ ] Mobile layout verified at 375px, 390px, 414px viewports
- [ ] Accessibility audit: keyboard navigation works; screen reader announces agent name and tool list correctly
- [ ] Expired flow_id renders error page — no 404 or unhandled error
- [ ] `consent_screen_shown` event fires and is verifiable

---

## US-03 — Consent Grant, Deny & Token Exchange

**As a** developer,
**I want to** receive a signed agent JWT after my user grants consent, and have a DENY recorded when they decline,
**so that** the agent can immediately begin making authorized tool calls on the user's behalf.

### Acceptance Criteria

**On Grant:**
- [ ] User clicks "Grant Access" → `POST /api/v1/consent/:flow_id/grant` is called (user's session JWT in cookie)
- [ ] AuthStar issues an agent JWT: `sub = agent_id`, `principal_type = "ai_agent"`, `delegation_chain = [user_id]`, `allowed_tools = requested_tools`, `exp = now + ttl_seconds`, `tenant_id`
- [ ] A one-time `code` is stored in Redis (`consent_code:{code}` → `agent_jwt`) with TTL = 60 seconds
- [ ] User is redirected to `redirect_uri?code=<code>&flow_id=<flow_id>`
- [ ] Consent grant written to `eiaa_executions` with `action = "user:delegate_to_agent"`, `principal_type = "human"`, full attestation — this is the compliance record
- [ ] `consent_granted` instrumentation event fires with `tenant_id`, `agent_id`, `user_id`, `tool_count`, `ttl_seconds`

**On Deny:**
- [ ] User clicks "Deny" → `POST /api/v1/consent/:flow_id/deny` is called
- [ ] DENY written to `eiaa_executions` with `action = "user:delegate_to_agent"`, `principal_type = "human"`, `allowed = false`
- [ ] User is redirected to `redirect_uri?error=consent_denied&flow_id=<flow_id>`
- [ ] `consent_denied` instrumentation event fires

**Token Exchange:**
- [ ] App calls `POST /api/v1/consent/exchange` with `{ code: string, flow_id: string }` (authenticated with tenant API key)
- [ ] Returns `{ agent_jwt: string, expires_at: ISO8601, allowed_tools: string[] }` if code is valid and not expired
- [ ] Code is consumed on first use — subsequent calls with same code return `400 ERR_CODE_ALREADY_USED`
- [ ] Expired code (> 60 seconds) returns `400 ERR_CODE_EXPIRED`

### Technical Notes

- Agent JWT issuance reuses existing `JwtService::sign_agent_token()` — no new JWT signing logic
- `consent_code` Redis key: `consent_code:{nanoid(21)}` → serialised agent JWT, TTL 60s
- Grant and Deny routes are **user-authenticated** (session cookie) — not API key; this is the user's action, not the app's
- `eiaa_executions` consent record: `capsule_id` can reference a special "consent capsule" compiled at agent registration; or use a sentinel value for the consent action — TBD with engineering

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: init → screen shown → grant → code in redirect → exchange → valid agent JWT with correct claims
- [ ] Integration test: init → deny → `error=consent_denied` in redirect
- [ ] Integration test: expired code → `400 ERR_CODE_EXPIRED`
- [ ] Integration test: code used twice → `400 ERR_CODE_ALREADY_USED`
- [ ] Agent JWT claims verified: `delegation_chain`, `allowed_tools`, `exp`, `principal_type` all correct

---

## US-04 — Delegations Management (User Profile)

**As an** end user,
**I want to** see all the AI agents I have authorised to act on my behalf and revoke any of them instantly,
**so that** I am always in control of what agents can do with my account.

### Acceptance Criteria

- [ ] User profile page → **Delegations** tab (new tab, visible only when ≥ 1 active delegation exists — or always visible with empty state)
- [ ] Active delegations list shows per delegation: agent name, model identity, tools granted (as pill tags), granted at (relative timestamp), expires at (or "Until revoked"), **Revoke** button
- [ ] Empty state: "No active agent delegations. Agents you authorize will appear here."
- [ ] **Revoke** button shows a confirmation: "Revoke access for [Agent Name]? The agent will be denied immediately." — **Revoke** (red) and **Cancel** buttons
- [ ] On confirmed revoke:
  - Redis blocklist key `agent_blocklist:{agent_id}:{user_id}` set with TTL = remaining token TTL
  - Next `authorize()` call with that agent JWT returns `DENY` with `ERR_REVOKED_DELEGATION` within 100ms
  - Delegation moves to "Revoked" section in the UI: shows revoked at timestamp
- [ ] Revoked delegations section is collapsed by default; expander shows count ("3 revoked")
- [ ] Revoked delegations are never deleted — visible indefinitely in the revoked section
- [ ] `consent_revoked` instrumentation event fires with `tenant_id`, `agent_id`, `user_id`, `ttl_remaining_seconds`

### Technical Notes

- `GET /api/v1/user/delegations` — new endpoint returning active and revoked delegations for the authenticated user
- Revocation: extend existing `POST /api/v1/agents/:id/revoke` to support user-scoped revocation (current implementation revokes all tokens for the agent; new variant revokes only tokens with `delegation_chain` containing `user_id`)
- Redis blocklist key includes `user_id` to allow user-scoped revocation without revoking the agent for other users

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Delegations tab renders active delegations and empty state correctly
- [ ] Revoke integration test: revoke delegation → next `authorize()` with that JWT returns DENY within 100ms
- [ ] Revoked delegation visible in revoked section after revoke action
- [ ] `consent_revoked` event fires and is verifiable

---

## US-05 — Consent Record in Audit Chain

**As a** Compliance/Security Lead,
**I want to** see the user consent event in the authorization audit trail for any delegated agent action,
**so that** I can prove the chain from "user consented" to "agent acted" without any gaps.

### Acceptance Criteria

- [ ] `GET /api/v1/audit/task/:task_id` response for a task that used a delegated agent JWT includes a `consent_record` field: `{ consent_record_id, user_id, agent_id, tools_granted, granted_at, ttl_seconds }`
- [ ] `GET /api/v1/audit/consent/:consent_record_id` returns the full consent event: user ID, agent ID, tools granted, TTL, grant timestamp, and the Ed25519 attestation from the capsule execution
- [ ] Audit log in the admin console (`/admin/audit`) displays consent grant events in the event stream — visually distinct from tool-call authorization events (different icon + label: "User consent granted")
- [ ] Task chain view links the consent event at the top of the chain: "Authorized by: [User display name] on [date] — [View consent record]"
- [ ] Consent DENY events also appear in the audit log — labelled "User consent denied"

### Technical Notes

- `eiaa_executions` row for the consent grant has `action = "user:delegate_to_agent"` — already queryable; add index on `(tenant_id, action, user_id)` for consent history queries (new migration `080_consent_executions_index.sql`)
- Task chain query: extend `GET /api/v1/audit/task/:task_id` to join consent record from `eiaa_executions` where `action = "user:delegate_to_agent"` and `agent_id` matches — included in the response if found
- `GET /api/v1/audit/consent/:consent_record_id` is a new endpoint mapping directly to an `eiaa_executions` row by ID

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: full flow — init → grant → agent calls `authorize()` → `GET /api/v1/audit/task/:task_id` response contains `consent_record` with correct fields
- [ ] `GET /api/v1/audit/consent/:consent_record_id` returns correct attestation data
- [ ] Audit log admin UI shows consent grant events with distinct icon and label

---

## Sprint Ordering Recommendation

| Sprint | Stories | Rationale |
|--------|---------|-----------|
| Sprint 1 | **US-01** Consent flow init (backend) | Pure backend — unblocks all UI work |
| Sprint 2 | **US-02** Consent screen UI | Pure frontend — depends on US-01 API |
| Sprint 3 | **US-03** Grant, Deny & token exchange | Completes the happy path end-to-end |
| Sprint 4 | **US-04** Delegations management | User-facing revocation — high trust value |
| Sprint 5 | **US-05** Consent record in audit chain | Compliance linkage — required before E5 Compliance tier |

**E4 launch gate:** Full consent flow (US-01 → US-03) passes end-to-end integration test. Consent screen usability test with 3 non-technical users: 100% grant-or-deny completion without confusion.

---

## Resources

- [Epic E4 — Agent Consent Flow](epic-e4-consent-flow.md)
- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products User Stories](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- Agent routes — [`backend/crates/api_server/src/routes/agents.rs`](../../backend/crates/api_server/src/routes/agents.rs)
- JWT claims — [`backend/crates/auth_core/src/jwt.rs`](../../backend/crates/auth_core/src/jwt.rs)
