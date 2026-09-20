# User Stories — E1: Self-Serve Tenant Onboarding

> **Epic:** [E1 — Self-Serve Tenant Onboarding](epic-e1-onboarding.md)
> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P0
> **Stories:** 7 · all independently deployable · ordered by dependency

---

## Story Map

```
US-01  Signup (account + tenant creation)
  └── US-02  Agent registration (depends on tenant)
       └── US-03  API key generation (depends on tenant + agent)
            └── US-04  Get Started wizard (depends on API key)
                 └── US-05  Live first-call indicator (depends on wizard)
US-06  API key management (parallel — returning user)
US-07  Actionable error codes (parallel — can ship any time)
```

---

## US-01 — Tenant Signup

**As an** AI Platform Engineer,
**I want to** create an AuthStar account and have a tenant provisioned automatically,
**so that** I can start calling `authorize()` without any manual setup from the AuthStar team.

### Acceptance Criteria

- [ ] `/sign-up` page renders with email + password form and "Continue with Google" / "Continue with GitHub" OAuth buttons
- [ ] On email signup: password meets complexity rules; confirmation email queued but **not** required before tenant creation (email verification deferred to Production tier upgrade)
- [ ] On OAuth signup (Google/GitHub): account created, tenant provisioned without any additional form steps
- [ ] Tenant slug is auto-generated from company name (entered on signup), lowercased, hyphenated, max 32 chars (e.g. "Acme Corp" → `acme-corp`)
- [ ] Slug shown for confirmation with an editable field; if slug is taken, append a 4-char nanoid suffix automatically
- [ ] Tenant is provisioned in ≤ 10 seconds from form submission
- [ ] Free tier (100K authorizations/month) is active immediately — no plan selection screen, no credit card prompt
- [ ] Concurrent signups (up to 50 simultaneous) do not cause DB errors — `ON CONFLICT DO NOTHING` pattern enforced
- [ ] Signup page loads in ≤ 1 second (no heavy JS bundle blocking first paint)
- [ ] Rate limit: 10 signup attempts/minute per IP (existing Redis sliding window); returns `429` with `Retry-After` header on breach
- [ ] CSRF double-submit cookie applied to all POST signup routes

### Technical Notes

- Use existing [`OrganizationService.create()`](../../backend/crates/api_server/src/services/organization_service.rs) — no new provisioning logic
- Google/GitHub OAuth uses existing [`OAuthService`](../../backend/crates/identity_engine/src/services/oauth_service.rs) with `session_type = "admin"` on first login
- Slug uniqueness enforced by DB constraint on `organizations.slug` — handle `UniqueViolation` sqlx error → append suffix → retry once
- Public signup routes (`POST /api/auth/sign-up`, `POST /api/auth/oauth/callback`) are **unauthenticated** — do not apply `EiaaAuthzLayer`; downstream admin routes require it

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Unit tests: slug generation, concurrent signup, slug collision retry
- [ ] Integration test: full signup → tenant exists → free tier active
- [ ] Signup page Lighthouse performance score ≥ 90
- [ ] Manual test: Google OAuth signup creates a tenant with correct slug

---

## US-02 — Inline Agent Registration in Wizard

**As an** AI Platform Engineer who has just signed up,
**I want to** register my first agent during the Get Started wizard,
**so that** my first `authorize()` call succeeds without a confusing "agent not found" error.

### Acceptance Criteria

- [ ] Step 2 of the Get Started wizard presents a minimal agent registration form: agent name (free text), model ID (free text, e.g. `claude-3-5-sonnet-20241022`), and a tool selector
- [ ] Tool selector offers 3 pre-defined starter tools: `web_search`, `send_email`, `read_file` — plus a "+ Add custom tool" text input for any other tool name
- [ ] Submitting the form calls `POST /api/v1/agents/register` with the entered values; on success, `agent_id` is stored in wizard state for use in US-03 and US-04
- [ ] If registration fails (validation error), the error is shown inline on the offending field — wizard does not advance
- [ ] A "Skip for now" link is available — but skipping shows a warning: "Your first `authorize()` call will fail without a registered agent"
- [ ] Registered agent appears in Admin → Agents list immediately after wizard completion

### Technical Notes

- Calls existing `POST /api/v1/agents/register` route — no new backend work
- Wizard state: store `agent_id` in component state (not localStorage); if browser is refreshed, wizard restarts from step 1
- Tool selector pre-populates `allowed_tools` in the register payload
- `EiaaAuthzLayer` with `admin:manage` action already wraps `/api/v1/agents/register`

### Definition of Done

- [ ] Code complete and reviewed
- [ ] E2E test: full wizard flow — signup → agent registration → agent appears in Agents list
- [ ] Manual test: "Skip for now" warning renders; skipping and proceeding fails at US-05 live indicator as expected

---

## US-03 — API Key Generation

**As an** AI Platform Engineer,
**I want to** receive a working API key during the Get Started wizard,
**so that** I can authenticate my SDK calls without navigating to a separate settings page.

### Acceptance Criteria

- [ ] Step 3 of the wizard generates a `sk_test_<nanoid>` API key scoped to the new tenant and the registered agent
- [ ] API key is displayed **once** inline in a read-only input field with a copy-to-clipboard button
- [ ] SHA-256 fingerprint of the key is shown below the key (e.g. `sha256:ab12cd...`) for future verification
- [ ] A warning banner reads: "Save this key now — it will not be shown again"
- [ ] "I've saved my key" checkbox must be ticked before the wizard advances to step 4
- [ ] API key is stored hashed (Argon2id) in the DB — plaintext is never written to any log or database column
- [ ] Key prefix `sk_test_` is stored in plaintext alongside the hash for display purposes in the API Keys settings page (US-06)
- [ ] On Production tier upgrade, a new `sk_live_` prefixed key is issued — `sk_test_` keys continue to work until explicitly revoked

### Technical Notes

- Extend existing `ApiKeyService` — do not create a new key storage mechanism
- Key format: `sk_test_` + 32 chars nanoid (e.g. `sk_test_<32-char-nanoid>`)
- Argon2id hash parameters: same as password hashing config (`auth_core::hash_password()`)
- Key generation route: `POST /api/v1/admin/api-keys` — already exists; ensure it returns the plaintext key exactly once in the response body

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Unit test: key generation produces correct prefix; hash verifies against generated key
- [ ] Security test: no plaintext key appears in any server log line or DB column (automated log scanner in CI)
- [ ] Manual test: API key is shown once; refreshing the page does not show it again; fingerprint matches expected SHA-256

---

## US-04 — Get Started Wizard Code Snippet

**As an** AI Platform Engineer,
**I want to** see a working, pre-filled code snippet in the Get Started wizard,
**so that** I can run my first `authorize()` call by copying one block — not by reading documentation.

### Acceptance Criteria

- [ ] Step 4 of the wizard shows a language toggle: **Python** (default) / **TypeScript**
- [ ] Python snippet is pre-filled with the real `tenant_id`, `api_key`, and `agent_id` from earlier wizard steps — no `<YOUR_TENANT_ID>` placeholders
- [ ] Python snippet contains exactly these lines in order:
  ```python
  pip install authstar-agent
  ```
  ```python
  from authstar import AgentAuthz

  authz = AgentAuthz(
      base_url="https://api.authstar.dev",
      tenant_id="<real_tenant_id>",
      api_key="<real_api_key>",
      agent_id="<real_agent_id>",
  )

  decision = authz.authorize(tool="web_search", resource="*", args={})
  print("allowed:", decision.allowed)
  print("audit_id:", decision.audit_id)
  ```
- [ ] TypeScript snippet is equivalent, using `@authstar/agent` import syntax and `async/await`
- [ ] A "Copy all" button copies the install command + snippet as one runnable block
- [ ] A "Run in shell" button copies a one-liner: `` python3 -c "$(pbpaste)" `` — with a note that it works on macOS; Linux/Windows alternative shown on hover
- [ ] Snippet is syntax-highlighted (Prism or equivalent); no dark mode required for R1

### Technical Notes

- Snippet is rendered client-side using wizard state — `tenant_id`, `api_key`, `agent_id` are in React component state from prior steps
- API key shown in snippet is the same key from US-03; shown in full here since the developer already copied it in US-03
- No server call in this step — purely client-side template rendering

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Manual test: Python snippet copied and run against a live dev environment produces a valid `decision.allowed` response
- [ ] Manual test: TypeScript snippet equivalent passes same check with `ts-node`
- [ ] Accessibility: copy button has `aria-label="Copy code snippet"`

---

## US-05 — Live First-Call Indicator

**As an** AI Platform Engineer who has just received my code snippet,
**I want to** see a real-time confirmation when my first `authorize()` call reaches AuthStar,
**so that** I know my integration is working before I leave the wizard.

### Acceptance Criteria

- [ ] Step 5 (final wizard step) shows a pulsing "Waiting for your first call…" indicator immediately on render
- [ ] The page polls `GET /api/v1/onboarding/status?tenant_id=<id>` every 3 seconds for up to 10 minutes
- [ ] When the first `authorize()` call is received for this tenant, the indicator transitions to: "✅ First authorization received — you're live!" with a green checkmark animation
- [ ] The success state shows: the tool name that was called, `ALLOW` or `DENY`, and the `audit_id` — confirming the real call came through
- [ ] "Explore your audit trail" button links to `GET /api/v1/audit/task/<task_id>` result displayed as a formatted JSON view in the dashboard
- [ ] "Go to dashboard" button is available at all times — developer does not have to wait for the first call to proceed
- [ ] If 10 minutes elapse without a call, the indicator shows: "No call yet — run the snippet above, or check `authstar doctor` for connectivity issues" with a link to docs
- [ ] `first_authorize_success` analytics event is fired server-side with: `tenant_id`, `sdk_language` (inferred from User-Agent on the authorize call), `time_to_activate_seconds` (time delta from `tenant_created` timestamp)

### Technical Notes

- `GET /api/v1/onboarding/status` is a new lightweight endpoint — returns `{ first_call_received: bool, last_decision: { tool, allowed, audit_id } | null }`
- Polling uses `setInterval` with cleanup on unmount; switch to SSE/WebSocket in R2 if polling causes load
- `sdk_language` inference: check `User-Agent` header on the authorize call for `python-httpx`, `python-requests`, `node-fetch`, `axios` patterns
- `first_authorize_success` event must fire even if `decision.allowed = false` — a DENY is still a successful first call (the SDK is working)

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: sign up → run Python snippet against test env → indicator turns green within 15 seconds
- [ ] Unit test: `first_authorize_success` event fires on first authorize call (ALLOW and DENY both trigger it)
- [ ] Manual test: 10-minute timeout message renders correctly; "Go to dashboard" link works at all stages

---

## US-06 — API Key Management (Returning Developer)

**As a** returning developer setting up a new environment,
**I want to** find my API keys, tenant ID, and base URL in the dashboard settings,
**so that** I can configure a new deployment without going through the signup wizard again.

### Acceptance Criteria

- [ ] Admin dashboard → Settings → **API Keys** page lists all active keys with: prefix (e.g. `sk_test_<prefix>…`), SHA-256 fingerprint, created date, last used timestamp, and a **Revoke** button
- [ ] Revoked keys are shown in a "Revoked" section with revocation timestamp — not deleted, for audit purposes
- [ ] **Create new key** button generates a new API key following the US-03 flow (shown once, never again)
- [ ] Admin dashboard → Settings → **General** page shows: Tenant ID (copy-to-clipboard), Tenant slug, Plan tier, AuthStar base URL (copy-to-clipboard)
- [ ] Revoking a key requires confirmation: modal with "Type the key prefix to confirm" input before revoke executes
- [ ] Revoked key returns `401 ERR_REVOKED_KEY` on any subsequent `authorize()` call — immediately, without waiting for cache TTL

### Technical Notes

- Revocation sets `revoked_at` timestamp on the API key row — existing `ApiKeyService` pattern
- Immediate revocation: on revoke, write a Redis key `api_key_revoked:<key_hash>` with TTL = 24h; check this key in the authorization hot path before the DB lookup
- `EiaaAuthzLayer` with `apikeys:manage` action wraps all API key management routes — already defined in the action string list in AGENTS.md

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: create key → use key → revoke key → next `authorize()` call returns `401 ERR_REVOKED_KEY` within 100ms of revocation
- [ ] Manual test: revoked keys appear in "Revoked" section; confirmation modal blocks accidental revocation

---

## US-07 — Actionable Error Codes

**As an** AI Platform Engineer whose first `authorize()` call failed,
**I want to** receive an error response that tells me exactly what went wrong and how to fix it,
**so that** I can resolve the issue without filing a support ticket.

### Acceptance Criteria

- [ ] All `authorize()` error responses include: `error_code` (string), `message` (human-readable), `docs_url` (link to specific troubleshooting guide)
- [ ] The following named error codes are implemented and tested:

| Error code | HTTP status | Trigger | Message |
|------------|-------------|---------|---------|
| `ERR_INVALID_KEY` | 401 | API key not found or revoked | "API key is invalid or has been revoked. Generate a new key at Settings → API Keys." |
| `ERR_AGENT_NOT_FOUND` | 404 | `agent_id` in JWT not registered for this tenant | "Agent not found. Register this agent at POST /api/v1/agents/register before calling authorize." |
| `ERR_TENANT_NOT_FOUND` | 404 | `tenant_id` in JWT does not exist | "Tenant not found. Check your tenant ID in Settings → General." |
| `ERR_CAPSULE_NOT_FOUND` | 503 | No compiled capsule exists for this action | "No policy found for this action. Deploy a policy in the Policy Builder or re-register your agent." |
| `ERR_RATE_LIMITED` | 429 | Auth flow rate limit exceeded | "Too many requests. Retry after {seconds} seconds." |
| `ERR_FREE_TIER_EXCEEDED` | 402 | Monthly authorization limit reached | "Free tier limit (100K/month) reached. Upgrade to Production tier to continue." |

- [ ] `docs_url` in each error points to a real, published troubleshooting page (stub pages acceptable for R1 launch, filled in during E3)
- [ ] Error response shape is consistent: `{ "error": { "code": "ERR_INVALID_KEY", "message": "...", "docs_url": "..." } }`
- [ ] Existing `AppError` variants map to these codes — no new error type introduced; use `AppError::Validation` → 400 where appropriate per AGENTS.md

### Technical Notes

- Extend `AppError` with `error_code` field or use a wrapper response serializer — do not change the `AppError` type itself (forward-only)
- `ERR_CAPSULE_NOT_FOUND` is the most common first-call error — this is what happens when a developer skips agent registration in US-02; the message must be maximally actionable
- `docs_url` base: `https://docs.authstar.dev/errors/<error_code_lowercase>` — stubs required at launch

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Unit test: each error code serializes to correct HTTP status + JSON shape
- [ ] Integration test: trigger each error condition in the test suite; assert error code and message match spec
- [ ] Manual test: run the Python SDK against a deliberately misconfigured tenant; verify each error produces the correct code and a usable `docs_url`

---

## Sprint Ordering Recommendation

| Sprint | Stories | Rationale |
|--------|---------|-----------|
| Sprint 1 | **US-01** + **US-07** | Signup unblocks everything; error codes can be built independently and make US-05 testing much clearer |
| Sprint 2 | **US-02** + **US-03** | Agent registration and key generation are fast backend stories that depend on US-01 |
| Sprint 3 | **US-04** + **US-05** | Wizard UI and live indicator — the activation experience; depends on US-02 + US-03 |
| Sprint 4 | **US-06** | API key management is a returning-user feature; can ship after activation flow is live |

**E1 launch gate:** All 7 stories pass acceptance criteria + usability test with 2 cold-start engineers in < 15 minutes.

---

## Resources

- [Epic E1 — Self-Serve Tenant Onboarding](epic-e1-onboarding.md)
- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products User Stories](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- [`OrganizationService`](../../backend/crates/api_server/src/services/organization_service.rs)
- [`ApiKeyService`](../../backend/crates/api_server/src/routes/api_keys.rs)
- [`AppError`](../../backend/crates/shared_types/src/lib.rs)
