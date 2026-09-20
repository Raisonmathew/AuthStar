# User Stories — E2: Policy Builder UI

> **Epic:** [E2 — Policy Builder UI](epic-e2-policy-builder.md)
> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P0
> **Stories:** 6 · ordered by dependency
> **Depends on:** E1 must be live (tenant must exist to author policies)

---

## Story Map

```
US-01  Policy entry point + template selection
  └── US-02  Tool allowlist form (depends on template)
       └── US-03  Test console (depends on draft policy)
            └── US-04  Deploy + progress + version record (depends on test)
                 └── US-05  Version history + rollback (depends on deployed versions)
US-06  Agent policy status + DENY → policy link (parallel — read-only views)
```

---

## US-01 — Policy Entry Point & Template Selection

**As a** Tenant Admin,
**I want to** open the Policy Builder from the admin console and choose a starting template,
**so that** I can create a new policy without knowing what JSON AST looks like.

### Acceptance Criteria

- [ ] Admin console left nav has a **Policies** item that routes to `/admin/policies`
- [ ] Policies list page shows all policies for the tenant: policy name, target agent, active version, last deployed, deploying admin
- [ ] **New Policy** button routes to `/admin/policies/new`
- [ ] New Policy page shows: agent selector dropdown (lists all registered agents in the tenant), policy name field, and 4 template cards:
  - **Allow single tool** — "Agent can call one specific tool"
  - **Allow multiple tools** — "Agent can call a defined list of tools"
  - **Allow with delegation requirement** — "Agent must have a human in its delegation chain"
  - **Start from scratch** — blank form, all fields empty
- [ ] Selecting a template pre-fills the form in US-02 with sensible defaults for that pattern
- [ ] Agent selector is required — "New Policy" button is disabled until an agent is selected
- [ ] `policy_editor_opened` instrumentation event fires when the form renders, with `tenant_id`, `agent_id`, `template_selected`

### Technical Notes

- Route `/admin/policies` requires `EiaaAuthzLayer` with `policies:manage` action — already in the AGENTS.md action string list
- Agent dropdown calls `GET /api/v1/agents` — existing route; filter to `status = active`
- Template selection is client-side state only — no backend call until US-04 deploy

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Policies list page renders with empty state when no policies exist
- [ ] All 4 templates render distinct pre-filled forms in US-02
- [ ] `policy_editor_opened` event fires and is verifiable in the analytics pipeline

---

## US-02 — Tool Allowlist Form

**As a** Tenant Admin,
**I want to** define exactly which tools my agent can call, with optional resource and argument constraints,
**so that** the policy accurately reflects my authorization requirements without me writing policy code.

### Acceptance Criteria

- [ ] Form shows a **tool rows** section: each row has tool name (dropdown from agent's `allowed_tools`), resource pattern (text input, optional, placeholder `*`), and argument constraints (key:value repeater, optional)
- [ ] **Add tool** button adds a new empty row; minimum 1 tool row required to proceed
- [ ] **Remove** (×) button on each row; at least 1 row must remain
- [ ] **Require human in delegation chain** toggle — when ON, adds `CheckDelegationChain` to the AST automatically; label: "Only allow if a human user is in the agent's delegation chain"
- [ ] **Conditional risk rule** section (collapsible, off by default): "Deny if risk score is greater than [number 0–100]" — single input; maps to `EvaluateRisk` + `Conditional(risk_score > N → Deny)` in AST
- [ ] **Read-only AST preview** panel (collapsed by default, expandable): shows the JSON AST that will be sent to the compiler — read-only; label: "View compiled AST (advanced)"
- [ ] Client-side validation fires on blur: tool name must not be empty; resource pattern must be valid glob or regex (test with `new RegExp()` guard); argument constraint keys must not be empty
- [ ] Validation errors shown inline under the offending field in red; "Deploy" and "Test Policy" buttons disabled while any field has an error

### Technical Notes

- AST preview generated client-side from form state using a `formToAst(formState): PolicyAst` pure function — same logic as the backend compiler input, so preview is always accurate
- `CheckDelegationChain` step inserts at position 2 in AST (after `VerifyAgentIdentity`, before `AuthorizeToolCall`) — enforced by `formToAst`
- Resource pattern `*` glob is converted to regex `.*` before sending to compiler
- Argument constraints serialise as `{ key: string, value: string }[]` in AST `AuthorizeToolCall.arg_constraints`

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Unit tests: `formToAst` produces correct AST for all 4 templates + delegation toggle + risk rule
- [ ] Client-side validation: empty tool name, invalid regex pattern, empty arg key each show inline error and disable deploy
- [ ] AST preview panel renders valid JSON matching what the compiler will receive

---

## US-03 — Policy Test Console

**As a** Tenant Admin,
**I want to** test my draft policy against a simulated `authorize()` call before deploying it,
**so that** I know it will behave as expected and won't accidentally break live agents.

### Acceptance Criteria

- [ ] **Test Policy** button is available at all times in the form view (not only after form is valid)
- [ ] Clicking "Test Policy" opens an inline panel below the form (does not navigate away) with input fields: agent ID (pre-filled from selected agent), user ID (text), tool name (dropdown from form's allowed tools + free-text option), resource (text, default `*`), args (JSON textarea, default `{}`), risk score override (0–100 slider, default 50)
- [ ] **Run Test** button sends `POST /api/v1/policies/test` with `{ ast: <draft_ast>, context: { agent_id, user_id, tool, resource, args, risk_score } }`
- [ ] Response renders within 2 seconds showing:
  - Large **ALLOW** (green) or **DENY** (red) badge
  - "Decision made by step: `AuthorizeToolCall` / `CheckDelegationChain` / `EvaluateRisk` / etc." — plain English label for the deciding AST step
  - Attestation preview: `decision_hash` (first 16 chars) to confirm it's a real capsule execution
- [ ] If a currently active policy exists for this agent, show a diff row: **"Currently active policy: ALLOW → This draft: DENY"** (or vice versa) — highlighted in amber if the decision changes
- [ ] Test can be run multiple times with different inputs before deploying — each run overwrites the previous result
- [ ] If `POST /api/v1/policies/test` returns a compiler error, show the error message inline with the offending form field highlighted (same as deploy error in US-04)

### Technical Notes

- New backend endpoint: `POST /api/v1/policies/test` — accepts raw AST + context; compiles capsule in-memory (does not write to DB); executes via gRPC runtime; returns `{ allowed: bool, deciding_step: string, decision_hash: string, compiler_error?: string }`
- In-memory compilation must not write to `eiaa_capsules` table — use a transient compilation path in `CapsuleCompiler`
- Endpoint protected by `EiaaAuthzLayer` with `policies:manage` action
- "Deciding step" plain-English labels: `VerifyAgentIdentity` → "Identity check", `CheckDelegationChain` → "Delegation chain check", `AuthorizeToolCall` → "Tool authorization rule", `EvaluateRisk` → "Risk score check", `Conditional` → "Conditional rule"

### Definition of Done

- [ ] Code complete and reviewed
- [ ] `POST /api/v1/policies/test` integration test: valid AST + allow context → ALLOW; valid AST + blocked tool → DENY; invalid AST → compiler error with field reference
- [ ] Frontend: test panel renders, Run Test returns result in < 2s against test environment
- [ ] Diff row renders correctly when active policy decision differs from draft decision

---

## US-04 — Deploy Policy

**As a** Tenant Admin,
**I want to** deploy my tested policy so that it becomes active for all future `authorize()` calls within 60 seconds,
**so that** I can confidently push policy changes without manual backend work.

### Acceptance Criteria

- [ ] **Deploy** button is enabled only when: form has no validation errors AND at least one test has been run (test result must be present — deploy without testing is permitted but requires dismissing a warning: "You haven't tested this policy. Deploy anyway?")
- [ ] Clicking Deploy shows a confirmation modal: "Deploy policy for agent `<agent_name>`? This will replace the current active policy immediately." with Cancel and **Deploy** buttons
- [ ] After confirmation, the button is replaced by a progress stepper:
  `Compiling... → Signing... → Activating... → ✅ Active`
- [ ] Each step completes before the next begins; if any step fails, progress stops and the error is shown inline with the failed step highlighted in red
- [ ] On success: policy version number shown (e.g. `v3`), deployed timestamp, and a **"View active policy"** link that routes to the version history page (US-05)
- [ ] On compiler failure: the error message from the capsule compiler is shown under the relevant form field; if the error cannot be mapped to a field, it appears in a top-of-form error banner
- [ ] Cache invalidation fires within 1 second of successful activation — next `authorize()` call uses the new capsule
- [ ] `policy_deployed` event fires on success with: `tenant_id`, `agent_id`, `policy_version`, `template_used`, `time_editor_to_deploy_seconds`
- [ ] `policy_deploy_failed` event fires on failure with: `tenant_id`, `agent_id`, `failure_stage` (`compile` / `sign` / `activate`), `error_code`

### Technical Notes

- Deploy calls existing `POST /api/v1/policies` route (or a new `/api/v1/policies/:agent_id/deploy` endpoint — TBD with engineering) which writes to `eiaa_capsules` with `created_by = claims.sub`
- Cache invalidation: call `CapsuleCacheService.invalidate(tenant_id, action)` immediately after writing to DB — do not rely on TTL
- Progress stepper polls `GET /api/v1/policies/:id/status` or uses the existing synchronous compile-sign-activate path if it completes in < 60s
- "Deploy without test" warning is a client-side gate — if the user dismisses it, the backend does not enforce test-first

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: deploy valid policy → appears in `eiaa_capsules` table → next `authorize()` call uses new capsule within 2 seconds
- [ ] Integration test: deploy invalid AST → `policy_deploy_failed` event fires; form shows error on correct field
- [ ] Manual test: progress stepper animates through all four steps; "View active policy" link works after success

---

## US-05 — Version History & Rollback

**As a** Tenant Admin,
**I want to** see every version of a policy that has ever been deployed and roll back to a previous version if needed,
**so that** I can recover from a bad deploy without losing the audit trail of who changed what and when.

### Acceptance Criteria

- [ ] Policy detail page at `/admin/policies/:policy_id` shows a **Version History** tab listing all versions in reverse-chronological order
- [ ] Each version row shows: version number, deployed by (user display name + avatar), deployed at (relative timestamp, e.g. "2 hours ago"), plain-English summary of the policy rules (e.g. "Allows `send_email` on `inbox:*`; requires human in delegation chain"), and two action buttons: **View AST** and **Rollback to this version**
- [ ] **View AST** opens a read-only syntax-highlighted JSON modal of the version's `ast_bytes` — no editing
- [ ] **Rollback to this version** button shows a confirmation modal: "Type the policy name to confirm rollback" — text input must exactly match the policy name before the Rollback button enables
- [ ] Confirmed rollback re-deploys the selected version as a **new version** (e.g. if rolling back from v5 to v3, a new v6 is created with v3's AST) — the original v5 is preserved in history unchanged
- [ ] Plain-English summaries are generated server-side from AST metadata — not inferred client-side
- [ ] Versions can never be deleted — the UI has no delete option
- [ ] Current active version is visually marked with an **Active** badge

### Technical Notes

- `GET /api/v1/policies/:agent_id/versions` — new endpoint returning paginated version list with `ast_summary` field (plain-English string generated by compiler)
- Plain-English summary generation: extend `CapsuleCompiler` to output a `summary: String` alongside the compiled capsule — rules engine maps AST steps to English phrases server-side
- Rollback creates a new `eiaa_capsules` row with `derived_from_version = <source_version>` for audit traceability
- Pagination: cursor-based, 20 versions per page — consistent with audit trail pagination pattern in the codebase

### Definition of Done

- [ ] Code complete and reviewed
- [ ] `GET /api/v1/policies/:agent_id/versions` returns correctly paginated results with `ast_summary` populated
- [ ] Rollback integration test: rollback v3 → new v6 created with v3's AST → v5 still present in history → next `authorize()` uses v6
- [ ] Rollback confirmation: incorrect policy name does not enable the Rollback button; correct name enables it
- [ ] Manual test: "View AST" modal renders valid syntax-highlighted JSON

---

## US-06 — Agent Policy Status & DENY → Policy Link

**As a** Tenant Admin or Developer,
**I want to** see at a glance which policy is active for each agent, and jump from a DENY audit record directly to the policy that caused it,
**so that** I can diagnose authorization failures without manually searching through policy history.

### Acceptance Criteria

- [ ] Admin → Agents list shows a **Policy** column for each agent: active policy name + version number (e.g. `email-policy v3`), or a ⚠️ **No policy** badge in amber if no custom policy is deployed
- [ ] Clicking the policy name in the Agents list navigates to the policy detail page (US-05)
- [ ] **No policy** amber badge shows a tooltip: "This agent uses the default allow-all policy. Deploy a custom policy to restrict access."
- [ ] Audit log page (`/admin/audit`) shows each DENY decision with a **View Policy** button that opens the Policy Builder at the exact version that made the decision (read-only view of that version's form state)
- [ ] "View Policy" deep link is of the form `/admin/policies/:policy_id/versions/:version_id` — bookmarkable and shareable
- [ ] If the policy version no longer exists (edge case: manual DB deletion), deep link renders a "Policy version not found" message instead of a 404

### Technical Notes

- Agents list: extend `GET /api/v1/agents` response to include `active_policy: { name, version, policy_id } | null`
- Audit log DENY records: the `eiaa_executions` table already stores `capsule_id` — join to `eiaa_capsules` to get the policy version; add `policy_id` and `policy_version` to the audit log API response
- "View Policy" read-only form view: re-use the Policy Builder form component with all inputs disabled; populate from the version's AST via `POST /api/v1/policies/ast-to-form` (new endpoint that reverses AST → form state)

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Agents list renders policy column with active version or amber badge for all agents
- [ ] "No policy" tooltip renders and is accessible (keyboard + screen reader)
- [ ] DENY audit record "View Policy" link navigates to correct policy version in read-only form view
- [ ] `POST /api/v1/policies/ast-to-form` returns correct form state for all 4 template types

---

## Sprint Ordering Recommendation

| Sprint | Stories | Rationale |
|--------|---------|-----------|
| Sprint 1 | **US-01** — Policy entry point + template selection | Pure frontend; unblocks all other stories; fast to ship |
| Sprint 2 | **US-02** — Tool allowlist form + AST preview | Core form logic + `formToAst` function; needs unit test investment |
| Sprint 3 | **US-03** — Test console + new `POST /api/v1/policies/test` backend | Highest trust-building feature; most complex new backend endpoint |
| Sprint 4 | **US-04** — Deploy + progress stepper + instrumentation | Connects form → backend → capsule; cache invalidation critical path |
| Sprint 5 | **US-05** + **US-06** | Version history and agent status are parallel read-only features; can share a sprint |

**E2 launch gate:** All 6 stories pass acceptance criteria + usability test: Tenant Admin deploys first custom policy in < 10 minutes, cold-start, no assistance.

---

## Resources

- [Epic E2 — Policy Builder UI](epic-e2-policy-builder.md)
- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products User Stories](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- Capsule compiler AST — [`backend/crates/capsule_compiler/src/ast.rs`](../../backend/crates/capsule_compiler/src/ast.rs)
- Capsule cache — [`backend/crates/api_server/src/services/capsule_cache.rs`](../../backend/crates/api_server/src/services/capsule_cache.rs)
- Policies route — [`backend/crates/api_server/src/routes/`](../../backend/crates/api_server/src/routes/)
