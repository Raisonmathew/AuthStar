# Epic E2 — Policy Builder UI

> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P0 · **Depends on:** E1 (tenant must exist before policies can be authored)
> **NSM contribution:** Engagement — `policy_deployed` event; gates Compliance tier (E5)
> **Status:** Ready for development — user stories drafted
> **User Stories:** [user-stories-e2-policy-builder.md](user-stories-e2-policy-builder.md)

---

## 1. Problem Statement

Today, writing a WASM capsule policy for AuthStar requires authoring raw JSON AST — a format no AI Platform Engineer outside the AuthStar team would encounter or understand. As a result, every tenant ships with only the default policy templates compiled at agent registration. Custom policies — the mechanism that makes EIAA genuinely powerful — are unreachable without deep platform knowledge.

A Tenant Admin must be able to define what their agents are allowed to do, test the policy against a simulated call, and deploy it to production — all through a UI, without writing a single line of JSON AST.

---

## 2. Product Outcomes & Instrumentation

| Phase | Product Outcome | Metric |
|-------|----------------|--------|
| R1 Launch | > 40% of activated tenants deploy at least one custom policy within 30 days | `policy_deployed` event per tenant cohort |
| R1 Launch | Policy deployment succeeds on first attempt > 80% of the time | `policy_deploy_success` vs `policy_deploy_failed` ratio |
| R1 Launch | Median time from "open policy editor" to "policy active" < 10 minutes | Time delta: `policy_editor_opened` → `policy_deployed` |
| 60 days post-launch | > 50% of Production-tier tenants have ≥ 2 deployed policy versions | Policy version count per tenant |

---

## 3. Assumptions

- R1 ships a **structured form with pre-built templates** — not drag-and-drop visual AST editor (faster to ship, lower engineering risk; drag-and-drop is R2 enhancement)
- Templates cover the 3 most common agent patterns validated in discovery: (a) single-tool allow, (b) multi-tool allow with resource pattern, (c) tool allow with delegation-chain requirement
- The Policy Builder calls the **actual capsule compiler** for validation — no client-side-only AST validation. "Valid" in the UI means "compiled successfully."
- Policy test console sends a real `authorize()` call against a draft (undeployed) capsule — uses a dedicated `POST /api/v1/policies/test` endpoint
- Deployed capsules are versioned automatically — each deploy creates a new version; previous versions are never deleted
- The UI must call `CapsuleCacheService` invalidation on deploy — not leave cache invalidation to TTL expiry
- Policy Builder is admin-only — accessible at `/admin/policies` — behind `EiaaAuthzLayer` with `policies:manage` action
- Go SDK agent support is out of scope for this epic

---

## 4. Non-Functional Requirements

- Policy compilation ≤ 60 seconds from "deploy" click to capsule active
- Policy test console response ≤ 2 seconds (calls local capsule runtime via gRPC)
- Policy Builder UI accessible only to tenant admins — `EiaaAuthzLayer` with `policies:manage` action required
- Every policy deployment must be recorded in `eiaa_capsules` with: `tenant_id`, `action`, `ast_bytes`, `wasm_bytes`, `ast_hash`, `wasm_hash`, `created_at`, `created_by` (user ID of deploying admin)
- Cache invalidation on deploy must propagate within 1 second — use existing `CapsuleCacheService.invalidate(tenant_id, action)`
- Draft policies are ephemeral (session-only) — not persisted until "Deploy" is clicked
- Policy form inputs must be validated client-side for obvious errors (empty tool name, invalid resource pattern regex) before the compile call is made — to reduce unnecessary compiler round-trips

---

## 5. User Requirements

| # | User Story | User Requirement |
|---|-----------|-----------------|
| 1 | A Tenant Admin needs to create a new policy so that they can control what their agents are allowed to do | Policy Builder accessible from Admin console → Policies → "New Policy" button |
| 2 | | Admin selects target agent from a dropdown of registered agents in the tenant |
| 3 | | Admin selects a template: "Allow single tool", "Allow multiple tools", "Allow with delegation requirement", or "Custom" |
| 4 | A Tenant Admin needs to define allowed tools and constraints so that the policy reflects their actual authorization requirements | For each tool: select tool name from agent's `allowed_tools` list; set optional resource pattern (glob or regex); set optional argument constraints (key: value pairs) |
| 5 | | For delegation requirement: toggle "Require human in delegation chain" — adds `CheckDelegationChain` step automatically |
| 6 | | For conditional rules: add condition blocks (e.g., "deny if risk score > 70") via structured form fields — no manual AST editing |
| 7 | A Tenant Admin needs to test a policy before deploying so that they don't accidentally break production agents | "Test Policy" button opens test console panel inline |
| 8 | | Test console accepts: agent ID, user ID, tool name, resource, args (JSON), risk score override |
| 9 | | Test console shows: ALLOW or DENY, which AST step made the decision, attestation preview |
| 10 | | Test result shows diff vs. currently active policy if one exists ("was: ALLOW → now: DENY") |
| 11 | A Tenant Admin needs to deploy a tested policy so that it becomes active for all future `authorize()` calls | "Deploy" button triggers compilation → signing → activation in sequence |
| 12 | | Progress indicator shows: Compiling → Signing → Activating → Active |
| 13 | | On success: new version number shown, timestamp, deploying admin's name |
| 14 | | On failure: error message from capsule compiler shown inline with the offending field highlighted |
| 15 | A Tenant Admin needs to see policy history so that they can audit who deployed what and when | Policy detail page shows version list: version number, deployed by, deployed at, "View AST" link, "Rollback to this version" button |
| 16 | | Rollback re-deploys the selected version as a new deployment (preserves history — does not overwrite) |
| 17 | | Each version shows a summary of its rules in plain English (e.g., "Allows send_email on inbox:* for agents with human in delegation chain") |
| 18 | A Tenant Admin needs to see the currently active policy for each agent so that they know which rules are in effect | Agents list page shows each agent with its active policy name, version, and last deployed timestamp |
| 19 | | "No policy" state shown clearly — agent will use default allow-all template if no custom policy is deployed |
| 20 | A developer needs to understand why an `authorize()` call was denied so that they can fix their policy | Audit log entry for a DENY decision links to the policy version that denied it; "View Policy" button opens the Policy Builder at that version |

---

## 6. Open Questions & Considerations

**Questions:**
- [ ] Should the "Custom" template option expose a raw JSON AST editor for power users, or is that deferred to R2? Recommendation: include a read-only AST preview in R1 (shows the compiled AST of the form-built policy); editable raw AST in R2.
- [ ] Should rollback require a second confirmation step? Recommendation: yes — rolling back a policy is a high-impact action; require "Type policy name to confirm" before rollback executes.
- [ ] Should the test console support saving test cases as a "policy test suite"? Recommendation: defer to R2 — R1 just needs ad-hoc testing; saved test suites are a retention feature.

**Considerations:**
- The test console is the trust-building mechanism. A Tenant Admin who tests before deploying is far less likely to file a support ticket after deploying. Invest in making the test console feedback clear and fast.
- Plain-English policy summaries (requirement 17) must be generated from the AST server-side, not inferred client-side — use the capsule compiler's metadata output.
- The "No policy" state (requirement 19) is a compliance risk for the Persona 2 buyer. Make it visually prominent — a yellow warning badge, not a neutral empty state.

---

## Next Steps

1. ✅ User stories drafted — see [user-stories-e2-policy-builder.md](user-stories-e2-policy-builder.md)
2. Kick off with engineering — confirm `POST /api/v1/policies/test` endpoint design and `formToAst` function spec
3. **Start Sprint 1:** US-01 (Policy entry point + template selection) — pure frontend, fast to ship
4. Design Policy Builder form UI (3 views: form editor, test console, version history) before Sprint 2
5. Usability test after Sprint 5 — gate: first policy deployed < 10 minutes, cold-start, no assistance

---

## Resources

- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products Epics](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts/epics)
- Capsule compiler AST spec — [`backend/crates/capsule_compiler/src/ast.rs`](../../backend/crates/capsule_compiler/src/ast.rs)
- Capsule cache service — [`backend/crates/api_server/src/services/capsule_cache.rs`](../../backend/crates/api_server/src/services/capsule_cache.rs)
