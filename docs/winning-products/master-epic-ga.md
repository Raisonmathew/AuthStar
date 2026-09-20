# Master Epic — AuthStar GA Launch

> **Winning Products Phase:** Delivery
> **Theme:** AuthStar General Availability — AI Agent Authorization + Human IDaaS
> **NSM:** 10+ AI companies with ≥1 agent tool call authorized in production per week (12-month target)
> **Status:** Draft v1 (2026-03-06)
> **Inputs:** OpA v3 (validated), PR-FAQ v1
> **Preceded by:** [OpA](opa-ai-agent-authz.md) · [PR-FAQ](prfaq-authstar.md)

---

## 1. Strategic Context

### Vision & Alignment

**Solution Value Statement:**

> Any company building AI agents can drop AuthStar into their stack with a single SDK call, authorize every agent tool call before it executes, and produce a cryptographically re-executable proof of that decision — without building an IAM system.

**NSM linkage:** Every feature epic in this Master Epic must move at least one of:
- AI Production Tenants (NSM primary)
- Time to First Authorized Tool Call (activation)
- Audit Query Adoption (retention / compliance value realized)

**Business Objectives:**
- Reach 10 AI builder companies with active production usage in 12 months
- Launch a self-serve onboarding path that eliminates engineering involvement for new tenant provisioning
- Make the compliance tier (immutable evidence + SOC 2 reports) available to paying customers
- Establish AuthStar as the reference implementation for AI agent authorization in at least one major framework community (LangChain, CrewAI, or OpenAI Agents SDK)

### Market Opportunity

The AI agent authorization category is forming now. Every practitioner team builds their own enforcement middleware because no standard exists. The compliance trigger is real and documented — enterprise deals stall without cryptographic pre-authorization evidence. The window to define the category is open but closing: agentgateway, Aport.io, and agent-guard are all in active development. AuthStar's moat — re-executable cryptographic attestation via WASM capsule + Ed25519 — is not replicated by any current competitor.

---

## 2. Problem Statement

**As an AI Platform Engineer** building a multi-agent production system, the problem I have is that I must write custom authorization middleware for every tool my agents can call, with no standard, no audit trail, and no way to prove to an auditor what my agent was authorized to do at any given moment. When an agent acts outside scope, I spend days reconstructing what happened from logs that were never designed to answer that question.

**As a Security/Compliance Lead** at a company selling AI agents to enterprise buyers, the problem I have is that my enterprise customers' security teams demand cryptographic proof that every agent action was pre-authorized. I cannot produce this today, so deals stall at the security review stage.

**Customer Impact:**
- Engineering teams spend weeks building undifferentiated authorization infrastructure that every team rebuilds independently
- Enterprise sales cycles blocked by security reviews that current logs cannot satisfy
- A $200K contract was killed because an AI company could not prove their agent's actions were pre-authorized (validated in discovery)

**Business Impact:**
- Without self-serve onboarding, every new customer requires manual engineering involvement — PLG is impossible
- Without a Policy Builder UI, Persona 1 cannot configure policies without knowing JSON AST — adoption ceiling is "engineers who already understand EIAA"
- Without the compliance tier, Persona 2's purchase trigger (the enterprise deal blocker) has no product answer

**Current Workarounds:**
- Static API keys with broad scope (no per-action control, no audit)
- OAuth scopes (static, can't evaluate runtime context)
- Custom `if agent.can_do(action)` middleware per tool (no attestation, rebuilt by every team)
- Manual chain-of-thought logging (logs become noise at tool-chain depth)

---

## 3. Use Cases

### Use Case 1 — First `authorize()` Call in Under 15 Minutes
- **Persona:** AI Platform Engineer (Persona 1)
- **Objective:** Sign up, provision a tenant, install the Python or TypeScript SDK, and call `authorize()` successfully without any help from AuthStar's team
- **Outcome:** Engineer reaches their first authorized tool call and first audit record in under 15 minutes; zero engineering involvement from AuthStar; NSM activation event fired

### Use Case 2 — Authorize a Tool Call Across an Agent Delegation Chain
- **Persona:** AI Platform Engineer (Persona 1)
- **Objective:** An orchestrator agent delegates to a sub-agent; both the delegation and each sub-agent tool call are independently authorized and linked in the audit trail by `parent_action_id`
- **Outcome:** Full causal chain is queryable end-to-end; `delegation_chain` in JWT preserves the human → orchestrator → sub-agent lineage; any action in the chain is independently re-executable

### Use Case 3 — Write and Deploy a Policy Without Touching JSON AST
- **Persona:** AI Platform Engineer (Persona 1) / Tenant Admin
- **Objective:** Define which tools an agent is allowed to call, under what conditions, using a visual editor or natural-language input — not raw WASM capsule JSON
- **Outcome:** Tenant admin deploys a working policy in under 10 minutes; capsule compiles and activates without engineering involvement; policy is versioned and auditable

### Use Case 4 — Produce Compliance Evidence for an Enterprise Security Review
- **Persona:** Security/Compliance Lead (Persona 2)
- **Objective:** Export the complete authorization record for a specific agent session — agent identity, tools called, resources accessed, arguments, policy version, decision, timestamp — and hand it to an enterprise customer's security team for verification
- **Outcome:** Security team can replay any decision in the exported record and verify the cryptographic attestation independently; SOC 2 / EU AI Act evidence is producible on demand in under 5 minutes

### Use Case 5 — End-User Authorizes an AI Agent to Act on Their Behalf
- **Persona:** End User (human) delegating to an AI agent
- **Objective:** A user sees a consent screen listing the tools the agent will have access to, the resources it can touch, and the time window — and explicitly authorizes the delegation before the agent acts
- **Outcome:** User consent is recorded as a capsule execution with full attestation; the agent JWT carries the `delegation_chain` back to the human; revocation by the user immediately invalidates the agent's token

---

## 4. Solution Overview

AuthStar GA delivers three capabilities in sequence across two releases:

**Release 1 — Make it self-serve (PLG unblocked):**
Self-Serve Tenant Onboarding + Policy Builder UI. A developer can go from zero to a working authorized agent call in under 15 minutes, without any involvement from AuthStar's engineering team.

**Release 2 — Make it enterprise-ready (compliance tier unlocked):**
Agent Consent Flow + Compliance Tier packaging (immutable evidence, SOC 2 reports, policy versioning UI) + SDK Completeness. An enterprise security team can verify authorization evidence on demand.

### Key Capabilities

1. **Self-serve onboarding:** Tenant signup, provisioning, and first capsule — no manual DB migration or env config
2. **Policy Builder UI:** Visual or natural-language policy editor — deploy a WASM capsule without writing JSON AST
3. **Agent Consent Flow:** End-user authorization screen for AI agent delegation
4. **Compliance tier:** Immutable evidence exports, policy version history, SOC 2 report generation
5. **SDK completeness:** Quickstart guides for Python, TypeScript, Go; React agent hooks; < 15-minute first-call target
6. **Instrumentation:** NSM tracking, activation funnel, first-call event, compliance-tier conversion

### Release Roadmap

| Release | Key Deliverables | NSM Gate |
|---------|-----------------|----------|
| **R1 — Self-Serve GA** | Tenant onboarding, Policy Builder UI, SDK quickstarts, activation instrumentation | First 3 paying customers on Production tier |
| **R2 — Compliance GA** | Agent Consent Flow, Compliance tier, SOC 2 evidence exports, Go + React agent SDKs | First compliance-tier customer; first enterprise deal unblocked |

---

## 5. User Stories

### Story 1 — Self-Serve Tenant Onboarding

**As an** AI Platform Engineer, **I need to** sign up, create a tenant, and reach my first successful `authorize()` call without any help from AuthStar's team, **so that** I can evaluate the product in my own stack before any sales conversation.

**Features:**
- Tenant signup flow: email + password or OAuth (Google/GitHub) → tenant provisioned automatically
- Guided "Get Started" wizard: creates first agent, generates SDK API key, shows working `authorize()` code snippet for Python and TypeScript
- Free tier auto-provisioned (100K authorizations/month) on signup — no plan selection required at first use
- Quickstart documentation: zero → first `authorize()` + first `deny` + first audit query in under 15 minutes
- Activation event fires when first `authorize()` call succeeds (NSM instrumentation)

### Story 2 — Policy Builder UI

**As a** Tenant Admin, **I need to** create and deploy a WASM capsule policy using a visual interface or natural-language input, **so that** I can control what my agents are allowed to do without writing raw JSON AST or understanding the EIAA capsule format.

**Features:**
- Visual policy editor: drag-and-drop AST steps (VerifyAgentIdentity, AuthorizeToolCall, Allow/Deny, Conditional)
- Tool allowlist builder: select tools from registered agent's allowed_tools; set resource patterns and argument constraints per tool
- Natural-language policy description field → compiled to AST (optional, v1 can be visual-only)
- Policy test console: run a simulated `authorize()` call against a draft policy and see the decision before deploying
- One-click deploy: compile → sign → activate capsule; previous version archived with full history
- Policy version history: see every deployed version, who deployed it, and when

### Story 3 — Agent Consent Flow

**As an** End User, **I need to** see a clear consent screen when an AI agent requests permission to act on my behalf, listing exactly which tools it will use, which resources it can access, and for how long, **so that** I understand and explicitly authorize what the agent will do before it acts.

**Features:**
- Consent screen UI: hosted by AuthStar at `/consent/:flow_id` — embeddable in any app via redirect
- Shows: agent name, model identity, requested tools, resource scope, delegation TTL
- User approves → agent JWT issued with `delegation_chain: [user_id]`, TTL, and `allowed_tools` bound to the consent
- User denies → DENY returned, no JWT issued, event recorded in audit trail
- Revocation: user can see and revoke active agent delegations from their profile page
- Revocation is immediate: Redis blocklist key set, all active agent tokens invalidated

### Story 4 — Compliance Tier

**As a** Security/Compliance Lead, **I need to** export a complete, cryptographically verifiable authorization record for any agent session — including every tool call, decision, policy version, and attestation — so that I can satisfy enterprise security reviews, SOC 2 audits, and EU AI Act evidence requirements on demand.

**Features:**
- Task chain export: download full authorization record for a task as JSON or PDF, signed with the tenant's Ed25519 key
- Re-execution endpoint: `POST /api/v1/audit/verify` — provide an exported record, AuthStar re-runs the capsule and confirms the attestation matches
- Policy version history: every capsule ever deployed for a tenant is archived with its AST, WASM bytes, hash, and signature
- SOC 2 report: auto-generated evidence summary listing all agent actions in a date range, grouped by agent and policy
- Compliance tier badge: verifiable claim that the tenant's authorization model meets EIAA standard (for use in security questionnaire responses)

### Story 5 — SDK Completeness

**As an** AI Platform Engineer, **I need to** find a working code example for my language and framework in under 2 minutes and run it successfully in under 15 minutes, **so that** I can integrate AuthStar into my existing stack without a discovery phase.

**Features:**
- Python SDK: quickstart guide, `authorize()` + `get_task_chain()` + `revoke()` documented with copy-paste examples
- TypeScript SDK: same coverage; ESM + CJS builds; Deno-compatible
- Go SDK: add `AgentAuthzClient` with same API surface as Python/TypeScript
- React SDK: `useAgentAuthz()` hook for front-end consent flow integration
- Framework guides: LangChain, CrewAI, OpenAI Agents SDK — one-page integration guide per framework
- `authstar doctor` CLI command: diagnoses connectivity, SDK version, and tenant configuration

---

## 6. Acceptance Criteria

### Story 1 — Self-Serve Onboarding
- **Given** a developer with no prior AuthStar account, **When** they sign up and follow the Get Started wizard, **Then** they have a working `authorize()` call returning a valid decision within 15 minutes, with zero interaction from AuthStar's team
- [ ] New tenant is provisioned automatically on signup — no manual DB migration
- [ ] Free tier (100K authorizations/month) is active immediately
- [ ] Get Started wizard produces a working code snippet for Python and TypeScript
- [ ] Activation event (`first_authorize_success`) is instrumented and firing
- [ ] Quickstart documentation covers: authorize → deny → policy edit → audit query, all in under 15 minutes

### Story 2 — Policy Builder UI
- **Given** a tenant admin with no EIAA knowledge, **When** they use the Policy Builder to define an agent's allowed tools and deploy, **Then** the compiled capsule is active within 60 seconds and the next `authorize()` call evaluates against it
- [ ] Visual editor covers all required AST steps: VerifyAgentIdentity, AuthorizeToolCall, Allow, Deny, Conditional
- [ ] Policy test console accurately predicts the live `authorize()` response before deployment
- [ ] Deployed policy appears in version history with author and timestamp
- [ ] Previous policy version remains queryable after a new version is deployed

### Story 3 — Agent Consent Flow
- **Given** a user presented with an agent consent screen, **When** they approve, **Then** the issued agent JWT contains `delegation_chain: [user_id]`, the correct `allowed_tools`, and an `exp` matching the consent TTL
- [ ] Consent screen is rendered at `/consent/:flow_id` within 500ms
- [ ] Denial records a DENY event in `eiaa_executions` with `principal_type = "human_consent_deny"`
- [ ] User can view active delegations at `/profile/delegations`
- [ ] Revoking a delegation sets the Redis blocklist key within 100ms and the next `authorize()` call for that agent returns DENY

### Story 4 — Compliance Tier
- **Given** a compliance-tier tenant, **When** they export a task chain for a specific `task_id`, **Then** the export contains every authorization decision in the chain, each with its attestation, and `POST /api/v1/audit/verify` confirms all attestations are valid
- [ ] Task chain export generates a JSON file signed with the tenant's Ed25519 key
- [ ] `POST /api/v1/audit/verify` returns VALID or INVALID with per-decision detail
- [ ] SOC 2 report generates successfully for any 30-day window
- [ ] Policy version history is complete for all capsules ever deployed by the tenant

### Story 5 — SDK Completeness
- **Given** an engineer who has never used AuthStar, **When** they follow the quickstart for their language, **Then** they have a working `authorize()` call within 15 minutes
- [ ] Python, TypeScript, and Go quickstarts each verified in a cold-start usability test: < 15 minutes
- [ ] LangChain, CrewAI, and OpenAI Agents SDK integration guides are published and working
- [ ] `authstar doctor` correctly diagnoses a misconfigured tenant and outputs actionable fix instructions

---

## 7. Key Results & Success Metrics

### Definition of Done
- [ ] All 5 stories pass acceptance criteria
- [ ] NSM instrumentation live: `first_authorize_success`, `policy_deployed`, `task_chain_exported` events firing
- [ ] First 3 paying Production-tier customers active
- [ ] First 1 Compliance-tier customer active
- [ ] p99 authorization latency ≤ 50ms measured in production (baseline: 0.23ms in testing ✅)
- [ ] Time to First Authorized Tool Call ≤ 15 minutes, verified on new signups

### Strategic Metrics

| Category | Goal | Measurement | Target |
|----------|------|-------------|--------|
| **Activation** | Developer reaches first `authorize()` call | `first_authorize_success` event | ≤ 15 minutes from signup |
| **Adoption** | AI companies in production | Tenants with ≥1 authorize/week | 10 in 12 months (NSM) |
| **Retention** | Compliance value realized | Audit query adoption | > 60% of production tenants monthly |
| **Expansion** | Compliance tier conversion | Production → Compliance upgrade | > 30% after first enterprise security review |
| **Performance** | Latency at scale | p99 sidecar authorization | ≤ 50ms |

### Release-Specific Metrics

| Release | Product Outcomes | Metrics |
|---------|-----------------|---------|
| R1 — Self-Serve GA | PLG flywheel starts; first 3 paying customers | Signups, activation rate, free → Production conversion |
| R2 — Compliance GA | First enterprise deal unblocked by AuthStar evidence | Compliance tier signups, `task_chain_exported` events, enterprise deal closure |

---

## 8. Instrumentation

### Moments of Truth (MoTs) for Product-Led Growth

1. **MoT 1 — First `authorize()` Success:** Developer reaches their first authorized tool call. This is the activation event. Target: < 15 minutes from signup. Fire `first_authorize_success` with tenant ID, language, and time-to-activate.

2. **MoT 2 — First Policy Deployed via UI:** Tenant admin deploys their first capsule policy without writing JSON AST. This signals the product is self-service beyond the free-tier default. Fire `policy_deployed` with editor type (visual/natural-language) and time spent in editor.

3. **MoT 3 — First Audit Query:** Tenant queries `GET /api/v1/audit/task/:task_id` for the first time. This signals the compliance value is being realized, not just the authorization enforcement. Fire `task_chain_queried` with tenant ID and task depth.

4. **MoT 4 — First Compliance Export:** Tenant exports a task chain or SOC 2 report. This is the Compliance tier activation signal and the strongest predictor of retention. Fire `compliance_export` with export type and tenant tier.

### PLG Funnel Tracking

| Stage | Event | Conversion target |
|-------|-------|------------------|
| Signup | `tenant_created` | — |
| Activation | `first_authorize_success` | > 60% of signups within 7 days |
| Engagement | `policy_deployed` | > 40% of activated tenants within 30 days |
| Retention | `authorize_weekly_active` | > 50% of Production tenants at day 90 |
| Expansion | `compliance_tier_upgraded` | > 30% of Production tenants after first enterprise security review |

---

## 9. Non-Functional Requirements

### Performance
- Authorization p99 ≤ 50ms (sidecar/local-network); ≤ 2ms in-process
- Consent screen render ≤ 500ms
- Policy compilation and activation ≤ 60 seconds from "deploy" click
- Tenant provisioning ≤ 10 seconds from signup completion

### Security
- All new routes must have `EiaaAuthzLayer` applied — no exceptions
- JWT must never contain roles, permissions, or scopes (EIAA invariant)
- Consent flow CSRF-protected with double-submit cookie
- Compliance exports signed with tenant's Ed25519 key — tamper-evident
- Revocation propagates to Redis blocklist within 100ms

### Scalability
- Self-serve onboarding must support concurrent signups without DB contention (use existing `ON CONFLICT DO NOTHING` patterns)
- Policy Builder UI must handle concurrent policy deployments per tenant without cache race conditions — invalidate `CapsuleCacheService` on activation
- Audit trail write path must not block the authorization hot path — AuditWriter async batch writer is already implemented

### Compliance
- Task chain export format must include: Agent ID, User ID, Tool, Resource, Arguments, Policy Version, Decision, Timestamp (minimum 5+3 fields per auditor standard)
- Re-execution endpoint must be available for any record in the last 7 years (SOC 2 Type II evidence window)
- Data residency: sidecar deployment model keeps all decision data within customer infrastructure

---

## 10. High-Level User Requirements

### Persona 1 — AI Platform Engineer

- **Need 1: Zero-friction first use.** Can reach first `authorize()` call in under 15 minutes without reading architecture docs or understanding EIAA. The SDK is the product surface — WASM capsules are invisible.
- **Need 2: Framework-agnostic drop-in.** Works with LangChain, CrewAI, OpenAI Agents SDK, AutoGen, or any custom orchestration without changing tool implementations.
- **Need 3: Delegation chain preserved across handoffs.** Multi-agent systems with orchestrator → sub-agent handoffs preserve the full lineage in every authorization decision without extra developer work.
- **Need 4: Fail-closed by default.** If the authorization service is unreachable, the default behavior is DENY — not ALLOW. Developers must opt in to a fallback policy, not opt out of safety.

### Persona 2 — Security/Compliance Lead

- **Need 1: Evidence on demand.** Can export the complete authorization record for any agent session in under 5 minutes, without engineering involvement.
- **Need 2: Third-party verifiability.** The exported record can be independently verified by the enterprise customer's security team using `POST /api/v1/audit/verify` — no AuthStar account required for verification.
- **Need 3: Policy version traceability.** Every authorization decision is linked to the exact policy version that made it — so a policy change can never retroactively alter the evidentiary record.
- **Need 4: Real-time revocation.** When an agent is revoked, all active tokens are invalidated within 100ms — not at next token expiry.

---

## 11. Feature Epics Breakdown

| Epic | Release | Priority | Description | Blocks |
|------|---------|----------|-------------|--------|
| **E1: Self-Serve Tenant Onboarding** | R1 | P0 | Signup, provisioning, Get Started wizard, activation instrumentation | All other epics — no customer can reach anything without this |
| **E2: Policy Builder UI** | R1 | P0 | Visual policy editor, test console, deploy, version history | E3, E4 — compliance tier requires versioned policies |
| **E3: SDK Quickstarts & Completeness** | R1 | P1 | Python/TS/Go quickstarts, framework guides, `authstar doctor` CLI | NSM activation — engineers can't self-serve without quickstarts |
| **E4: Agent Consent Flow** | R2 | P1 | Hosted consent screen, delegation JWT, revocation UI | Persona 2 compliance story requires consent linkage in audit |
| **E5: Compliance Tier** | R2 | P1 | Task chain export, re-execution endpoint, SOC 2 report, compliance badge | Persona 2 purchase trigger; enterprise deal unblocking |
| **E6: Go + React Agent SDKs** | R2 | P2 | Go `AgentAuthzClient`, React `useAgentAuthz()` hook | Persona 3 expansion; enterprise IdP integrations |
| **E7: Webhook Reliability** | R2 | P2 | Retry queue, delivery confirmation, dead-letter for agent action webhooks | Persona 1 production reliability |

---

## 12. Risks & Mitigation

### Strategic Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Anthropic / OpenAI build native agent AuthZ that satisfies enterprise buyers | High | Medium | AuthStar's cross-platform, cross-model re-executable attestation is the differentiator — a platform-native solution cannot be verified independently by a third party. Accelerate time to first 10 customers before this risk materializes. |
| Category defined by an OSS competitor (agentgateway, agent-guard) before AuthStar reaches scale | High | Medium | Contribute to framework communities (LangChain, CrewAI integration guides) before competitor does. Open-source the SDK. Managed platform + compliance tier are the commercial moat. |
| Per-execution pricing assumed internally but rejected by buyers | Medium | Low | Pricing model is usage-based (validated by market data). Do not ship per-execution-only pricing. Compliance tier is the revenue lever. |

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Policy Builder UI produces invalid AST that passes the editor but fails capsule compilation | High | Medium | Policy test console must run actual compilation before showing "valid" — not just client-side validation. Gate deploy button on successful compile. |
| Capsule cache race condition on concurrent policy deployments | Medium | Low | Existing `CapsuleCacheService` with Redis TTL handles this; invalidate on activation using existing pattern. Add integration test for concurrent deploys. |
| Self-serve provisioning DB contention under concurrent signups | Medium | Low | Use existing `ON CONFLICT DO NOTHING` patterns from OrganizationService. Load test at 100 concurrent signups before R1 launch. |

### Market Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Persona 1 adopts the free tier but never converts to paid | Medium | Medium | Instrument the activation funnel precisely. Identify where free-tier users hit the 100K limit and present upgrade prompt with compliance story, not just a paywall. |
| Enterprise security reviews require on-premises deployment before considering SaaS | Medium | Medium | Sidecar model already supports fully on-premises deployment — decision data never leaves customer infrastructure. Communicate this clearly in the compliance tier docs and security questionnaire template. |

---

## 13. Assumptions & Constraints

### Strategic Assumptions
- Practitioner-validated: 5/5 platform engineers and 3/3 compliance leads confirmed the pain and purchase trigger (OpA v3)
- Usage-based pricing is the right model for Persona 1; compliance premium is the right model for Persona 2 (market data validated)
- PLG motion (developer installs SDK, converts on free tier limit) is viable before investing in enterprise sales motion
- The sidecar deployment model satisfies data residency requirements for the initial enterprise segment

### Technical Constraints
- Every new route must use `EiaaAuthzLayer` — no exceptions (AGENTS.md)
- JWT must never contain roles, permissions, or scopes — EIAA invariant is non-negotiable
- DB migrations are forward-only — no modifying existing migration files
- Policy Builder UI must call the actual capsule compiler for validation — no client-side-only AST validation
- AuditWriter async batch path must not be bypassed for the compliance tier — write-behind is intentional for performance

### Out of Scope (this Master Epic)
- Kubernetes HA configuration and multi-region deployment
- Additional OAuth 2.0 grant types beyond what is already implemented
- More capsule AST step types beyond the current 13 (no premature AST expansion)
- Go SDK agent support beyond `AgentAuthzClient` basic API surface
- Government / sovereign deployment packaging (future Master Epic)

---

## 14. Open Questions & Decisions

### Strategic Questions
- [ ] What is the exact per-million-authorization price for the Production tier? (Needs pricing interview synthesis)
- [ ] Should the Compliance tier be a flat monthly add-on or a multiplier on the Production tier base? (Run pricing test with 5 buyers)
- [ ] Should AuthStar open-source the SDK and keep the managed platform proprietary, or keep both closed-source? (Community growth vs. competitive protection)

### Technical Questions
- [ ] Should the Policy Builder UI ship as a visual drag-and-drop editor (more build effort) or a structured form with pre-built templates (faster to ship, lower ceiling)? Recommend: structured form with templates for R1, drag-and-drop for R2.
- [ ] Should `authstar doctor` CLI be a standalone binary or a subcommand of an `authstar` CLI that also handles tenant config? Recommend: subcommand of a unified `authstar` CLI.
- [ ] Does the consent flow need a mobile-responsive design for R1, or is desktop-only acceptable for the initial AI builder segment?

### Key Decisions Needed

| Decision | Owner | Status |
|----------|-------|--------|
| Production tier price per million authorizations | Founder / PM | Open — pending pricing interviews |
| Policy Builder UI: form templates vs. drag-and-drop for R1 | Engineering Lead | Recommend form templates for R1 |
| SDK open-source strategy | Founder | Open |
| R1 scope lock | PM + Engineering Lead | Required before first sprint |

---

## 15. Next Steps

### Immediate Actions
1. **Lock R1 scope** — confirm E1 (Onboarding) and E2 (Policy Builder UI) as the R1 epics; confirm E3 (SDK Quickstarts) is also R1
2. **Draft Feature Epics E1, E2, E3** — one Epic document per feature, with user requirements and acceptance criteria broken into sprint-ready stories
3. **Pricing decision** — run 5 pricing interviews with the Production tier model; set price before R1 launch
4. **SDK open-source decision** — this affects community GTM strategy; decide before R1
5. **Update ROADMAP.md** — mark Discovery phase complete; mark Delivery phase in progress

### Governance
- **Review cadence:** Bi-weekly — review NSM, activation funnel, and epic status
- **Decision authority:** Founder for strategic decisions (pricing, open-source); Engineering Lead for technical scope decisions
- **Communication:** Update this document after each review; link from ROADMAP.md

---

## 16. Success Criteria — Definition of Done

- [ ] E1: Any engineer can go from zero to first `authorize()` call in ≤ 15 minutes unassisted
- [ ] E2: Any tenant admin can deploy a working policy without writing JSON AST
- [ ] E3: Python, TypeScript, and Go quickstarts all verified at ≤ 15 minutes cold-start
- [ ] E4: End-user can authorize and revoke an AI agent delegation from their profile page
- [ ] E5: Compliance-tier tenant can export a task chain, verify all attestations via the API, and generate a SOC 2 report for any 30-day window
- [ ] NSM instrumentation live and baseline established
- [ ] First 3 paying Production-tier customers active
- [ ] First 1 Compliance-tier customer active

---

## Resources

- [Winning Products Master Epic Guidance](https://w3.ibm.com/w3publisher/ibm-software-roadmaps/roadmaps-into-aha/roadmaps-into-aha-part-3)
- [Winning Products Delivery Phase](https://w3.ibm.com/w3publisher/winning-products/how-we-work/product-development-lifecycle/delivery)
- [OpA — AI Agent AuthZ (validated)](opa-ai-agent-authz.md)
- [PR-FAQ — AuthStar](prfaq-authstar.md)
- [Winning Products Roadmap](ROADMAP.md)
