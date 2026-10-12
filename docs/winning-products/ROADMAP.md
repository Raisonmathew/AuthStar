# AuthStar — Winning Products Roadmap

> **Framework:** IBM Winning Products PDLC
> **Created:** 2026-03-06
> **Status:** ✅ Discovery Complete → 🔵 Delivery Phase in progress

---

## North Star Metric (NSM)

> **10+ AI companies using AuthStar to authorize agent tool calls in production within 12 months.**

Every product decision, priority call, and feature gate should be measured against this metric.
Secondary metric: Active human auth tenants (measuring the parallel IDaaS business).

---

## Segment Priority Order

| Priority | Segment | Buyer | Pain |
|----------|---------|-------|------|
| 1 | **AI Builders** | CTO / Head of AI Eng at companies building with Claude/GPT/Gemini | No cryptographic proof of what their agent was authorized to do; no re-executable audit |
| 2 | **Enterprise Compliance** | CISO / Head of IAM at regulated enterprises | Authorization logic baked into tokens — can't audit, can't replay, can't prove |
| 3 | **Sovereign Gov / Defense** | Gov IT Architects | US/EU data sovereignty requirements; can't use US-cloud IdPs; need air-gappable AuthZ |

---

## PDLC Phase Plan

### Phase 1 — DISCOVERY ✅ Complete

| Step | Artifact | Status | Purpose |
|------|----------|--------|---------|
| 1 | **OpA: AI Agent AuthZ** | ✅ Validated (v3) | 5/5 engineers + 3/3 compliance leads confirmed |
| 2 | **PR-FAQ** | ✅ Drafted (v1) | GA press release — working backwards complete |
| 3 | **Master Epic: GA Launch** | ✅ Drafted (v1) | 7 feature epics, 2 releases scoped |
| 4 | **OpA: Human IDaaS** | ⬜ Not started | Validate enterprise IDaaS opportunity (post R1) |

**Gate met:** 5/5 platform engineers + 3/3 compliance leads confirmed pain and purchase trigger.

---

### Phase 2 — DELIVERY 🔵 In Progress

| Epic | Release | Priority | Status | Outcome |
|------|---------|----------|--------|---------|
| **E1: Self-Serve Tenant Onboarding** | R1 | P0 | ✅ Drafted | Zero → first `authorize()` in ≤ 15 min, no engineering involvement |
| **E2: Policy Builder UI** | R1 | P0 | ✅ Drafted | Deploy a WASM capsule without writing JSON AST |
| **E3: SDK Quickstarts** | R1 | P1 | ✅ Drafted | Python/TS/Go quickstarts + framework guides ≤ 15 min |
| **E4: Agent Consent Flow** | R2 | P1 | ✅ Drafted | End-user authorizes AI agent via hosted consent screen |
| **E5: Compliance Tier** | R2 | P1 | ✅ Drafted | Task chain export, re-execution endpoint, SOC 2 report |
| **E6: Go + React Agent SDKs** | R2 | P2 | ⬜ Not started | Go `AgentAuthzClient`, React `useAgentAuthz()` hook |
| **E7: Webhook Reliability** | R2 | P2 | ⬜ Not started | Retry queue, delivery confirmation, dead-letter |

---

### Phase 3 — GROWTH (After first 3 paying customers)

| Activity | Purpose |
|----------|---------|
| Instrument NSM tracking | Know when a new customer's first agent tool call is authorized |
| Activation funnel metrics | Where do customers drop off during onboarding? |
| Retention signals | Which capsule policy patterns correlate with long-term retention? |
| Pricing validation | Test packaging — per-seat vs. per-capsule-execution vs. MAU |

---

## What NOT to build next

These are well-engineered but should not consume more resources until Discovery is validated:

- More capsule AST step types
- Go SDK agent support
- Additional OAuth 2.0 grant types
- Kubernetes HA configuration

---

## Document Index

| Document | File | Status |
|----------|------|--------|
| OpA — AI Agent AuthZ | `docs/winning-products/opa-ai-agent-authz.md` | ✅ Validated (v3) |
| PR-FAQ | `docs/winning-products/prfaq-authstar.md` | ✅ Drafted (v1) |
| Master Epic: GA Launch | `docs/winning-products/master-epic-ga.md` | ✅ Drafted (v1) |
| Feature Epic E1: Self-Serve Onboarding | `docs/winning-products/epic-e1-onboarding.md` | ✅ Drafted — 7 user stories |
| Feature Epic E1 User Stories | `docs/winning-products/user-stories-e1-onboarding.md` | ✅ 7 stories (US-01–US-07) |
| Feature Epic E2: Policy Builder UI | `docs/winning-products/epic-e2-policy-builder.md` | ✅ Drafted — 6 user stories |
| Feature Epic E2 User Stories | `docs/winning-products/user-stories-e2-policy-builder.md` | ✅ 6 stories (US-01–US-06) |
| Feature Epic E3: SDK Quickstarts | `docs/winning-products/epic-e3-sdk-quickstarts.md` | ✅ Drafted — 6 user stories |
| Feature Epic E3 User Stories | `docs/winning-products/user-stories-e3-sdk-quickstarts.md` | ✅ 6 stories (US-01–US-06) |
| Feature Epic E4: Agent Consent Flow | `docs/winning-products/epic-e4-consent-flow.md` | ✅ Drafted |
| Feature Epic E4 User Stories | `docs/winning-products/user-stories-e4-consent-flow.md` | ✅ 5 stories |
| Feature Epic E5: Compliance Tier | `docs/winning-products/epic-e5-compliance-tier.md` | ✅ Drafted |
| Feature Epic E5 User Stories | `docs/winning-products/user-stories-e5-compliance-tier.md` | ✅ 6 stories |
| OpA — Human IDaaS | _(file not yet created)_ | ⬜ Not started — post-R1 |
