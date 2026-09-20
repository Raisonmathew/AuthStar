# PR-FAQ — AuthStar

> **Winning Products Phase:** Discovery (Working Backwards)
> **Status:** Draft v1 (2026-03-06)
> **Inputs:** OpA v3 (validated), deep research findings, 5 practitioner interviews, 3 CISO interviews
> **Next step after approval:** Master Epic — GA Launch

---

## PRESS RELEASE

**FOR IMMEDIATE RELEASE**

---

### AuthStar Makes Every AI Agent Action Provable

#### The first authorization platform that cryptographically proves what an AI agent was allowed to do — before it acts, not after

---

**[City, Date]** — AuthStar today announced general availability of its AI Agent Authorization platform, giving companies building on Claude, GPT-4o, Gemini, and custom models the ability to authorize every agent tool call before it executes — and produce a cryptographic proof of that decision that any auditor, regulator, or enterprise customer can independently verify.

Until now, companies deploying AI agents in production have relied on API keys, OAuth scopes, or application-level `if` statements to control what their agents can do. None of these produce a record that proves the agent was authorized for a specific action at a specific moment. When something goes wrong — and in production, things go wrong — engineering teams spend days reconstructing what happened from logs that were never designed to answer the question: *"Was this agent authorized to do this?"*

AuthStar answers that question with a single function call:

```python
from authstar import authorize

decision = authorize(
    agent="agt_abc123",
    user="usr_human123",
    tool="send_email",
    resource="inbox:customer@acme.com",
    args={"subject": "...", "body": "..."},
    delegation_chain=["usr_human123"]
)
# decision.allowed       → True / False
# decision.attestation   → cryptographic proof, re-executable by any third party
# decision.audit_id      → links to the complete task chain
# decision.policy_version → the exact policy version that made this decision
```

The decision is backed by a compiled WebAssembly policy capsule, signed with Ed25519, and written to a tamper-evident audit trail. The entire record — agent identity, tool called, resource accessed, arguments provided, policy version, and the decision itself — can be re-executed by a regulator or customer to independently verify the outcome. No other authorization system offers this.

"Every team building AI agents is writing the same authorization middleware over and over," said [Founder]. "We built that layer once, made it cryptographically verifiable, and gave it back to the community as a drop-in SDK. If an agent misbehaves, you don't need a three-week investigation — you replay the authorization record and have your answer in seconds."

AuthStar's enforcement layer adds 0.23ms at p99 — imperceptible in any agent workflow. It supports Python, TypeScript, and Go, integrates with existing HTTP stacks without changing tool implementations, and is available today with a free tier covering 100,000 authorizations per month.

AuthStar also extends the same enforcement model to human authentication — supporting OAuth 2.0, SAML 2.0, WebAuthn/passkeys, TOTP MFA, and multi-tenant organization management — making it the only platform that applies a single, consistent authorization architecture to both human and AI principals.

---

**Availability:** AuthStar is available now at [authstar.dev]. Free tier: 100K authorizations/month. Production tier: $49/month (includes 5M authorizations) + $0.0001 per authorization overage. Compliance tier: $299/month add-on — immutable evidence, policy versioning, and SOC 2 audit reports included.

---

## CUSTOMER FAQs

**Q: How is AuthStar different from just using OAuth scopes or an API key per agent?**

OAuth scopes and API keys are static — they grant access at the session level but cannot evaluate the context of a specific action (which resource, which arguments, what risk score, what time). They also produce no record that proves the authorization decision was made. With AuthStar, every tool call is evaluated at the moment it happens against a compiled policy that knows the full context, and the decision is signed and stored. A scope that says "can write email" cannot tell you whether the agent was authorized to write *this* email to *this* recipient at *this* moment. AuthStar can.

**Q: What does "re-executable attestation" mean in practice?**

When AuthStar authorizes a tool call, it produces a signed record containing the agent identity, the tool called, the resource, the arguments, the policy version, the full evaluation context, and the decision. That record can be fed back into AuthStar at any point in the future — by you, by an auditor, or by your enterprise customer — and it will re-run the same policy against the same inputs and produce the same signed output. If the record has been tampered with, verification fails. This is what "cryptographic proof" means: not a log entry, but a reproducible, verifiable decision.

**Q: What does it look like when an enterprise customer's security team asks for proof of authorization?**

You export the task chain for the relevant agent session — a structured record of every action the agent took, each linked to its authorization decision and policy version. The security team can replay any decision in that chain themselves to verify it matches the record. They get: Agent ID, User ID, Tool, Resource, Arguments, Policy Version, Decision, Timestamp — the exact five-plus fields enterprise auditors require for AI governance evidence.

**Q: Does this work with multi-agent systems where one agent delegates to another?**

Yes. AuthStar's JWT carries a `delegation_chain` field that tracks the full human → orchestrator → sub-agent lineage. Each delegation step is evaluated against a policy capsule. The `parent_action_id` field in the audit trail links every sub-agent action back to the parent action that authorized the delegation. You can reconstruct the complete causal chain for any task across any number of agent handoffs.

**Q: What frameworks does AuthStar work with?**

AuthStar is framework-agnostic. The `authorize()` call is a plain HTTP call to AuthStar's sidecar or hosted service — it works with LangChain, CrewAI, OpenAI Agents SDK, Anthropic tool use, AutoGen, or any custom orchestration framework. You do not change your tool implementations. You add one function call before each tool executes.

**Q: How does this handle the case where my agent is making thousands of tool calls per minute?**

AuthStar's enforcement point runs as a local sidecar — policy decisions are evaluated in-process against a cached, compiled policy. Authorization adds 0.23ms at p99 under load. At 10,000 tool calls per minute, the total overhead is under 2.3 seconds of authorization time per minute. The audit trail is written asynchronously via a write-behind batch writer with 10,000-capacity channel — it does not block the authorization path.

**Q: What happens if the AuthStar service is unavailable?**

AuthStar is fail-closed by design — if the authorization service cannot be reached and no cached policy is available, the `authorize()` call returns DENY. The circuit breaker on the gRPC runtime client opens after 5 consecutive failures and recovers after 30 seconds. Teams can configure a local fallback policy for high-availability deployments. We recommend the sidecar deployment model for latency-sensitive or air-gapped environments.

**Q: Can I use AuthStar for human authentication as well as AI agents?**

Yes. AuthStar applies the same Entitlement-Independent Authentication Architecture (EIAA) to both human and AI principals. Human users authenticate via email/password, OAuth (Google, GitHub, Microsoft), WebAuthn/passkeys, or TOTP MFA. The same WASM policy capsule that authorizes an AI agent tool call also authorizes a human's API request. The JWT never carries roles or permissions — authorization is always evaluated at request time against the current context. This gives enterprise teams a single authorization architecture for their entire stack.

---

## INTERNAL FAQs

**Q: What is the business model and why usage-based?**

Usage-based pricing aligns with how platform engineers think about infrastructure cost: they know their agent call volume and can predict their authorization bill. The market has validated this model — Pore, Permit, Kastra, and Ceadly all use usage-based pricing, ranging from $0.00002 to $0.002 per decision. AuthStar's compliance tier (immutable evidence, policy versioning, SOC 2 reports) commands a premium similar to Ceadly's $2K–$10K/month immutable-evidence add-on, because regulated enterprise buyers are paying for the cryptographic proof layer, not the raw authorization volume.

Tier structure:
- **Developer:** Free / 100K authorizations/month — PLG on-ramp
- **Production:** $49/month (includes 5M authorizations) + $0.0001/authorization overage — predictable, scales with agent usage
- **Compliance:** $299/month add-on on top of Production — immutable evidence, policy versioning, SOC 2 reports — Persona 2 purchase trigger
- **Enterprise:** Annual ACV, custom volume, IdP integration, dedicated SLA — Persona 3 expansion

**Q: Why will customers choose AuthStar over building their own?**

Every team we interviewed is building their own authorization middleware. Whelix built fail-closed AuthZ for a 32-tool platform. AgentLock was created because OpenAI's Agents SDK had no per-tool authorization. JofeTube333 built a custom step-by-step tracing tool. The problem is that custom solutions solve one dimension (either enforcement, or logging, or policy) but never the combination of enforcement + provenance + cryptographic re-executability. That combination is what enterprise procurement requires and what AuthStar uniquely provides. The build-vs-buy decision tips toward buy when the custom solution cannot produce a cryptographic re-executable record — which no custom solution can without building EIAA from scratch.

**Q: What is the Go-to-Market motion?**

Phase 1 — PLG: Developer installs SDK, reaches first `authorize()` call in under 15 minutes, converts to Production tier when they hit the free tier limit. Acquisition channel: AI agent framework communities (LangChain Discord, CrewAI GitHub, OpenAI Developers Forum), developer blogs, and open-source contributions.

Phase 2 — PLS: Once a company has 3+ production agents using AuthStar, a solutions engineer reaches out to discuss the Compliance tier. The trigger is the first enterprise security review the customer faces — that is when the compliance story becomes a purchase trigger.

Phase 3 — Enterprise: After the Compliance tier is validated with 10+ customers, package for Persona 3 (Enterprise CISO) with IdP connectors, compliance reporting, and SLA.

**Q: What is the biggest risk to the business?**

The biggest risk is that large AI platform companies (Anthropic, OpenAI, Google DeepMind) build native authorization layers that are "good enough" for their own ecosystems, reducing the urgency for a third-party solution among companies building on those platforms. The mitigation: AuthStar's cryptographic re-executability is a cross-platform, cross-model standard — an auditor can verify an AuthStar attestation regardless of which model or framework generated the agent action. No single AI platform's native solution can make that claim.

**Q: What does the competition look like in 12 months?**

The category is forming. agentgateway and agent-guard are OSS with no managed platform play. Aport.io is the closest direct competitor but lacks WASM capsule re-execution and a compliance tier. Pore/Permit/Kastra are generic AuthZ APIs without agent identity models. The risk is that one of these adds cryptographic attestation before AuthStar reaches scale. Speed to first 10 paying customers is the critical metric.

**Q: What are the two biggest product gaps before GA?**

1. **Self-serve onboarding:** A customer cannot currently sign up, provision a tenant, and reach their first authorization call without engineering involvement. This blocks PLG entirely and is the P0 epic for the GA launch.
2. **Policy Builder UI:** Writing a WASM capsule policy requires raw JSON AST. No Persona 1 engineer will do this. A visual policy editor — or at minimum, a natural-language-to-policy compiler — is required before AuthStar is self-service for non-trivial use cases. This is the P1 epic.

**Q: How does AuthStar handle data residency requirements?**

The local/sidecar deployment model keeps all authorization decisions and audit records within the customer's own infrastructure. The control plane (policy compilation and distribution) can be hosted in any region. For regulated industries (EU AI Act, GDPR, HIPAA), the sidecar model ensures no agent action data leaves the customer's environment. This is a deliberate architectural choice — not a feature to add later.

**Q: What are the metrics we will track at launch?**

| Metric | Target | Review cadence |
|--------|--------|----------------|
| NSM: AI Production Tenants | 10 in 12 months | Monthly |
| Time to First Authorized Tool Call | < 15 minutes | Per new signup cohort |
| Developer → Production conversion | > 20% in 90 days | Monthly |
| Audit Query Adoption | > 60% of production tenants | Monthly |
| Authorization Latency p99 | < 50ms sidecar | Weekly |
| Compliance Tier Conversion | > 30% of Production tenants after first enterprise security review | Quarterly |

---

## Next Step: Master Epic

The PR-FAQ defines what we are building and for whom. The next governing document is the **Master Epic — AuthStar GA Launch**, which breaks the GA launch into P0/P1/P2 delivery epics:

- P0: Self-Serve Tenant Onboarding
- P0: Policy Builder UI (or natural-language policy compiler)
- P1: Agent Consent Flow (end-user authorizes an AI agent)
- P1: SDK Completeness (Go + React agent support, all SDKs with quickstart)
- P2: Webhook Reliability

See: [`master-epic-ga.md`](master-epic-ga.md)

---

## Resources

- [Winning Products PR-FAQ Method](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- [PDLC Discovery Phase](https://w3.ibm.com/w3publisher/winning-products/how-we-work/product-development-lifecycle/discovery)
- [OpA — AI Agent AuthZ (validated)](opa-ai-agent-authz.md)
- [AuthStar Winning Products Roadmap](ROADMAP.md)
