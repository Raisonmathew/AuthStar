# Epic E1 — Self-Serve Tenant Onboarding

> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P0 · **Blocks:** E2, E3, E4, E5 — no customer reaches anything without this
> **NSM contribution:** Activation — `first_authorize_success` event
> **Status:** Ready for development — user stories drafted
> **User Stories:** [user-stories-e1-onboarding.md](user-stories-e1-onboarding.md)

---

## 1. Problem Statement

A developer who wants to evaluate AuthStar today cannot sign up, provision a tenant, and reach their first `authorize()` call without manual DB migration, environment configuration, and engineering involvement from the AuthStar team. This makes PLG impossible and caps growth to the number of customers that can be manually onboarded.

Every new customer must be able to go from zero to a working authorized agent call in under 15 minutes, unassisted, on any day of the week.

---

## 2. Product Outcomes & Instrumentation

| Phase | Product Outcome | Metric |
|-------|----------------|--------|
| R1 Launch | > 60% of signups reach first `authorize()` call within 7 days | `first_authorize_success` event per cohort |
| R1 Launch | Median time-to-first-authorize < 15 minutes | Time delta: `tenant_created` → `first_authorize_success` |
| R1 Launch | Zero manual provisioning interventions per week | Count of support tickets or manual DB interventions for onboarding |
| 30 days post-launch | > 20% of activated tenants convert to Production tier | `plan_upgraded` event on free → Production conversion |

---

## 3. Assumptions

- Tenant provisioning uses existing `OrganizationService` patterns — `ON CONFLICT DO NOTHING` handles concurrent signups safely
- Free tier (100K authorizations/month) is auto-provisioned on signup with no plan selection required — reduce friction at first contact
- Google and GitHub OAuth signup are supported from day one (engineers prefer OAuth over email/password for tooling)
- The Get Started wizard generates a real, working API key scoped to the new tenant — not a placeholder
- The wizard targets Python and TypeScript first (the two SDKs with existing agent support); Go is R2
- No credit card required at signup — free tier is unconditional
- The `authstar doctor` CLI diagnostic is part of E3 (SDK Quickstarts), not this epic — but the wizard must output a command the developer can run to verify connectivity

---

## 4. Non-Functional Requirements

- Tenant provisioning completes in ≤ 10 seconds from signup form submission
- Signup page loads in ≤ 1 second (no heavy JS bundles blocking first paint)
- Free tier enforced by existing `EntitlementService` — no new billing logic needed for R1 free tier
- API key generated with `nanoid`-based prefixed ID (`sk_live_` prefix for production keys, `sk_test_` for sandbox) — key is shown exactly once at generation, never stored in plaintext, hashed with Argon2id
- All new signup routes must have `EiaaAuthzLayer` applied for admin paths; public signup routes are unauthenticated by design
- Rate limit signup endpoint at 10 requests/minute per IP (existing `rate_limit_auth_flow` Redis sliding window pattern)
- CSRF protection on all form submissions (existing double-submit cookie pattern)
- Tenant slug auto-generated from company name; editable before confirmation; unique enforcement via DB constraint

---

## 5. User Requirements

| # | User Story | User Requirement |
|---|-----------|-----------------|
| 1 | An AI Platform Engineer needs to create an AuthStar account so that they can start evaluating the product | Signup form accepts email + password OR Google/GitHub OAuth; confirms email; provisions tenant automatically |
| 2 | | Tenant slug is auto-generated and shown for confirmation before finalizing |
| 3 | | Free tier (100K authorizations/month) is active immediately — no plan selection, no credit card |
| 4 | An AI Platform Engineer needs to get credentials so that they can call `authorize()` from their code | Get Started wizard generates an API key scoped to the new tenant |
| 5 | | API key displayed once inline; copy-to-clipboard button; SHA-256 fingerprint shown for verification |
| 6 | | SDK installation command shown for Python and TypeScript (`pip install authstar-agent` / `npm install @authstar/agent`) |
| 7 | An AI Platform Engineer needs a working code example so that they can make their first authorized call without reading docs | Wizard shows a pre-filled `authorize()` code snippet with the real tenant ID and API key already inserted |
| 8 | | Snippet covers: import, call `authorize()`, check `decision.allowed`, print `decision.audit_id` |
| 9 | | "Run in your terminal" button copies the full working command including `pip install` + the snippet |
| 10 | An AI Platform Engineer needs to confirm their setup is working so that they know they're ready to integrate | After wizard completion, a live "waiting for first call…" indicator polls for `first_authorize_success` event |
| 11 | | When first `authorize()` call arrives, the indicator turns green with "✅ First authorization received — you're live" |
| 12 | | `first_authorize_success` event is fired with `tenant_id`, `sdk_language`, and `time_to_activate_seconds` |
| 13 | A returning developer needs to find their API keys and tenant config so that they can set up a new environment | Dashboard → Settings → API Keys shows all active keys with fingerprint, created date, last used, and revoke button |
| 14 | | Tenant ID and base URL are shown in Settings → General — copy-to-clipboard |
| 15 | An AI Platform Engineer needs to understand what went wrong if their first call fails so that they can fix it without filing a support ticket | Error responses from `authorize()` include a human-readable `message` field and a `docs_url` linking to the relevant troubleshooting guide |
| 16 | | Common errors (invalid API key, tenant not found, agent not registered) have named error codes (`ERR_INVALID_KEY`, `ERR_AGENT_NOT_FOUND`) |

---

## 6. Open Questions & Considerations

**Questions:**
- [ ] Should the wizard include a "register your first agent" step inline, or leave that to the quickstart docs? Recommendation: include a minimal agent registration step — without a registered agent, the `authorize()` call will fail and the developer won't understand why.
- [ ] Should email verification be required before the API key is shown, or can it be deferred? Recommendation: defer email verification — require it before Production tier conversion, not before free tier activation. Friction at first use costs activation.
- [ ] Should sandbox (test) keys and production keys be separate tiers, or a single key type? Recommendation: single key type with `sk_test_` prefix for the free tier; `sk_live_` prefix issued on Production tier upgrade.

**Considerations:**
- The Get Started wizard is the highest-leverage UX investment in R1. A developer who fails to reach `first_authorize_success` in 15 minutes is unlikely to return.
- The "waiting for first call" live indicator creates a dopamine moment — the developer sees AuthStar respond to their actual code in real time. This is the activation hook.
- API key generation must use the existing `ApiKeyService` pattern — do not create a new key storage mechanism.

---

## Next Steps

1. ✅ User stories drafted — see [user-stories-e1-onboarding.md](user-stories-e1-onboarding.md)
2. Kick off with engineering — walk through US-01 through US-07 and confirm sprint ordering
3. **Start Sprint 1 now:** US-01 (Signup) + US-07 (Error codes) — US-07 can be parallelised
4. Design Get Started wizard (3 screens: account → credentials → first call confirmation) before Sprint 3
5. Usability test after Sprint 4 with 2 cold-start engineers — gate: < 15 minutes unassisted

---

## Resources

- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products Epics](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts/epics)
- [PR-FAQ — AuthStar](prfaq-authstar.md)
