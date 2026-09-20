# Epic E4 — Agent Consent Flow

> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R2 · **Priority:** P1
> **Depends on:** E1 (tenant + human auth), E2 (policies must exist to scope the consent)
> **NSM contribution:** Expands addressable use cases — enables user-delegated AI agents, not just service-to-service
> **Status:** Ready for development — user stories drafted
> **User Stories:** [user-stories-e4-consent-flow.md](user-stories-e4-consent-flow.md)

---

## 1. Problem Statement

AuthStar can issue an agent JWT, but today only a tenant admin or service account can do so — via `POST /api/v1/agents/token` with an admin-level JWT. There is no mechanism for an **end user** to authorize an AI agent to act on their behalf, see what the agent is permitted to do, or revoke that permission later.

This is the missing delegation primitive. Without it, the authorization record shows "admin issued this token" rather than "user Alice authorized this agent to act for her" — which means the compliance chain is broken at the most important link: human consent.

Every AI agent acting on behalf of a human user must have an explicit, recorded, revocable consent decision from that user — not just a service account token.

---

## 2. Product Outcomes & Instrumentation

| Phase | Product Outcome | Metric |
|-------|----------------|--------|
| R2 Launch | > 30% of production tenants using the consent flow for at least one agent delegation per week | `consent_granted` events per tenant per week |
| R2 Launch | Consent screen renders in ≤ 500ms | p95 consent screen render time |
| R2 Launch | > 80% of users who see a consent screen complete it (grant or deny) without abandoning | Consent screen completion rate: `consent_screen_shown` → `consent_granted` or `consent_denied` |
| 60 days post-R2 | Revocation used by > 10% of tenants (signals the feature is discoverable and trusted) | `consent_revoked` event count |

---

## 3. Assumptions

- Consent flow is triggered by the **application** (not AuthStar) — the app redirects the user to AuthStar's hosted consent screen at `/consent/:flow_id`; AuthStar handles the UI and token issuance; the app receives the agent JWT via callback
- This mirrors the OAuth 2.0 authorization code flow model — familiar to developers, auditable by design
- The consent screen is **hosted by AuthStar** — tenants do not need to build their own consent UI; they can optionally brand it (logo + colours) using existing tenant branding settings
- Agent JWT issued after consent carries `delegation_chain: [user_id]`, `allowed_tools` bound to the consent, and `exp` matching the TTL the user agreed to
- Revocation is **immediate** — Redis blocklist key set within 100ms; not deferred to token expiry
- The consent record is stored as an `eiaa_executions` row — a consent grant is a capsule execution with `action = "user:delegate_to_agent"` — making it part of the tamper-evident audit trail
- Human auth (E1) must exist — the user must be signed in to grant consent; unauthenticated consent redirects to sign-in

---

## 4. Non-Functional Requirements

- Consent screen renders in ≤ 500ms cold (no blocking API calls before first paint)
- Consent flow uses CSRF protection — consent form has a CSRF token bound to the flow ID
- Agent JWT issued after consent must include: `sub = agent_id`, `principal_type = "ai_agent"`, `delegation_chain = [user_id]`, `allowed_tools`, `exp = now + ttl_seconds`, `tenant_id`
- Consent record written to `eiaa_executions` with `action = "user:delegate_to_agent"`, `principal_type = "human"`, `user_id`, `agent_id`, `allowed_tools` in `input_context` JSONB
- Revocation propagates to Redis blocklist (`agent_blocklist:{agent_id}:{user_id}`) within 100ms
- Consent screen must be mobile-responsive — users may see it on a phone during a web session
- Consent screen must be accessible: WCAG 2.1 AA — keyboard navigable, screen reader compatible, sufficient colour contrast

---

## 5. User Requirements

| # | User Story | User Requirement |
|---|-----------|-----------------|
| 1 | A developer needs to initiate a consent flow for their user so that the agent token is tied to user consent | App calls `POST /api/v1/consent/init` with `agent_id`, `requested_tools[]`, `ttl_seconds`, `redirect_uri` — receives `flow_id` and `consent_url` |
| 2 | | App redirects user to `consent_url` (e.g. `https://auth.authstar.dev/consent/:flow_id`) |
| 3 | An end user needs to see what an AI agent is requesting permission to do so that they can make an informed decision | Consent screen shows: agent name, model identity (e.g. "Claude 3.5 Sonnet"), list of requested tools with plain-English descriptions, resources the agent can access, and how long the permission lasts |
| 4 | | Plain-English tool descriptions shown alongside tool names (e.g. `send_email` → "Send emails on your behalf") — tenant-configurable |
| 5 | | TTL shown as human-readable duration (e.g. "1 hour", "until you revoke it") — not a raw timestamp |
| 6 | An end user needs to grant or deny the consent request so that they control what the agent can do | **Grant** button issues the agent JWT and redirects to `redirect_uri?code=<agent_jwt>&flow_id=<id>` |
| 7 | | **Deny** button records a DENY in `eiaa_executions` and redirects to `redirect_uri?error=consent_denied&flow_id=<id>` |
| 8 | | Grant and Deny both require the user to be authenticated — unauthenticated users are redirected to sign-in first, then returned to the consent screen |
| 9 | A developer needs to exchange the consent code for an agent JWT so that their application can use it for `authorize()` calls | App calls `POST /api/v1/consent/exchange` with `code` and `flow_id` — receives `{ agent_jwt, expires_at, allowed_tools }` |
| 10 | | `agent_jwt` is the fully-signed AuthStar JWT with `delegation_chain = [user_id]` — ready to use with `authorize()` |
| 11 | An end user needs to see and revoke their active agent delegations so that they remain in control | User profile page → **Delegations** tab shows all active delegations: agent name, tools, granted at, expires at, **Revoke** button |
| 12 | | Revoke is immediate — agent JWT invalidated within 100ms; next `authorize()` call for that agent returns `DENY` with `ERR_REVOKED_DELEGATION` |
| 13 | | Revoked delegations remain visible in a "Revoked" history section (not deleted) — shows who revoked and when |
| 14 | A developer needs to brand the consent screen so that it matches their product's look and feel | Consent screen uses tenant's logo and primary colour from existing branding settings (set in Admin → Branding) |
| 15 | | If no branding is configured, AuthStar default branding is used — consent screen still renders correctly |
| 16 | A compliance lead needs to prove that a specific agent action was user-authorized so that they can satisfy an enterprise security review | Audit trail for any agent action that used a delegated token shows the `consent_record_id` linking to the original consent grant event |
| 17 | | `GET /api/v1/audit/consent/:consent_record_id` returns the full consent event: user ID, agent ID, tools granted, TTL, grant timestamp, and the attestation from the capsule execution |

---

## 6. Open Questions & Considerations

**Questions:**
- [ ] Should the consent screen support "partial grant" — user can deselect individual tools from the requested list? Recommendation: defer to R2.1 — partial grants add significant UX and policy complexity; R2 ships full-grant or full-deny only.
- [ ] Should the consent JWT be returned directly in the redirect (implicit flow) or via a code exchange (auth code flow)? Recommendation: code exchange — the agent JWT must never appear in browser history or server logs from the redirect URI.
- [ ] Should consent TTL be set by the application or the user? Recommendation: application sets the maximum TTL; user can optionally shorten it on the consent screen (e.g. "Grant for: 1 hour / 8 hours / until I revoke it").

**Considerations:**
- The consent record being an `eiaa_executions` row is architecturally elegant — it means consent itself is a capsule execution with full attestation. This is the link that makes AuthStar's compliance story watertight: not just "the agent was authorized for this action" but "the user consented to this delegation at this moment, under this policy."
- The Delegations tab on the user profile page must be discoverable. Consider adding a "Your active AI agent permissions" notification on the user dashboard when active delegations exist — not just buried in settings.
- Mobile-responsiveness is required because enterprise users often approve agent access during a workflow on a mobile device.

---

## Next Steps

1. Kick off with engineering — confirm `POST /api/v1/consent/init` and `POST /api/v1/consent/exchange` endpoint design
2. Design consent screen UI (single page — agent identity + tool list + grant/deny)
3. Design Delegations tab on user profile page
4. Confirm `eiaa_executions` schema handles `action = "user:delegate_to_agent"` without migration (check current JSONB flexibility)
5. Usability test consent screen with 3 non-technical users — gate: 100% grant-or-deny completion without confusion

---

## Resources

- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products Epics](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts/epics)
- [PR-FAQ — AuthStar](prfaq-authstar.md)
- Agent routes — [`backend/crates/api_server/src/routes/agents.rs`](../../backend/crates/api_server/src/routes/agents.rs)
- EIAA auth middleware — [`backend/crates/api_server/src/middleware/eiaa_authz.rs`](../../backend/crates/api_server/src/middleware/eiaa_authz.rs)
