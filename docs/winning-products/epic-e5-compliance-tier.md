# Epic E5 — Compliance Tier

> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R2 · **Priority:** P1
> **Depends on:** E1 (tenants), E2 (policy versioning), E4 (consent records in audit chain)
> **NSM contribution:** Revenue + retention — Compliance tier is the primary monetisation event for Persona 2
> **Status:** Ready for development — user stories drafted
> **User Stories:** [user-stories-e5-compliance-tier.md](user-stories-e5-compliance-tier.md)

---

## 1. Problem Statement

AuthStar's tamper-evident audit trail and re-executable attestation are the product's core differentiator — the thing no other authorization platform offers. But today, this capability is invisible: there is no UI to export it, no endpoint to verify it externally, no report a security team can hand to an auditor, and no tier distinction that signals "this tenant takes compliance seriously."

A Security/Compliance Lead at an AI company facing an enterprise security review needs to be able to:
1. Export the complete authorization record for any agent session as a verifiable artefact
2. Hand it to their customer's security team, who can verify it independently without an AuthStar account
3. Generate a SOC 2 / EU AI Act evidence summary on demand for any date range
4. Point to a compliance badge that answers the security questionnaire question: *"What authorization controls do you have over your AI agents?"*

Without this, AuthStar is a developer tool. With it, it is a compliance platform — and Persona 2's $2–10K/month purchase trigger is unlocked.

---

## 2. Product Outcomes & Instrumentation

| Phase | Product Outcome | Metric |
|-------|----------------|--------|
| R2 Launch | First Compliance-tier customer active within 30 days of R2 | `compliance_tier_upgraded` event |
| R2 Launch | > 80% of Compliance-tier tenants export a task chain within their first week | `task_chain_exported` event in first 7 days |
| R2 Launch | `POST /api/v1/audit/verify` successfully verifies ≥ 99% of exported records | Verification success rate (monitors attestation integrity) |
| 60 days post-R2 | > 30% of Production-tier tenants upgrade to Compliance after first enterprise security review | `compliance_tier_upgraded` event rate among Production tenants with ≥ 1 enterprise deal |

---

## 3. Assumptions

- Compliance tier is a **paid add-on** on top of the Production tier — not a separate plan. Billing uses existing Stripe integration.
- The re-execution endpoint (`POST /api/v1/audit/verify`) is **publicly accessible** with the exported record as the only input — no AuthStar account required to verify an exported record. This is intentional: the value proposition to Persona 2's enterprise customer is "you can verify this yourself."
- SOC 2 report is a **structured PDF or JSON export** — not a live dashboard. It is generated on demand for any 30-day window.
- Policy version history is already partially implemented (every `eiaa_capsules` row is versioned) — this epic adds the UI to surface it and the API to query it for a given date range.
- The compliance badge is a **verifiable claim** — a URL that returns `{ tenant_id, compliance_tier: true, eiaa_certified: true, last_verified: <timestamp> }` — so that tenants can include it in their security questionnaire responses as a live check.
- Data retention: `eiaa_executions` records are retained for 7 years for Compliance-tier tenants (configurable by tenant in admin settings); default for free/Production tier is 90 days.

---

## 4. Non-Functional Requirements

- Task chain export generates in ≤ 30 seconds for chains up to 10,000 decisions
- `POST /api/v1/audit/verify` responds in ≤ 2 seconds per decision (single decision verification); batch verification (up to 1,000 decisions) responds in ≤ 30 seconds
- Export file is signed with the tenant's Ed25519 key — tamper-evident; any modification invalidates the signature
- SOC 2 report PDF generated in ≤ 60 seconds for any 30-day window
- Compliance tier features are gated by `EntitlementService` — a non-Compliance tenant calling `POST /api/v1/audit/export` receives `402 ERR_COMPLIANCE_TIER_REQUIRED`
- All Compliance tier API routes protected by `EiaaAuthzLayer` with `audit:verify` or `audit:read` actions (already defined in AGENTS.md action list)
- 7-year data retention enforced by disabling the `cleanup_expired_records()` PL/pgSQL job for `eiaa_executions` on Compliance-tier tenants

---

## 5. User Requirements

| # | User Story | User Requirement |
|---|-----------|-----------------|
| 1 | A Security/Compliance Lead needs to export the complete authorization record for an agent session so that they can hand it to an enterprise security team | `GET /api/v1/audit/task/:task_id/export` returns a signed JSON file containing all decisions in the task chain |
| 2 | | Export file contains per-decision: `agent_id`, `user_id`, `tool`, `resource`, `args_hash`, `policy_version`, `allowed`, `attestation` (Ed25519 signature), `timestamp` |
| 3 | | Export file includes a `file_signature` field — Ed25519 signature of the entire file contents using the tenant's key — verifiable without an AuthStar account |
| 4 | | Admin console → Audit → Task Chain view has an **Export** button that triggers the download |
| 5 | An enterprise security team needs to verify an exported record without creating an AuthStar account so that they can independently validate the compliance claim | `POST /api/v1/audit/verify` accepts the exported JSON file (no auth header required) and returns per-decision: `valid: true/false`, `decision_hash_matches: true/false`, `attestation_valid: true/false`, `policy_version_archived: true/false` |
| 6 | | If any decision fails verification, the response identifies the exact decision and the reason for failure |
| 7 | | Verification endpoint is rate-limited to 60 requests/minute per IP (unauthenticated public endpoint) |
| 8 | A Security/Compliance Lead needs to generate a SOC 2 / EU AI Act evidence report so that they can respond to an audit or compliance questionnaire | Admin console → Compliance → **Generate Report** button — select date range (up to 30 days), select report type (SOC 2 / EU AI Act / General), click Generate |
| 9 | | Report generated as a PDF within 60 seconds — downloadable, printable, contains: tenant name, date range, total authorizations, total denials, agents active, policies deployed in period, sample of ALLOW and DENY decisions with attestations |
| 10 | | Report includes a **verification URL** that an auditor can visit to confirm the report was generated by AuthStar for this tenant on this date |
| 11 | A Security/Compliance Lead needs to view the full policy version history for any date range so that they can show which policy was active when a given action was authorized | Admin console → Policies → **History** tab — filterable by agent, date range; shows every version deployed, by whom, and when |
| 12 | | Clicking a version shows the full AST in plain-English format (reuses E2 US-05 plain-English summary) |
| 13 | | "Which policy was active on [date]?" query: `GET /api/v1/policies/:agent_id/active-at?timestamp=<ISO8601>` returns the exact capsule version active at that moment |
| 14 | A Security/Compliance Lead needs to show their enterprise customer a verifiable compliance status so that they can answer security questionnaire questions without a lengthy written response | Compliance badge URL: `GET /api/v1/compliance/badge/:tenant_slug` returns `{ tenant_id, compliance_tier: true, eiaa_certified: true, last_audit_export: <timestamp>, last_verified: <timestamp> }` — publicly accessible, no auth required |
| 15 | | Badge URL can be embedded in a security questionnaire response: "AuthStar compliance status: https://api.authstar.dev/compliance/badge/acme-corp" |
| 16 | | Badge returns `eiaa_certified: false` if the tenant's Compliance tier subscription is lapsed — so the badge is live and cannot be screenshot-spoofed |
| 17 | A Compliance-tier tenant admin needs to configure data retention so that they can meet their regulatory requirements | Admin console → Settings → **Data Retention** panel shows: current retention policy (default 7 years for Compliance tier), option to set a custom retention period (7–10 years), option to apply a legal hold on a specific task chain (prevents deletion regardless of retention policy) |
| 18 | | Retention setting change is logged in the admin audit trail with the admin's user ID and timestamp |
| 19 | A developer needs to know which tier is required for a feature before they hit a paywall so that they can plan their upgrade | All Compliance-tier-only API endpoints return `402` with `{ "error": { "code": "ERR_COMPLIANCE_TIER_REQUIRED", "message": "This feature requires the Compliance tier. Upgrade at Settings → Billing.", "upgrade_url": "https://app.authstar.dev/admin/billing/upgrade" } }` |

---

## 6. Open Questions & Considerations

**Questions:**
- [ ] Should the SOC 2 report use a specific framework mapping (CC6.1, CC6.3, etc.) or be a generic authorization evidence report for R2? Recommendation: generic for R2; add SOC 2 framework mapping and EU AI Act Article 9 mapping as a separate story in R2.1.
- [ ] Should `POST /api/v1/audit/verify` be completely unauthenticated, or require a tenant-issued verification key? Recommendation: completely unauthenticated — the value proposition is that the enterprise customer can verify independently. A verification key would require them to get credentials from the AI company, defeating the purpose.
- [ ] Should the compliance badge be a static JSON response or a signed JWT that the recipient can verify offline? Recommendation: signed JWT for R2.1; plain JSON for R2 (simpler, still live and unforgeable by the tenant since it comes from AuthStar's servers).

**Considerations:**
- The verification endpoint being public and unauthenticated is the product's boldest architectural claim — "we trust the math." Ensure the Ed25519 verification logic is independently auditable (open-source the verification library or publish the algorithm spec).
- The SOC 2 report is the single most valuable PDF AuthStar will ever generate. It will be attached to enterprise deals worth $200K+. Invest in its design, not just its content.
- The compliance badge is a PLG acquisition tool in reverse — the AI company's enterprise customers will Google "AuthStar compliance" and find the badge documentation. This is inbound marketing built into the product architecture.

---

## Next Steps

1. Kick off with engineering — confirm `POST /api/v1/audit/verify` verification algorithm and Ed25519 key management for tenant-signed exports
2. Design SOC 2 report PDF template (content-first; typography second)
3. Confirm `EntitlementService` can gate Compliance tier features without schema changes
4. Confirm `cleanup_expired_records()` PL/pgSQL function can be disabled per-tenant without a migration
5. Usability test export + verify flow with a simulated enterprise security review: Compliance Lead exports, hands file to a colleague who verifies it cold — gate: verification completes without assistance

---

## Resources

- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products Epics](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts/epics)
- [OpA — AI Agent AuthZ](opa-ai-agent-authz.md) — Ceadly pricing validation for compliance tier
- [PR-FAQ — AuthStar](prfaq-authstar.md)
- Audit writer — [`backend/crates/api_server/src/services/audit_writer.rs`](../../backend/crates/api_server/src/services/audit_writer.rs)
- Attestation verifier — [`backend/crates/api_server/src/services/attestation_verifier.rs`](../../backend/crates/api_server/src/services/attestation_verifier.rs)
- Entitlement service — [`backend/crates/billing_engine/`](../../backend/crates/billing_engine/)
