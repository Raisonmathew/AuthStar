# User Stories — E5: Compliance Tier

> **Epic:** [E5 — Compliance Tier](epic-e5-compliance-tier.md)
> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R2 · **Priority:** P1
> **Stories:** 6 · ordered by business impact
> **Depends on:** E1 (tenants), E2 (policy versioning), E4 US-05 (consent records in chain)

---

## Story Map

```
US-01  Task chain export (the core compliance artefact)
  └── US-02  External verification endpoint (enterprise customer verifies independently)
US-03  SOC 2 / EU AI Act report generation                ← parallel to US-01/02
US-04  Policy version history API + "active at" query     ← parallel
US-05  Compliance badge (public verifiable status URL)    ← parallel
US-06  Compliance tier gating + upgrade prompt            ← prerequisite for all others
```

Ship US-06 first — it gates access to all other features and enables Stripe billing for the tier.

---

## US-06 — Compliance Tier Gating & Upgrade Prompt

**As a** Production-tier tenant admin,
**I want to** see Compliance tier features clearly labelled and be prompted to upgrade when I try to use them,
**so that** I know what I'm missing and can upgrade without filing a support ticket.

### Acceptance Criteria

- [ ] All Compliance-tier API endpoints return `402` with structured error when called by a non-Compliance tenant:
  ```json
  {
    "error": {
      "code": "ERR_COMPLIANCE_TIER_REQUIRED",
      "message": "This feature requires the Compliance tier.",
      "upgrade_url": "https://app.authstar.dev/admin/billing/upgrade"
    }
  }
  ```
- [ ] Admin console → **Compliance** section (new left-nav item) is visible to all tenants — but features are locked behind a "Upgrade to Compliance" gate UI when on free/Production tier
- [ ] Locked features show a 🔒 icon and an inline **Upgrade** CTA: "Unlock task chain exports, SOC 2 reports, and the compliance badge"
- [ ] Admin console → Settings → **Billing** page has a **Compliance tier** card: description, price, and **Upgrade** button that initiates a Stripe checkout session
- [ ] On successful Stripe upgrade, `EntitlementService` updates the tenant's plan tier to `compliance` — all locked features unlock immediately without page reload
- [ ] `compliance_tier_upgraded` instrumentation event fires with `tenant_id`, `previous_tier`, `timestamp`
- [ ] Data retention for `eiaa_executions` automatically extends to 7 years on upgrade — `cleanup_expired_records()` PL/pgSQL job skips Compliance-tier tenants

### Technical Notes

- `EntitlementService` already supports plan tier detection — add `compliance` as a new tier above `production`
- `cleanup_expired_records()` function: add a check `WHERE tenant_id NOT IN (SELECT tenant_id FROM organizations WHERE plan_tier = 'compliance')` — no structural migration needed
- Stripe checkout: use existing `StripeService.create_checkout_session()` with a new `compliance` price ID
- Billing page upgrade flow: existing Stripe integration handles payment; webhook updates `plan_tier` on `checkout.session.completed` event

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: Production-tier tenant calls `GET /api/v1/audit/task/:id/export` → `402 ERR_COMPLIANCE_TIER_REQUIRED`
- [ ] Integration test: upgrade via Stripe webhook → `plan_tier = compliance` → same endpoint returns 200
- [ ] Locked feature UI renders with 🔒 icon and Upgrade CTA for all 5 Compliance features
- [ ] `compliance_tier_upgraded` event fires and is verifiable

---

## US-01 — Task Chain Export

**As a** Security/Compliance Lead,
**I want to** export the complete, cryptographically signed authorization record for any agent task chain,
**so that** I can hand a single file to an enterprise security team that proves every action the agent took was pre-authorized.

### Acceptance Criteria

- [ ] `GET /api/v1/audit/task/:task_id/export` returns a JSON file download (Content-Disposition: attachment)
- [ ] Export file structure:
  ```json
  {
    "authstar_export_version": "1.0",
    "tenant_id": "acme-corp",
    "task_id": "task_xxx",
    "exported_at": "2026-03-06T12:00:00Z",
    "exported_by": "usr_admin123",
    "decisions": [
      {
        "decision_id": "dec_xxx",
        "agent_id": "agt_xxx",
        "user_id": "usr_xxx",
        "tool": "send_email",
        "resource": "inbox:customer@acme.com",
        "args_hash": "sha256:ab12cd...",
        "policy_version": 3,
        "allowed": true,
        "attestation": "<ed25519_signature>",
        "timestamp": "2026-03-06T11:58:00Z",
        "parent_decision_id": "dec_yyy"
      }
    ],
    "consent_record": { ... },
    "file_signature": "<ed25519_signature_of_entire_file>"
  }
  ```
- [ ] `file_signature` is Ed25519 signature of `SHA-256(canonical_json(decisions + metadata))` using the tenant's signing key
- [ ] Export generates in ≤ 30 seconds for task chains up to 10,000 decisions
- [ ] Admin console → Audit → Task Chain view has an **Export** button for any task chain
- [ ] Export button shows a loading indicator while generating; download starts automatically on completion
- [ ] Endpoint is Compliance-tier gated — non-Compliance tenants receive `402` (US-06)
- [ ] `task_chain_exported` instrumentation event fires with `tenant_id`, `task_id`, `decision_count`, `export_size_bytes`

### Technical Notes

- Canonical JSON: use `BTreeMap`-ordered serialization (same pattern as existing capsule signing in `CapsuleCompiler`)
- Tenant signing key: Ed25519 keypair stored in `tenant_signing_keys` table (new migration `081_tenant_signing_keys.sql`) — one keypair per tenant, generated on Compliance tier upgrade
- For large exports (> 1,000 decisions): stream the response rather than buffering in memory; use `axum::body::Body` streaming
- `args_hash` is already stored in `eiaa_executions.tool_args_hash` — no new computation needed

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: export a task chain with 10 decisions → verify file structure, `file_signature` validates against tenant key
- [ ] Performance test: task chain with 10,000 decisions exports in ≤ 30 seconds
- [ ] Export button in admin UI works end-to-end — file downloads with correct filename `authstar-export-{task_id}-{date}.json`
- [ ] Migration `081_tenant_signing_keys.sql` applied forward-only

---

## US-02 — External Verification Endpoint

**As an** enterprise security team member,
**I want to** verify an exported AuthStar task chain without creating an AuthStar account,
**so that** I can independently confirm that every agent action in the export was cryptographically authorized.

### Acceptance Criteria

- [ ] `POST /api/v1/audit/verify` accepts the export JSON file as the request body — **no authentication required**
- [ ] Response per decision: `{ decision_id, valid: bool, checks: { file_signature_valid, decision_hash_valid, attestation_valid, policy_version_archived } }`
- [ ] `file_signature_valid`: verifies the `file_signature` against the tenant's public key (looked up by `tenant_id` from the file — public keys are public)
- [ ] `decision_hash_valid`: re-computes `SHA-256(canonical_json(decision))` and compares to `attestation` preimage
- [ ] `attestation_valid`: verifies the Ed25519 signature in `attestation` against the EIAA runtime's public key
- [ ] `policy_version_archived`: confirms the policy version referenced in the decision is still in `eiaa_capsules` (not deleted)
- [ ] If all checks pass for all decisions: `{ "result": "VALID", "decisions_verified": N, "decisions": [...] }`
- [ ] If any decision fails: `{ "result": "INVALID", "first_failure": { decision_id, failed_check, reason }, "decisions": [...] }`
- [ ] Rate limited: 60 requests/minute per IP (public endpoint, no auth)
- [ ] Endpoint responds in ≤ 2 seconds for up to 100 decisions; ≤ 30 seconds for up to 1,000 decisions

### Technical Notes

- Unauthenticated endpoint: add to router without `EiaaAuthzLayer` (intentional — public verification is the value proposition)
- Tenant public key lookup: `GET /api/v1/.well-known/tenant-keys/:tenant_id` — new public endpoint returning the tenant's Ed25519 public key in JWK format
- The verification logic re-uses `AttestationVerifier` — no new cryptographic code; just a new endpoint calling existing services
- Rate limiting: use existing Redis sliding window pattern from `rate_limit_auth_flow` middleware

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: export a real task chain → verify with `POST /api/v1/audit/verify` → `result: VALID`
- [ ] Integration test: tamper with one decision in the export JSON → verify → `result: INVALID` with `first_failure` identifying the tampered decision
- [ ] Rate limit test: 61 requests from same IP in 1 minute → 61st returns `429`
- [ ] Performance: 1,000-decision verification completes in ≤ 30 seconds

---

## US-03 — SOC 2 / EU AI Act Evidence Report

**As a** Security/Compliance Lead,
**I want to** generate a compliance evidence report for any 30-day window on demand,
**so that** I can respond to a SOC 2 audit or EU AI Act review without manually assembling log evidence.

### Acceptance Criteria

- [ ] Admin console → Compliance → **Generate Report** page: date range picker (up to 30 days), report type selector (SOC 2 Type II Evidence / EU AI Act Article 9 / General Authorization Evidence)
- [ ] **Generate** button triggers report generation; progress indicator shown; download starts automatically on completion (≤ 60 seconds)
- [ ] Report PDF contains:
  - Cover page: tenant name, date range, report type, generated at timestamp, AuthStar logo
  - Summary table: total authorizations, total denials, denial rate, unique agents active, policies deployed in period
  - Policy change log: every policy deployed in the period — agent, version, deployed by, deployed at, plain-English summary
  - Sample evidence: 10 ALLOW decisions and 10 DENY decisions with full decision fields (decision_id, agent, tool, resource, policy version, timestamp, attestation prefix)
  - Verification instructions: "To verify any decision in this report independently, visit `POST /api/v1/audit/verify`"
  - Verification URL: `https://api.authstar.dev/compliance/report-verification/:report_id` — returns `{ generated_by: "authstar", tenant_id, generated_at, record_count }` confirming the report is authentic
- [ ] Report is Compliance-tier gated (US-06)
- [ ] `compliance_report_generated` instrumentation event fires with `tenant_id`, `report_type`, `date_range_days`, `decision_count`

### Technical Notes

- PDF generation: use a Rust PDF library (`printpdf` or equivalent) or generate structured HTML → print-to-PDF via headless Chromium in a Docker sidecar — TBD with engineering; HTML approach is faster to implement
- `report_id` stored in `compliance_reports` table (new migration `082_compliance_reports.sql`): `id`, `tenant_id`, `report_type`, `date_range_start`, `date_range_end`, `generated_at`, `generated_by`, `decision_count`
- Verification URL endpoint: `GET /api/v1/compliance/report-verification/:report_id` — unauthenticated; returns report metadata only (no decision data)

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: generate a SOC 2 report for a 30-day window → PDF downloads, contains all required sections
- [ ] PDF renders correctly in PDF viewer — no broken layout, no missing fields
- [ ] Verification URL returns correct metadata for a generated report
- [ ] Report generation completes in ≤ 60 seconds for a 30-day window with up to 100,000 decisions

---

## US-04 — Policy Version History API & "Active At" Query

**As a** Security/Compliance Lead,
**I want to** query which policy was active for an agent at any point in time,
**so that** I can definitively answer "was the agent's policy the same when this action happened as it is today?"

### Acceptance Criteria

- [ ] `GET /api/v1/policies/:agent_id/versions` returns paginated list of all deployed versions: `{ version, deployed_at, deployed_by, ast_summary, wasm_hash, is_current }`
- [ ] `GET /api/v1/policies/:agent_id/active-at?timestamp=<ISO8601>` returns the exact capsule version active at the specified timestamp: `{ version, deployed_at, deployed_by, ast_summary, wasm_hash, ast_bytes }`
- [ ] If no custom policy was deployed before the specified timestamp, returns `{ "default_policy": true, "message": "No custom policy was deployed before this timestamp — default allow-all policy was in effect" }`
- [ ] Admin console → Policies → **History** tab (reuses E2 US-05 UI) — adds a date-range filter to narrow the version list
- [ ] History tab has a "Policy active at…" date picker: enter a date/time → highlights the version that was active and shows a banner: "This policy (v3) was active from March 1 to March 5"
- [ ] Endpoint is available to all authenticated tenants (not Compliance-gated) — policy history is a base feature; Compliance tier adds the `active-at` query and the audit report integration

### Technical Notes

- `GET /api/v1/policies/:agent_id/versions`: query `eiaa_capsules` ordered by `created_at DESC` where `tenant_id` and `action` match the agent's action string — already stored in the table
- `active-at` query: `SELECT * FROM eiaa_capsules WHERE tenant_id = $1 AND action = $2 AND created_at <= $3 ORDER BY created_at DESC LIMIT 1`
- `ast_summary` generation: reuse the plain-English summary from E2 US-05 — already implemented

### Definition of Done

- [ ] Code complete and reviewed
- [ ] `GET /api/v1/policies/:agent_id/versions` returns paginated results with correct `is_current` flag
- [ ] `GET /api/v1/policies/:agent_id/active-at?timestamp=...` returns correct version for 3 test timestamps: before first deploy, between two deploys, after latest deploy
- [ ] "No custom policy" case returns correct response
- [ ] Admin UI "Policy active at…" date picker highlights correct version

---

## US-05 — Compliance Badge

**As a** Security/Compliance Lead,
**I want to** include a live, verifiable compliance status URL in our security questionnaire responses,
**so that** our enterprise customers can confirm our authorization controls are active without asking us to produce documentation every quarter.

### Acceptance Criteria

- [ ] `GET /api/v1/compliance/badge/:tenant_slug` returns JSON (no auth required):
  ```json
  {
    "tenant_id": "acme-corp",
    "compliance_tier": true,
    "eiaa_certified": true,
    "last_audit_export": "2026-03-01T09:00:00Z",
    "last_verified": "2026-03-06T12:00:00Z",
    "verification_url": "https://api.authstar.dev/compliance/badge/acme-corp"
  }
  ```
- [ ] `compliance_tier: false` and `eiaa_certified: false` returned if the tenant's Compliance subscription is lapsed or cancelled — badge cannot be screenshot-spoofed
- [ ] `last_audit_export` is the timestamp of the most recent task chain export — shows the badge is actively used, not just purchased
- [ ] Response includes `Cache-Control: max-age=300` — badge is live but not hammered on every security questionnaire page load
- [ ] An embeddable HTML snippet is documented: `<a href="https://api.authstar.dev/compliance/badge/acme-corp">Verify AuthStar compliance</a>` — tenant can add this to their security documentation
- [ ] Endpoint is rate limited: 120 requests/minute per IP

### Technical Notes

- New unauthenticated route: `GET /api/v1/compliance/badge/:tenant_slug`
- Looks up `organizations` by `slug` → checks `plan_tier = 'compliance'` → queries most recent `task_chain_exported` event timestamp
- `last_verified` is updated every time the badge is queried (write to `organizations.compliance_badge_last_checked_at`) — indicates the badge is being actively referenced

### Definition of Done

- [ ] Code complete and reviewed
- [ ] Integration test: Compliance-tier tenant → badge returns `eiaa_certified: true`
- [ ] Integration test: downgraded tenant → badge returns `eiaa_certified: false` within 5 minutes
- [ ] `last_audit_export` reflects most recent export timestamp
- [ ] Rate limit test: 121 requests/minute → 121st returns `429`
- [ ] HTML embed snippet documented on docs site

---

## Sprint Ordering Recommendation

| Sprint | Stories | Rationale |
|--------|---------|-----------|
| Sprint 1 | **US-06** Compliance tier gating + upgrade | Must ship first — gates all other features and enables billing |
| Sprint 2 | **US-01** Task chain export | Core compliance artefact; unlocks US-02 |
| Sprint 3 | **US-02** External verification | Highest enterprise trust signal; depends on US-01 |
| Sprint 4 | **US-03** SOC 2 report + **US-04** Policy history API | Parallel — both are read-only outputs from existing data |
| Sprint 5 | **US-05** Compliance badge | Polish; highest GTM value once US-01–04 are live |

**E5 launch gate:** US-06 → US-01 → US-02 end-to-end: a Compliance-tier tenant exports a task chain and an external colleague verifies it without an AuthStar account. First Compliance-tier paying customer active.

---

## Resources

- [Epic E5 — Compliance Tier](epic-e5-compliance-tier.md)
- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products User Stories](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- Audit writer — [`backend/crates/api_server/src/services/audit_writer.rs`](../../backend/crates/api_server/src/services/audit_writer.rs)
- Attestation verifier — [`backend/crates/api_server/src/services/attestation_verifier.rs`](../../backend/crates/api_server/src/services/attestation_verifier.rs)
- Entitlement service — [`backend/crates/billing_engine/`](../../backend/crates/billing_engine/)
