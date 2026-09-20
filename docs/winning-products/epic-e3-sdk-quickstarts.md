# Epic E3 — SDK Quickstarts & Framework Guides

> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P1 · **Depends on:** E1 (tenant + API key must exist)
> **NSM contribution:** Activation speed — reduces time-to-first-authorize for every future signup
> **Status:** Ready for development — user stories drafted
> **User Stories:** [user-stories-e3-sdk-quickstarts.md](user-stories-e3-sdk-quickstarts.md)

---

## 1. Problem Statement

AuthStar has functional Python and TypeScript SDKs, but no quickstart guide that takes a developer from zero to a working `authorize()` call in under 15 minutes. The SDK READMEs describe the API but not the journey. Developers who hit friction in the first 15 minutes — a missing import, an unclear configuration step, a confusing error message — abandon and do not return.

Every developer who installs an AuthStar SDK must be able to reach their first successful `authorize()` call, their first `deny`, their first policy edit, and their first audit query without assistance — all in under 15 minutes.

---

## 2. Product Outcomes & Instrumentation

| Phase | Product Outcome | Metric |
|-------|----------------|--------|
| R1 Launch | Median time-to-first-authorize < 15 minutes across all signups | Time delta: `tenant_created` → `first_authorize_success` (from E1 instrumentation) |
| R1 Launch | > 70% of developers who install the SDK reach `first_authorize_success` within 7 days | SDK install event → `first_authorize_success` conversion rate |
| R1 Launch | < 5% of developers contact support for a problem covered by a quickstart | Support ticket categorization |
| 30 days post-launch | AuthStar mentioned in at least one LangChain, CrewAI, or OpenAI Agents SDK community thread as a recommended AuthZ integration | Qualitative — community monitoring |

---

## 3. Assumptions

- Quickstarts are **code-first** — developers read by running, not by reading prose. Every quickstart opens with an installable, runnable code block.
- Python and TypeScript quickstarts ship in R1. Go quickstart ships in R2 alongside the Go `AgentAuthzClient` implementation.
- Framework guides cover LangChain, CrewAI, and OpenAI Agents SDK in R1 — these are the three frameworks with the largest developer communities among the target persona.
- `authstar doctor` CLI command is part of this epic — it is the self-service diagnostic tool that replaces "file a support ticket because my first call failed."
- Quickstarts are hosted on `docs.authstar.dev` (or equivalent) — not in the GitHub README — so they can be updated without a release.
- The Get Started wizard in E1 generates a pre-filled code snippet; this epic builds the full narrative quickstart that the wizard links to for deeper reading.
- All quickstart code snippets are tested in CI — a broken example is a P0 bug.

---

## 4. Non-Functional Requirements

- All quickstart code examples must be CI-tested against the live SDK on every PR — broken examples fail the build
- `authstar doctor` must run without any AuthStar account (connectivity and version checks) and with an account (tenant config validation, API key validity, agent registration check)
- `authstar doctor` output must be human-readable and actionable — every failure must include a "Fix:" suggestion with a specific command or doc link
- Quickstart pages must load in < 2 seconds with no client-side JS required for reading (static site or server-rendered)
- Framework guides must be kept in sync with SDK versions — a version incompatibility must be flagged by CI within 24 hours of an SDK release

---

## 5. User Requirements

| # | User Story | User Requirement |
|---|-----------|-----------------|
| 1 | A Python developer needs to go from SDK install to first `authorize()` call so that they can evaluate AuthStar in their stack | Python quickstart: single page, < 500 words, opens with `pip install authstar-agent` |
| 2 | | Step 1: Install. Step 2: Configure (tenant ID + API key). Step 3: Register an agent. Step 4: Call `authorize()`. Step 5: Query the audit trail. Each step is a self-contained runnable block. |
| 3 | | Expected output shown for every code block — developer knows if they're on track without having to interpret raw JSON |
| 4 | A TypeScript developer needs to go from SDK install to first `authorize()` call so that they can evaluate AuthStar in their stack | TypeScript quickstart: same 5-step structure; ESM and CJS import examples shown; Deno alternative noted |
| 5 | | Type definitions shown for `AuthorizationDecision` — developers understand `decision.allowed`, `decision.attestation`, `decision.audit_id`, `decision.policy_version` without reading API docs |
| 6 | A developer using LangChain needs to integrate AuthStar into their agent tool calls so that every tool call is authorized before execution | LangChain guide: shows wrapping a `Tool` with an `authorize()` call as a decorator or middleware; < 30 lines of integration code |
| 7 | | Shows how to pass `delegation_chain` from the LangChain agent context to the `authorize()` call |
| 8 | | Shows how to query the task chain audit after a run: `client.get_task_chain(task_id)` |
| 9 | A developer using CrewAI needs to integrate AuthStar so that every agent action is authorized | CrewAI guide: shows wrapping a `BaseTool` with pre-execution authorization; same structure as LangChain guide |
| 10 | A developer using OpenAI Agents SDK needs to integrate AuthStar so that every tool call is authorized | OpenAI Agents SDK guide: shows using a function tool wrapper with `authorize()` called before the function body executes |
| 11 | A developer needs to diagnose why their first call failed so that they can fix it without filing a support ticket | `authstar doctor` command: `pip install authstar-agent && authstar doctor --tenant-id <id> --api-key <key>` |
| 12 | | Checks: network connectivity to AuthStar base URL; API key validity; tenant exists; at least one agent registered; SDK version is current |
| 13 | | Output format: ✅ / ❌ per check; for each ❌ a "Fix:" line with a specific command or doc URL |
| 14 | | Exits with code 0 if all checks pass; non-zero if any fail — usable in CI pipelines |
| 15 | A developer needs to understand how to handle `decision.allowed = false` gracefully so that their agent fails safely | Quickstart includes a "Handling denials" section: shows how to check `decision.allowed`, log `decision.audit_id`, and surface a user-friendly error without leaking policy internals |
| 16 | | Shows the difference between `DENY` (policy decision) and an exception (network error or misconfiguration) — both must be handled differently |
| 17 | A developer needs to iterate on their policy and verify the change works before deploying to production so that they don't break live agents | Quickstart includes a "Test a policy change" section: links to the Policy Builder UI (E2) and shows how to re-run the same `authorize()` call against a draft policy using the test console |
| 18 | A developer needs to find the audit record for a specific agent action so that they can verify what was authorized | Quickstart includes a "Query the audit trail" section: `client.get_task_chain(task_id)` in Python; `client.getTaskChain(taskId)` in TypeScript; shows the full response structure |

---

## 6. Open Questions & Considerations

**Questions:**
- [ ] Should framework guides be separate pages or sections within a single "Integrations" page? Recommendation: separate pages — easier to link from framework communities and keeps each guide focused.
- [ ] Should the `authstar doctor` command be bundled in the Python SDK or distributed as a separate `authstar-cli` package? Recommendation: bundled in the Python SDK for R1 (faster to ship); separate CLI package for R2 when Go and TypeScript CLIs are needed.
- [ ] Should CI test quickstarts against a live AuthStar test environment or a mocked API? Recommendation: live test environment with a dedicated CI tenant — mocks create false confidence that the example actually works end-to-end.

**Considerations:**
- The three framework guides (LangChain, CrewAI, OpenAI Agents SDK) are the primary PLG acquisition channels. When a developer searches "LangChain authorization" or "CrewAI tool permissions", these guides must appear. SEO and community posting are the distribution strategy.
- Every code example must be under 30 lines. If an integration requires more than 30 lines, the SDK abstraction is wrong — fix the SDK, not the guide.
- The `authstar doctor` command is the first line of support. Every failure it catches is a support ticket that doesn't get filed. Invest in the diagnostic output quality.

---

## Next Steps

1. ✅ User stories drafted — see [user-stories-e3-sdk-quickstarts.md](user-stories-e3-sdk-quickstarts.md)
2. **Start Sprint 1:** US-01 (Python quickstart) — validates the structure all other guides will reuse
3. Implement `authstar doctor` CLI (US-03) in Sprint 2 alongside TypeScript quickstart
4. Set up CI test job against live test environment before publishing US-01
5. Post framework guides to community channels within 2 weeks of R1 launch — distribution is part of the epic

---

## Resources

- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products Epics](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts/epics)
- Python SDK — [`sdks/python/idaas/agent.py`](../../sdks/python/idaas/agent.py)
- TypeScript Agent SDK — [`sdks/typescript/agent/src/client.ts`](../../sdks/typescript/agent/src/client.ts)
- Python SDK README — [`sdks/python/README.md`](../../sdks/python/README.md)
