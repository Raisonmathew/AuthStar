# User Stories — E3: SDK Quickstarts & Framework Guides

> **Epic:** [E3 — SDK Quickstarts & Framework Guides](epic-e3-sdk-quickstarts.md)
> **Master Epic:** [AuthStar GA Launch](master-epic-ga.md)
> **Release:** R1 · **Priority:** P1
> **Stories:** 6 · ordered by delivery value
> **Depends on:** E1 live (tenant + API key needed to test examples end-to-end)

---

## Story Map

```
US-01  Python quickstart (5-step, code-first)
US-02  TypeScript quickstart (mirrors Python)
US-03  authstar doctor CLI (diagnostic command)    ← these three are independent
US-04  LangChain integration guide
US-05  CrewAI integration guide
US-06  OpenAI Agents SDK integration guide
```

All 6 are parallelisable after E1 is live. US-01 ships first — it validates the quickstart structure before US-02 reuses it.

---

## US-01 — Python Quickstart

**As a** Python developer,
**I want to** follow a single page that takes me from `pip install` to a working `authorize()` call, a handled denial, and a queried audit record,
**so that** I can evaluate AuthStar in my own stack in under 15 minutes without reading API documentation.

### Acceptance Criteria

- [ ] Published at `docs.authstar.dev/quickstart/python` — static page, loads in < 2 seconds, no client-side JS required to read
- [ ] Page opens with the install command as the very first code block — no preamble prose before the first runnable line
- [ ] Page is structured in exactly 5 numbered steps, each with a runnable code block and the expected terminal output below it:

  **Step 1 — Install**
  ```bash
  pip install authstar-agent
  ```
  *Expected output:* `Successfully installed authstar-agent-x.x.x`

  **Step 2 — Configure**
  ```python
  from authstar import AgentAuthz

  authz = AgentAuthz(
      base_url="https://api.authstar.dev",
      tenant_id="YOUR_TENANT_ID",       # Settings → General
      api_key="YOUR_API_KEY",           # Settings → API Keys
      agent_id="YOUR_AGENT_ID",         # Agents → copy ID
  )
  ```
  *Expected output:* (no output — configuration only)

  **Step 3 — Register an agent** (if not already done in the wizard)
  ```python
  # Skip this step if you registered an agent during signup
  agent = authz.register_agent(
      name="my-first-agent",
      model_id="claude-3-5-sonnet-20241022",
      allowed_tools=["web_search", "send_email"],
  )
  print("agent_id:", agent.agent_id)
  ```
  *Expected output:* `agent_id: agt_xxxxxxxxxxxxxxxx`

  **Step 4 — Authorize a tool call**
  ```python
  decision = authz.authorize(
      tool="web_search",
      resource="https://example.com",
      args={"query": "authstar docs"},
  )
  print("allowed:", decision.allowed)
  print("audit_id:", decision.audit_id)

  if not decision.allowed:
      raise PermissionError(f"Agent denied: audit_id={decision.audit_id}")
  ```
  *Expected output:* `allowed: True` / `audit_id: dec_xxxxxxxxxxxxxxxx`

  **Step 5 — Query the audit trail**
  ```python
  chain = authz.get_task_chain(task_id=decision.audit_id)
  for entry in chain.entries:
      print(entry.tool, "→", "ALLOW" if entry.allowed else "DENY")
  ```
  *Expected output:* `web_search → ALLOW`

- [ ] A "Handling denials" callout box explains: check `decision.allowed` before executing the tool; log `decision.audit_id` for support; never expose `decision.attestation` in user-facing errors
- [ ] A "What's next" section at the bottom links to: Policy Builder UI, full SDK API reference, LangChain guide
- [ ] All 5 code blocks are CI-tested against the live test environment on every PR — a broken block fails the build

### Technical Notes

- CI test job: creates a temporary tenant with a test API key, runs each code block sequentially, asserts expected output patterns, tears down the tenant after the run
- `YOUR_TENANT_ID` / `YOUR_API_KEY` / `YOUR_AGENT_ID` placeholders must be clearly distinguished from real values — use a different colour or a `# replace this` comment
- Page hosted as static Markdown rendered to HTML — no CMS required for R1

### Definition of Done

- [ ] Page published and accessible
- [ ] CI job runs all 5 code blocks against live test env on every PR — passing on merge
- [ ] Manual cold-start test with 1 engineer who hasn't seen AuthStar: < 15 minutes to Step 5 output
- [ ] "Handling denials" callout present and accurate

---

## US-02 — TypeScript Quickstart

**As a** TypeScript developer,
**I want to** follow the same 5-step structure as the Python quickstart but using `@authstar/agent`,
**so that** I can integrate AuthStar into my TypeScript or Node.js agent stack in under 15 minutes.

### Acceptance Criteria

- [ ] Published at `docs.authstar.dev/quickstart/typescript`
- [ ] Identical 5-step structure to US-01 — same steps, TypeScript syntax
- [ ] Step 1 shows both npm and yarn install: `npm install @authstar/agent` / `yarn add @authstar/agent`
- [ ] Step 2 shows ESM import (`import { AgentAuthz } from '@authstar/agent'`) as primary; CJS (`require`) shown in a collapsed "CommonJS" tab; Deno noted in a one-line callout
- [ ] Step 4 `authorize()` call uses `async/await` — `const decision = await authz.authorize(...)`
- [ ] Type annotation shown for `AuthorizationDecision` with all four fields documented inline: `allowed: boolean`, `attestation: string`, `audit_id: string`, `policy_version: string`
- [ ] All code blocks CI-tested — same test job as US-01 but targeting the TypeScript SDK

### Technical Notes

- Share the CI test infrastructure from US-01 — same temporary tenant; different language runner (`ts-node` or `tsx`)
- ESM/CJS toggle: use a `<Tabs>` component if the docs platform supports it; otherwise show both sequentially with clear labels

### Definition of Done

- [ ] Page published and CI job passing
- [ ] Manual cold-start test with 1 TypeScript engineer: < 15 minutes to Step 5
- [ ] CJS and Deno examples verified manually

---

## US-03 — `authstar doctor` CLI

**As a** developer whose first `authorize()` call failed,
**I want to** run `authstar doctor` and get a checklist of what's wrong and how to fix each issue,
**so that** I can resolve connectivity and configuration problems without filing a support ticket.

### Acceptance Criteria

- [ ] `authstar doctor` is available after `pip install authstar-agent` — no separate install step
- [ ] Running `authstar doctor` with no arguments prints usage and runs connectivity-only checks (no credentials needed)
- [ ] Running `authstar doctor --tenant-id <id> --api-key <key>` runs the full diagnostic suite:

  | Check | What it tests | Pass output | Fail output + Fix |
  |-------|--------------|-------------|------------------|
  | Network | `GET https://api.authstar.dev/health` responds 200 | `✅ AuthStar API reachable` | `❌ Cannot reach api.authstar.dev — Fix: check firewall / VPN. Docs: docs.authstar.dev/errors/network` |
  | API key | Key authenticates | `✅ API key valid` | `❌ API key invalid or revoked — Fix: generate a new key at Settings → API Keys` |
  | Tenant | Tenant ID exists | `✅ Tenant found: acme-corp` | `❌ Tenant not found — Fix: check AUTHSTAR_TENANT_ID in your environment` |
  | Agent | ≥ 1 agent registered | `✅ 2 agents registered` | `❌ No agents registered — Fix: run authz.register_agent(...) or use the wizard` |
  | SDK version | Installed version ≥ latest stable | `✅ SDK up to date (v1.2.3)` | `⚠️ SDK outdated (v1.1.0, latest v1.2.3) — Fix: pip install --upgrade authstar-agent` |

- [ ] Output is coloured: ✅ green, ❌ red, ⚠️ yellow — plain text fallback when `NO_COLOR=1` or not a TTY
- [ ] Exits with code `0` if all checks pass; `1` if any ❌; `2` if any ⚠️ but no ❌
- [ ] Works in CI pipelines: `authstar doctor --tenant-id $ID --api-key $KEY && echo "AuthStar OK"`
- [ ] `--json` flag outputs machine-readable JSON: `{ "checks": [{ "name": "network", "status": "pass"|"fail"|"warn", "message": "...", "fix": "..." }] }`

### Technical Notes

- Implement as a `Click` CLI command in the Python SDK: `authstar/cli.py` → `@click.command('doctor')`
- Entry point in `pyproject.toml`: `[project.scripts] authstar = "authstar.cli:main"`
- SDK version check: `GET https://pypi.org/pypi/authstar-agent/json` → compare `info.version` to `importlib.metadata.version('authstar-agent')`
- API key check: `GET /api/v1/admin/me` with `Authorization: Bearer <api_key>` — returns 200 if valid, 401 if not

### Definition of Done

- [ ] Code complete and reviewed
- [ ] `authstar doctor` available after `pip install authstar-agent` — verified in a clean virtualenv
- [ ] All 5 checks run and produce correct pass/fail output against a live test environment
- [ ] Exit codes verified: `0` all pass, `1` on API key failure, `2` on SDK outdated
- [ ] `--json` flag output parses as valid JSON with correct schema
- [ ] CI pipeline usage verified: `authstar doctor ... && echo "OK"` works as expected

---

## US-04 — LangChain Integration Guide

**As a** developer using LangChain,
**I want to** see a single page showing exactly how to wrap a LangChain `Tool` with an AuthStar `authorize()` call,
**so that** I can add authorization to my existing LangChain agent in under 30 minutes without changing my tool implementations.

### Acceptance Criteria

- [ ] Published at `docs.authstar.dev/integrations/langchain`
- [ ] Opens with a one-paragraph "Why" — "LangChain tools execute without authorization checks by default. This guide adds AuthStar's pre-execution enforcement in < 30 lines."
- [ ] Shows a complete, runnable integration in ≤ 30 lines of Python:
  ```python
  from langchain.tools import Tool
  from authstar import AgentAuthz

  authz = AgentAuthz(tenant_id="...", api_key="...", agent_id="...")

  def authorized_tool(name: str, func, resource: str = "*"):
      def wrapper(*args, **kwargs):
          decision = authz.authorize(
              tool=name,
              resource=resource,
              args={"args": args, "kwargs": kwargs},
              delegation_chain=["usr_human123"],  # pass from your agent context
          )
          if not decision.allowed:
              raise PermissionError(f"Tool '{name}' denied. audit_id={decision.audit_id}")
          return func(*args, **kwargs)
      return Tool(name=name, func=wrapper, description=f"{name} (AuthStar authorized)")

  # Wrap your existing tools — no changes to the tool functions themselves
  search_tool = authorized_tool("web_search", your_search_function, resource="https://*")
  ```
- [ ] Shows how to extract `task_id` from LangChain's callback context and pass it to `authorize()` for task-chain linking
- [ ] Shows `authz.get_task_chain(task_id)` call after agent run to verify the audit trail
- [ ] "Common errors" section covers: `PermissionError` from a DENY, agent not registered (`ERR_AGENT_NOT_FOUND`), and how to handle both gracefully
- [ ] Code block CI-tested with LangChain `^0.3` and Python 3.11

### Technical Notes

- `delegation_chain` value in the guide uses a placeholder comment — note that the real value comes from the human user's session token or user ID passed into the agent context
- CI test: installs `langchain>=0.3`, runs the wrapper snippet with a mock tool function against the live test environment
- Guide links back to the Python quickstart for initial setup; assumes tenant + agent already exist

### Definition of Done

- [ ] Page published and CI job passing with `langchain>=0.3`
- [ ] Integration verified end-to-end: LangChain tool wrapped → `authorize()` called → ALLOW returned → mock tool executes → audit trail queryable
- [ ] Posted as a reply in the LangChain Discord `#showcase` channel (community distribution)

---

## US-05 — CrewAI Integration Guide

**As a** developer using CrewAI,
**I want to** see how to add AuthStar authorization to a CrewAI `BaseTool`,
**so that** every tool call in my CrewAI agent is authorized before execution, in under 30 lines.

### Acceptance Criteria

- [ ] Published at `docs.authstar.dev/integrations/crewai`
- [ ] Same structure as US-04 (Why → integration code → task chain → common errors)
- [ ] Integration overrides `BaseTool._run()` with an `authorize()` pre-check — ≤ 30 lines:
  ```python
  from crewai.tools import BaseTool
  from authstar import AgentAuthz

  authz = AgentAuthz(tenant_id="...", api_key="...", agent_id="...")

  class AuthorizedTool(BaseTool):
      name: str
      description: str
      resource: str = "*"

      def _run(self, *args, **kwargs) -> str:
          decision = authz.authorize(
              tool=self.name,
              resource=self.resource,
              args={"args": args, "kwargs": kwargs},
          )
          if not decision.allowed:
              return f"[DENIED] Tool '{self.name}' not authorized. audit_id={decision.audit_id}"
          return self._execute(*args, **kwargs)

      def _execute(self, *args, **kwargs) -> str:
          raise NotImplementedError
  ```
- [ ] Shows a concrete subclass example (`WebSearchTool(AuthorizedTool)`) with `_execute` implemented
- [ ] Code block CI-tested with `crewai>=0.80` and Python 3.11

### Definition of Done

- [ ] Page published and CI job passing with `crewai>=0.80`
- [ ] Integration verified end-to-end against live test environment
- [ ] Posted to CrewAI GitHub Discussions (community distribution)

---

## US-06 — OpenAI Agents SDK Integration Guide

**As a** developer using the OpenAI Agents SDK,
**I want to** see how to wrap a function tool with AuthStar authorization,
**so that** every tool call in my OpenAI agent is pre-authorized in under 30 lines.

### Acceptance Criteria

- [ ] Published at `docs.authstar.dev/integrations/openai-agents`
- [ ] Same structure as US-04 and US-05
- [ ] Integration wraps a `FunctionTool` using the `@function_tool` decorator pattern — ≤ 30 lines:
  ```python
  from agents import function_tool
  from authstar import AgentAuthz

  authz = AgentAuthz(tenant_id="...", api_key="...", agent_id="...")

  def authorized(tool_name: str, resource: str = "*"):
      def decorator(func):
          @function_tool
          async def wrapper(*args, **kwargs):
              decision = authz.authorize(
                  tool=tool_name,
                  resource=resource,
                  args={"args": args, "kwargs": kwargs},
              )
              if not decision.allowed:
                  return f"[DENIED] audit_id={decision.audit_id}"
              return await func(*args, **kwargs)
          return wrapper
      return decorator

  @authorized("web_search", resource="https://*")
  async def web_search(query: str) -> str:
      ...  # your implementation
  ```
- [ ] Note on async: `authz.authorize()` has an async variant `await authz.authorize_async()` — guide shows both, with async as the preferred option for OpenAI Agents SDK
- [ ] Code block CI-tested with `openai-agents>=0.0.9` (or current stable) and Python 3.11

### Definition of Done

- [ ] Page published and CI job passing
- [ ] Async `authorize_async()` method confirmed implemented in Python SDK before this story ships
- [ ] Integration verified end-to-end against live test environment
- [ ] Posted to OpenAI Developer Forum (community distribution)

---

## Sprint Ordering Recommendation

| Sprint | Stories | Rationale |
|--------|---------|-----------|
| Sprint 1 | **US-01** Python quickstart | Validates the structure; everything else reuses it |
| Sprint 2 | **US-02** TypeScript quickstart + **US-03** `authstar doctor` | Independent; both unblock activation metric improvements |
| Sprint 3 | **US-04** LangChain guide | Highest community reach of the three frameworks |
| Sprint 4 | **US-05** CrewAI + **US-06** OpenAI Agents SDK | Can be parallelised; same structure as LangChain guide |

**E3 launch gate:** US-01 and US-03 must ship before R1 launch. US-04–06 must ship within 2 weeks of R1 to capture the PLG community acquisition window.

---

## Resources

- [Epic E3 — SDK Quickstarts & Framework Guides](epic-e3-sdk-quickstarts.md)
- [Master Epic — AuthStar GA Launch](master-epic-ga.md)
- [Winning Products User Stories](https://w3.ibm.com/w3publisher/winning-products/toolkits/methods-artifacts)
- Python SDK — [`sdks/python/idaas/agent.py`](../../sdks/python/idaas/agent.py)
- TypeScript SDK — [`sdks/typescript/agent/src/client.ts`](../../sdks/typescript/agent/src/client.ts)
