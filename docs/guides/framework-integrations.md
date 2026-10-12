# AuthStar — Framework Integration Guides

End-to-end examples for integrating AuthStar agent authorization into the
three most-used AI orchestration frameworks.

---

## LangChain (Python)

AuthStar wraps cleanly as a LangChain **Tool** or a **RunnableLambda** callback
that gates every tool call before it executes.

### Installation

```bash
pip install authstar langchain langchain-openai
```

### Pattern 1 — Authorization Tool (recommended)

Expose `authorize()` as a LangChain tool so the agent explicitly requests
permission before acting. The EIAA decision is returned as structured JSON
so the agent can include the `decision_ref` in downstream calls for full
audit traceability.

```python
"""langchain_authstar_tool.py"""
import json
from langchain.tools import tool
from authstar import AuthstarClient

authstar = AuthstarClient(
    base_url="https://api.authstar.io",
    api_key="ask_your_key",
    tenant_id="your-tenant-uuid",
)

@tool
def check_authorization(action: str, subject: str, context: str = "{}") -> str:
    """
    Check whether `subject` is permitted to perform `action`.
    Pass any relevant context as a JSON string.
    Returns a JSON object with `allowed`, `decision_ref`, and `reason`.
    """
    ctx = json.loads(context) if context else {}
    decision = authstar.authorize(action=action, subject=subject, context=ctx)
    return json.dumps({
        "allowed": decision.allowed,
        "decision_ref": decision.decision_ref,
        "reason": decision.reason,
    })
```

Wire it into your agent:

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate

llm = ChatOpenAI(model="gpt-4o")
tools = [check_authorization, send_email, read_calendar]  # your real tools here

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Always call check_authorization "
               "before using any tool that modifies data."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
result = executor.invoke({"input": "Send a status email to alice@example.com"})
```

### Pattern 2 — Pre-execution callback hook

If you want authorization to happen transparently (without a dedicated tool
call), use a `RunnableLambda` that wraps every tool execution:

```python
"""langchain_authstar_callback.py"""
from langchain_core.callbacks import BaseCallbackHandler
from authstar import AuthstarClient, AuthstarError
import logging

logger = logging.getLogger(__name__)

class AuthstarGuard(BaseCallbackHandler):
    """Callback handler that gates every tool call through AuthStar EIAA."""

    def __init__(self, client: AuthstarClient, agent_id: str):
        self.client = client
        self.agent_id = agent_id

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        tool_name = serialized.get("name", "unknown_tool")
        action = f"agent:tool:{tool_name}"
        try:
            decision = self.client.authorize(
                action=action,
                subject=self.agent_id,
                context={"tool_input_preview": input_str[:200]},
            )
            if not decision.allowed:
                raise PermissionError(
                    f"AuthStar denied {action}: {decision.reason} "
                    f"(ref: {decision.decision_ref})"
                )
            logger.info("AuthStar allowed %s (ref: %s)", action, decision.decision_ref)
        except AuthstarError as e:
            # Fail closed — if AuthStar is unreachable, deny the call.
            raise PermissionError(f"AuthStar unavailable: {e}") from e
```

---

## CrewAI (Python)

CrewAI's **Task** and **Agent** model makes it straightforward to enforce
per-task authorization using a shared AuthStar client.

### Installation

```bash
pip install authstar crewai crewai-tools
```

### Pattern — Authorized Task Wrapper

Subclass `Task` to add an authorization check before the crew executes it:

```python
"""crewai_authstar.py"""
from __future__ import annotations
from crewai import Task, Agent, Crew
from authstar import AuthstarClient

authstar = AuthstarClient(
    base_url="https://api.authstar.io",
    api_key="ask_your_key",
    tenant_id="your-tenant-uuid",
)


class AuthorizedTask(Task):
    """
    A CrewAI Task that gates execution through AuthStar EIAA.

    Parameters
    ----------
    action:
        The EIAA action string (e.g. `"data:write_crm"`).
    agent_id:
        The agent principal identifier registered in AuthStar.
    """
    action: str
    agent_id: str

    def execute(self, *args, **kwargs):  # type: ignore[override]
        decision = authstar.authorize(
            action=self.action,
            subject=self.agent_id,
            context={"task_description": self.description[:200]},
        )
        if not decision.allowed:
            raise PermissionError(
                f"AuthStar denied '{self.action}' for agent '{self.agent_id}': "
                f"{decision.reason} (decision_ref={decision.decision_ref})"
            )
        return super().execute(*args, **kwargs)


# ── Usage ──────────────────────────────────────────────────────────────────

researcher = Agent(
    role="Senior Research Analyst",
    goal="Gather competitive intelligence",
    backstory="Expert at finding and synthesising market data.",
    verbose=True,
)

research_task = AuthorizedTask(
    description="Research the top 5 IDaaS competitors and summarise their pricing.",
    expected_output="A structured JSON report with competitors and pricing tiers.",
    agent=researcher,
    action="agent:web_search",
    agent_id="agt_researcher_001",
)

crew = Crew(agents=[researcher], tasks=[research_task], verbose=True)
result = crew.kickoff()
```

### Using `task_id` for task-chain audit

Pass a stable `task_id` in context so all authorization decisions across
a crew run appear as a single linked chain in the AuthStar audit log:

```python
import uuid

TASK_ID = str(uuid.uuid4())

class AuthorizedTask(Task):
    action: str
    agent_id: str
    task_id: str = ""

    def execute(self, *args, **kwargs):
        decision = authstar.authorize(
            action=self.action,
            subject=self.agent_id,
            context={"task_id": self.task_id or TASK_ID},
        )
        if not decision.allowed:
            raise PermissionError(f"Denied: {decision.reason}")
        return super().execute(*args, **kwargs)
```

---

## OpenAI Agents SDK (Python)

The [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
exposes **hooks** (`on_tool_start` / `on_tool_end`) that fire before and
after every tool call — the correct seam for authorization.

### Installation

```bash
pip install authstar openai-agents
```

### Pattern — Lifecycle Hook

```python
"""openai_agents_authstar.py"""
from agents import Agent, Runner, function_tool
from agents.lifecycle import AgentHooks
from authstar import AuthstarClient, AuthstarError

authstar = AuthstarClient(
    base_url="https://api.authstar.io",
    api_key="ask_your_key",
    tenant_id="your-tenant-uuid",
)

AGENT_ID = "agt_my_openai_agent_001"


class AuthstarHooks(AgentHooks):
    """Enforce AuthStar EIAA authorization before every tool call."""

    async def on_tool_start(self, context, agent, tool):  # type: ignore[override]
        action = f"agent:tool:{tool.name}"
        try:
            decision = authstar.authorize(
                action=action,
                subject=AGENT_ID,
                context={"task_id": str(context.context.get("task_id", ""))},
            )
        except AuthstarError as exc:
            # Fail closed — if AuthStar is unreachable, block the tool call.
            raise PermissionError(f"AuthStar unreachable: {exc}") from exc

        if not decision.allowed:
            raise PermissionError(
                f"AuthStar denied '{action}': {decision.reason} "
                f"(ref: {decision.decision_ref})"
            )


@function_tool
def send_email(recipient: str, subject: str, body: str) -> str:
    """Send an email (requires AuthStar authorization)."""
    # Your real email logic here
    return f"Email sent to {recipient}"


@function_tool
def read_calendar(date: str) -> str:
    """Read calendar events for a date (requires AuthStar authorization)."""
    # Your real calendar logic here
    return f"No events on {date}"


agent = Agent(
    name="SecureAssistant",
    instructions="Help the user with email and calendar tasks.",
    tools=[send_email, read_calendar],
    hooks=AuthstarHooks(),
)

result = Runner.run_sync(
    agent,
    input="What is on my calendar tomorrow and then send a summary to bob@example.com?",
    context={"task_id": "task_abc123"},
)
print(result.final_output)
```

### Verifying audit completeness after a run

After a run completes, confirm every tool call in the task chain has a
valid attestation:

```python
task_id = "task_abc123"
page = authstar.get_task_chain(task_id)

all_verified = True
for item in page.items:
    result = authstar.verify_decision(item.id)
    if not result.decisions_match:
        print(f"⚠  Discrepancy on {item.action}: {result.discrepancy_reason}")
        all_verified = False

print("✓ All decisions verified" if all_verified else "✗ Discrepancies found")
```

---

## Common patterns across all frameworks

### Fail closed vs fail open

Always fail **closed** (deny on error) for production agents. Only allow
fail-open in integration tests:

```python
try:
    decision = authstar.authorize(action, subject, context)
    if not decision.allowed:
        raise PermissionError(decision.reason)
except AuthstarError as e:
    if os.getenv("AUTHSTAR_FAIL_OPEN") == "true":
        logger.warning("AuthStar unavailable — fail-open in effect: %s", e)
    else:
        raise PermissionError(f"Authorization service unavailable: {e}") from e
```

### Linking decisions to a task chain

Set `task_id` in context on every call for a logical unit of work. This
builds a linked audit chain visible in the AuthStar console:

```python
import uuid

TASK_ID = uuid.uuid4().hex  # generate once per task/session

decision = authstar.authorize(
    action="agent:send_email",
    subject="agt_my_agent",
    context={"task_id": TASK_ID, "recipient": "alice@example.com"},
)
```

### Storing `decision_ref` for compliance export

The `decision_ref` from each `authorize()` call is the audit anchor. Store
it alongside your application's own records for SOC 2 compliance:

```python
decision = authstar.authorize("data:write_crm", agent_id)
db.execute(
    "INSERT INTO crm_write_log (record_id, authstar_decision_ref) VALUES (?, ?)",
    (record_id, decision.decision_ref),
)
```
