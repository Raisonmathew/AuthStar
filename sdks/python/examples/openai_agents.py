"""
examples/openai_agents.py — Wrap AuthStar authorization as an OpenAI Agents SDK function tool.

This example registers ``AuthstarClient.authorize()`` as a **function tool**
for the `openai-agents` SDK (``pip install openai-agents``), so any OpenAI
Responses-API agent can call it during a run.

Installation
------------
::

    pip install authstar openai-agents

Usage
-----
::

    AUTHSTAR_URL=https://api.authstar.io \\
    AUTHSTAR_API_KEY=ask_... \\
    AUTHSTAR_TENANT_ID=your-tenant \\
    OPENAI_API_KEY=sk-... \\
    python openai_agents.py

How it works
------------
The OpenAI Agents SDK supports two ways to define function tools:

1. **``@function_tool`` decorator** — decorates a typed Python function; the
   SDK generates the JSON schema from the function signature and docstring.
2. **``FunctionTool`` class** — explicitly provides the JSON schema.

Both are shown; the demo agent uses the decorator variant.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

# openai-agents must be installed separately: pip install openai-agents
from agents import Agent, FunctionTool, Runner, function_tool
from agents.tool import FunctionToolResult

from authstar import AuthstarClient
from authstar.exceptions import AuthstarError

# ---------------------------------------------------------------------------
# Shared AuthStar client
# ---------------------------------------------------------------------------

_CLIENT: Optional[AuthstarClient] = None


def _get_client() -> AuthstarClient:
    """Return the module-level singleton, constructing it on first call."""
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = AuthstarClient(
            base_url=os.environ.get("AUTHSTAR_URL", "https://api.authstar.io"),
            api_key=os.environ["AUTHSTAR_API_KEY"],
            tenant_id=os.environ["AUTHSTAR_TENANT_ID"],
        )
    return _CLIENT


# ---------------------------------------------------------------------------
# Approach 1 — @function_tool decorator
# ---------------------------------------------------------------------------


@function_tool
def authstar_authorize(
    action: str,
    subject: str,
    context_json: str = "{}",
) -> str:
    """Check whether a subject is permitted to perform an EIAA action.

    Args:
        action: The EIAA action string, e.g. 'agent:read_customer_data'.
        subject: The agent ID or user UUID requesting the action.
        context_json: Optional JSON-encoded dict with extra policy context,
            e.g. '{"task_id": "task-xyz", "resource": "customers"}'.

    Returns:
        A JSON string with 'allowed' (bool), 'decision_ref' (str), and
        'reason' (str or null).  If authorization fails due to a network or
        API error, 'allowed' will be false and an 'error' key will be present.
    """
    try:
        ctx: dict[str, Any] = json.loads(context_json) if context_json else {}
    except json.JSONDecodeError:
        return json.dumps(
            {"allowed": False, "error": f"context_json is not valid JSON: {context_json!r}"}
        )

    client = _get_client()
    try:
        decision = client.authorize(action=action, subject=subject, context=ctx)
    except AuthstarError as exc:
        return json.dumps({"allowed": False, "error": str(exc)})

    return json.dumps(
        {
            "allowed": decision.allowed,
            "decision_ref": decision.decision_ref,
            "reason": decision.reason,
        }
    )


# ---------------------------------------------------------------------------
# Approach 2 — FunctionTool with explicit JSON schema
#
# Use this when you need tighter control over the schema (e.g. descriptions
# visible in the OpenAI dashboard) or when the function is async.
# ---------------------------------------------------------------------------

_AUTHSTAR_SCHEMA: dict[str, Any] = {
    "name": "authstar_authorize",
    "description": (
        "Check whether an agent or user is permitted to perform a specific EIAA action "
        "using the AuthStar authorization platform.  Always call this before accessing "
        "protected resources."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "The EIAA action string, e.g. 'agent:read_customer_data'.",
            },
            "subject": {
                "type": "string",
                "description": "The agent ID or user UUID requesting the action.",
            },
            "context_json": {
                "type": "string",
                "description": (
                    "Optional JSON-encoded dict with additional policy context, "
                    "e.g. '{\"task_id\": \"task-xyz\"}'."
                ),
                "default": "{}",
            },
        },
        "required": ["action", "subject"],
        "additionalProperties": False,
    },
}


def _authstar_authorize_handler(args_json: str) -> str:
    """Handler used by :data:`authstar_authorize_explicit`."""
    try:
        args = json.loads(args_json)
    except json.JSONDecodeError:
        return json.dumps({"allowed": False, "error": "tool arguments are not valid JSON"})

    return authstar_authorize(
        action=args.get("action", ""),
        subject=args.get("subject", ""),
        context_json=args.get("context_json", "{}"),
    )


authstar_authorize_explicit = FunctionTool(
    name=_AUTHSTAR_SCHEMA["name"],
    description=_AUTHSTAR_SCHEMA["description"],
    params_json_schema=_AUTHSTAR_SCHEMA["parameters"],
    on_invoke_tool=_authstar_authorize_handler,
)
"""
``FunctionTool`` instance with an explicit JSON schema.  Can be passed to an
``Agent`` in place of the ``@function_tool``-decorated version::

    agent = Agent(
        name="Compliance Agent",
        instructions=...,
        tools=[authstar_authorize_explicit],
    )
"""


# ---------------------------------------------------------------------------
# Demo: wire the tool into an OpenAI Agents SDK agent
# ---------------------------------------------------------------------------


async def _run_demo() -> None:
    """Run a single-turn agent that uses the AuthStar authorization tool."""
    agent = Agent(
        name="Compliance Agent",
        instructions=(
            "You are a compliance agent.  Before granting access to any data, "
            "you MUST call the authstar_authorize tool to verify the request is allowed. "
            "Always report the decision_ref alongside your answer."
        ),
        tools=[authstar_authorize],
        model="gpt-4o",
    )

    result = await Runner.run(
        agent,
        input=(
            "Check whether agent 'agent-demo-001' can perform the action "
            "'agent:read_customer_data' for task 'task-smoke-test' "
            "with context {\"resource\": \"customers\"}."
        ),
    )
    print("Agent output:", result.final_output)


if __name__ == "__main__":
    import asyncio

    asyncio.run(_run_demo())
