"""
examples/crewai_agent.py — Wrap AuthStar authorization as a CrewAI tool.

This example shows how to create a CrewAI ``@tool``-decorated function (and an
equivalent ``BaseTool`` subclass) that calls ``AuthstarClient.authorize()``,
then how to attach it to a CrewAI Agent and Task.

Installation
------------
::

    pip install authstar crewai

Usage
-----
::

    AUTHSTAR_URL=https://api.authstar.io \\
    AUTHSTAR_API_KEY=ask_... \\
    AUTHSTAR_TENANT_ID=your-tenant \\
    python crewai_agent.py

Architecture note
-----------------
CrewAI tools come in two flavours:

1. **``@tool`` decorator** — wraps a plain function; the docstring becomes the
   tool description.  Simplest approach.
2. **``BaseTool`` subclass** — gives finer control over input validation via a
   Pydantic ``args_schema``.

Both are shown below.  The agent in the demo uses the ``BaseTool`` variant.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Type

from pydantic import BaseModel, Field

# crewai must be installed separately: pip install crewai
from crewai.tools import BaseTool as CrewBaseTool
from crewai.tools import tool as crewai_tool

from authstar import AuthstarClient
from authstar.exceptions import AuthstarError

# ---------------------------------------------------------------------------
# Shared AuthStar client (constructed once from environment variables)
# ---------------------------------------------------------------------------

_CLIENT: Optional[AuthstarClient] = None


def _get_client() -> AuthstarClient:
    """Return the module-level singleton ``AuthstarClient``, constructing it on
    first call from the ``AUTHSTAR_*`` environment variables."""
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = AuthstarClient(
            base_url=os.environ.get("AUTHSTAR_URL", "https://api.authstar.io"),
            api_key=os.environ["AUTHSTAR_API_KEY"],
            tenant_id=os.environ["AUTHSTAR_TENANT_ID"],
        )
    return _CLIENT


# ---------------------------------------------------------------------------
# Approach 1 — @tool decorator (lightweight)
# ---------------------------------------------------------------------------


@crewai_tool("AuthStar Authorization Check")
def authstar_authorize_fn(action: str, subject: str, context_json: str = "{}") -> str:
    """Check whether a subject is permitted to perform an EIAA action.

    Args:
        action: The EIAA action string, e.g. 'agent:read_customer_data'.
        subject: The agent ID or user UUID requesting the action.
        context_json: JSON-encoded dict of additional context, e.g.
            '{"task_id": "task-xyz", "resource": "customers"}'.

    Returns:
        JSON string with keys: allowed (bool), decision_ref (str), reason (str | null).
    """
    try:
        ctx: dict[str, Any] = json.loads(context_json)
    except json.JSONDecodeError:
        return json.dumps({"error": f"context_json must be valid JSON; got: {context_json!r}"})

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
# Approach 2 — BaseTool subclass (structured input schema)
# ---------------------------------------------------------------------------


class _AuthzInput(BaseModel):
    """Validated input for :class:`AuthstarCrewTool`."""

    action: str = Field(
        ...,
        description="EIAA action to authorize, e.g. 'agent:read_customer_data'.",
    )
    subject: str = Field(
        ...,
        description="Agent ID or user UUID requesting the action.",
    )
    context: Optional[dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional context forwarded to the policy capsule.",
    )


class AuthstarCrewTool(CrewBaseTool):
    """CrewAI tool that authorizes agent actions via the AuthStar EIAA platform.

    Attach this tool to a CrewAI ``Agent`` that needs to make policy-guarded
    decisions before calling downstream APIs or tools.

    Parameters
    ----------
    client:
        A configured :class:`~authstar.AuthstarClient` instance.

    Example
    -------
    ::

        from crewai import Agent, Task, Crew
        from authstar import AuthstarClient
        from examples.crewai_agent import AuthstarCrewTool

        authz_tool = AuthstarCrewTool(client=AuthstarClient(...))

        agent = Agent(
            role="Data Analyst",
            goal="Analyze customer data with proper authorization",
            backstory="You always check permissions before accessing sensitive data.",
            tools=[authz_tool],
        )
    """

    name: str = "authstar_authorize"
    description: str = (
        "Check whether an agent or user is permitted to perform a specific EIAA action. "
        "Always call this tool before accessing protected resources. "
        "Input: action (str), subject (str), optional context (dict). "
        "Output: JSON with 'allowed' (bool), 'decision_ref' (str), 'reason' (str or null)."
    )
    args_schema: Type[BaseModel] = _AuthzInput
    model_config = {"arbitrary_types_allowed": True}

    client: AuthstarClient

    def _run(
        self,
        action: str,
        subject: str,
        context: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Execute the authorization check synchronously."""
        try:
            decision = self.client.authorize(
                action=action,
                subject=subject,
                context=context or {},
            )
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
# Demo: wire the tool into a simple CrewAI agent
# ---------------------------------------------------------------------------


def main() -> None:
    """Run a one-shot CrewAI crew that checks authorization before acting."""
    from crewai import Agent, Crew, Task

    client = AuthstarClient(
        base_url=os.environ.get("AUTHSTAR_URL", "https://api.authstar.io"),
        api_key=os.environ["AUTHSTAR_API_KEY"],
        tenant_id=os.environ["AUTHSTAR_TENANT_ID"],
    )
    authz_tool = AuthstarCrewTool(client=client)

    # Define an agent that uses the authorization tool
    analyst = Agent(
        role="Compliance Analyst",
        goal="Verify that AI agents are authorized before granting them data access.",
        backstory=(
            "You are a compliance officer responsible for verifying that every agent "
            "request has been explicitly authorized by the platform's EIAA policy engine."
        ),
        tools=[authz_tool],
        verbose=True,
    )

    # Define a task that asks the agent to check authorization
    task = Task(
        description=(
            "Check whether agent 'agent-demo-001' is permitted to perform the action "
            "'agent:read_customer_data' for task 'task-smoke-test'. "
            "Use the authstar_authorize tool to find out.  "
            "Report the outcome including the decision reference."
        ),
        expected_output=(
            "A clear statement of whether the agent is authorized, the decision "
            "reference string, and any reason given by the policy engine."
        ),
        agent=analyst,
    )

    crew = Crew(agents=[analyst], tasks=[task], verbose=True)
    result = crew.kickoff()
    print("\nCrew result:", result)


if __name__ == "__main__":
    main()
