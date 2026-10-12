"""
examples/langchain_tool.py — Wrap AuthStar authorization as a LangChain BaseTool.

This example shows how to expose ``AuthstarClient.authorize()`` as a LangChain
tool so it can be used inside a LangChain agent or chain.

Installation
------------
::

    pip install "authstar[langchain]"

Usage
-----
::

    python langchain_tool.py

The tool can be passed directly to any LangChain agent that accepts a list of
tools::

    from langchain.agents import initialize_agent, AgentType
    from langchain_openai import ChatOpenAI

    agent = initialize_agent(
        tools=[authz_tool],
        llm=ChatOpenAI(model="gpt-4o"),
        agent=AgentType.OPENAI_FUNCTIONS,
    )
    result = agent.run("Can agent-abc read customer data for task-xyz?")
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Type

from pydantic import BaseModel, Field

# langchain-core is an optional dependency — install with: pip install authstar[langchain]
from langchain_core.tools import BaseTool

from authstar import AuthstarClient
from authstar.exceptions import AuthstarError


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------


class AuthzInput(BaseModel):
    """Input schema for the AuthStar authorization tool."""

    action: str = Field(
        ...,
        description=(
            "The EIAA action to authorize, e.g. 'agent:read_customer_data' or "
            "'data:write'.  Must be a non-empty string."
        ),
    )
    subject: str = Field(
        ...,
        description="The agent ID or user UUID requesting the action.",
    )
    context: Optional[str] = Field(
        None,
        description=(
            "Optional JSON-encoded dict of additional context passed to the "
            "policy capsule, e.g. '{\"task_id\": \"task-xyz\", \"resource\": \"customers\"}'."
        ),
    )


# ---------------------------------------------------------------------------
# LangChain tool
# ---------------------------------------------------------------------------


class AuthstarAuthzTool(BaseTool):
    """LangChain tool that checks authorization via the AuthStar EIAA platform.

    The tool calls ``AuthstarClient.authorize()`` and returns a JSON string
    with the decision, reference, and reason so the agent can act on it.

    Parameters
    ----------
    client:
        A configured :class:`~authstar.AuthstarClient` instance.

    Example
    -------
    ::

        from authstar import AuthstarClient
        from examples.langchain_tool import AuthstarAuthzTool

        client = AuthstarClient(
            base_url=os.environ["AUTHSTAR_URL"],
            api_key=os.environ["AUTHSTAR_API_KEY"],
            tenant_id=os.environ["AUTHSTAR_TENANT_ID"],
        )
        tool = AuthstarAuthzTool(client=client)

        # Direct invocation
        result = tool.run({
            "action": "agent:read_customer_data",
            "subject": "agent-abc123",
            "context": '{"task_id": "task-xyz"}',
        })
        print(result)
        # {"allowed": true, "decision_ref": "dec_...", "reason": "Policy allowed"}
    """

    name: str = "authstar_authorize"
    description: str = (
        "Check whether an agent or user is permitted to perform a specific action "
        "using the AuthStar EIAA authorization platform.  "
        "Input must include 'action' (the EIAA action string) and 'subject' (the agent/user ID). "
        "Optionally include 'context' as a JSON string with extra policy context. "
        "Returns a JSON string with 'allowed' (bool), 'decision_ref', and 'reason'."
    )
    args_schema: Type[BaseModel] = AuthzInput

    # Pydantic v2 model config: allow arbitrary types so we can store the client
    model_config = {"arbitrary_types_allowed": True}

    client: AuthstarClient

    def _run(
        self,
        action: str,
        subject: str,
        context: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Synchronous execution — called by LangChain agent runtimes."""
        ctx: dict[str, Any] = {}
        if context:
            try:
                ctx = json.loads(context)
            except json.JSONDecodeError:
                return json.dumps(
                    {"error": f"context must be valid JSON; got: {context!r}"}
                )

        try:
            decision = self.client.authorize(
                action=action,
                subject=subject,
                context=ctx,
            )
        except AuthstarError as exc:
            return json.dumps({"error": str(exc), "allowed": False})

        return json.dumps(
            {
                "allowed": decision.allowed,
                "decision_ref": decision.decision_ref,
                "reason": decision.reason,
            }
        )

    async def _arun(
        self,
        action: str,
        subject: str,
        context: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Async execution — delegates to the synchronous implementation.

        ``AuthstarClient`` is synchronous.  For true async support, wrap this
        tool's client calls in ``asyncio.to_thread``.
        """
        import asyncio

        return await asyncio.to_thread(
            self._run,
            action=action,
            subject=subject,
            context=context,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def _build_tool() -> AuthstarAuthzTool:
    """Build the tool from environment variables."""
    client = AuthstarClient(
        base_url=os.environ.get("AUTHSTAR_URL", "https://api.authstar.io"),
        api_key=os.environ["AUTHSTAR_API_KEY"],
        tenant_id=os.environ["AUTHSTAR_TENANT_ID"],
    )
    return AuthstarAuthzTool(client=client)


if __name__ == "__main__":
    tool = _build_tool()

    # Direct invocation without an agent — useful for quick smoke tests.
    result = tool.invoke(
        {
            "action": "agent:read_customer_data",
            "subject": "agent-demo-001",
            "context": json.dumps({"task_id": "task-smoke-test", "resource": "customers"}),
        }
    )
    print("Authorization result:", result)
