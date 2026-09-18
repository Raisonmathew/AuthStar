"""
IDaaS Agent Authorization SDK

Drop-in client for authorizing AI agent tool calls through AuthStar EIAA.
Matches the plan in docs/AI_AGENT_AUTHORIZATION.md — Sprint D (Python SDK).

Usage::

    from idaas.agent import AgentAuthz, AgentAuthzDenied

    authz = AgentAuthz(
        tenant_id="acme",
        api_key="sk_live_...",
        agent_id="agt_abc123",
        task_id="task_xyz789",
        base_url="https://api.authstar.com",
    )

    decision = authz.authorize_tool_call(
        tool_name="send_email",
        args={"to": "user@example.com", "body": "Flight booked!"},
    )

    if decision.allowed:
        result = send_email(...)
        authz.record_execution(
            tool_name="send_email",
            result_hash=hashlib.sha256(str(result).encode()).hexdigest(),
        )
    else:
        raise AgentAuthzDenied(decision.reason, decision.attestation)

Async usage (G-5)::

    from idaas.agent import AsyncAgentAuthz, AgentAuthzDenied
    import asyncio

    async def main():
        authz = AsyncAgentAuthz(
            tenant_id="acme",
            api_key="sk_live_...",
            agent_id="agt_abc123",
            task_id="task_xyz789",
        )
        decision = await authz.authorize_tool_call(
            tool_name="send_email",
            args={"to": "user@example.com"},
        )
        await authz.close()
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentDecision:
    """Result of an EIAA tool-call authorization check."""

    allowed: bool
    """True when the capsule returned Allow; False when it returned Deny."""

    reason: Optional[str] = None
    """Human-readable denial reason from the capsule (None when allowed)."""

    attestation: Optional[str] = None
    """Base64url-encoded Ed25519 attestation signature from the EIAA runtime."""

    decision_ref: Optional[str] = None
    """Unique reference for this decision — use in audit queries."""

    risk_score: Optional[int] = None
    """Risk score evaluated by the Risk Engine (0–100)."""


@dataclass
class AgentExecution:
    """Confirmation returned after recording a successful tool execution."""

    execution_id: str
    tool_name: str
    task_id: str  # Non-optional — schema enforces NOT NULL
    recorded_at: str


@dataclass
class AgentTaskChainItem:
    """A single EIAA execution row from the task audit chain."""

    id: str
    decision_ref: str
    action: str
    capsule_hash_b64: str
    decision: Any
    attestation_signature_b64: str
    attestation_timestamp: str
    created_at: str
    task_id: Optional[str] = None
    parent_action_id: Optional[str] = None
    delegation_depth: int = 0
    principal_type: str = ""
    agent_id: Optional[str] = None
    model_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args_hash: Optional[str] = None


@dataclass
class AgentChainResponse:
    """Cursor-paginated response from the task chain and agent history endpoints."""

    items: List[AgentTaskChainItem]
    next_cursor: Optional[str] = None


class AgentAuthzDenied(Exception):
    """Raised when an EIAA capsule denies a tool-call authorization."""

    def __init__(
        self,
        reason: Optional[str] = None,
        attestation: Optional[str] = None,
        decision_ref: Optional[str] = None,
    ) -> None:
        self.reason = reason
        self.attestation = attestation
        self.decision_ref = decision_ref
        msg = reason or "Agent tool call denied by EIAA capsule"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# AgentAuthz client (synchronous)
# ---------------------------------------------------------------------------

class AgentAuthz:
    """
    AuthStar AI Agent Authorization client (synchronous).

    Wraps the ``/api/v1/agents/{agent_id}/authorize``,
    ``/api/v1/agents/{agent_id}/executions``,
    ``/api/v1/audit/task/{task_id}``, and
    ``/api/v1/audit/agent/{agent_id}`` API endpoints.

    Every call is authenticated with a per-request Bearer token obtained from
    ``POST /api/v1/agents/token`` (or supplied directly via *agent_token*).

    G-6 FIX: Token expiry is tracked via ``_token_expires_at``.  ``_ensure_token()``
    re-mints the token when fewer than 60 seconds remain, so a long-running
    agentic session no longer fails with 401 after the default 3600 s TTL.

    Args:
        tenant_id:   Tenant slug or ID.
        api_key:     Service API key for minting agent tokens on behalf of the
                     tenant.  Sent as ``X-API-Key``.
        agent_id:    Registered agent principal ID (``agt_…``).
        task_id:     Task identifier grouping all tool calls in this session.
        base_url:    Base URL of the AuthStar API (no trailing slash).
        agent_token: Pre-minted agent JWT.  When supplied, *api_key* is not
                     used for token issuance.
        token_ttl_seconds: TTL to request when minting a new token (default 3600).
        timeout:     HTTP request timeout in seconds (default 10).
    """

    def __init__(
        self,
        tenant_id: str,
        api_key: str,
        agent_id: str,
        task_id: str,
        base_url: str = "https://api.authstar.com",
        agent_token: Optional[str] = None,
        token_ttl_seconds: int = 3600,
        timeout: int = 10,
    ) -> None:
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.agent_id = agent_id
        self.task_id = task_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token_ttl_seconds = token_ttl_seconds

        self._session = requests.Session()
        self._session.headers.update({"X-API-Key": api_key})
        self._agent_token: Optional[str] = agent_token
        # G-6 FIX: Track when the cached token expires.
        # If a pre-minted token is supplied we conservatively treat it as
        # expiring at ``now + token_ttl_seconds`` — callers that need exact
        # expiry should not pass a pre-minted token.
        self._token_expires_at: float = (
            time.monotonic() + token_ttl_seconds if agent_token else 0.0
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authorize_tool_call(
        self,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        *,
        raise_on_deny: bool = False,
    ) -> AgentDecision:
        """
        Authorize a tool call through the EIAA capsule.

        Sends ``POST /api/v1/agents/{agent_id}/authorize`` with a SHA-256
        hash of the serialised *args*.  The hash is sent, not the raw args,
        so secrets in arguments never leave the caller's process.

        Args:
            tool_name:      Name of the tool about to be invoked.
            args:           Tool arguments (serialised to JSON for hashing).
            raise_on_deny:  When True, raise :exc:`AgentAuthzDenied` instead
                            of returning a decision with ``allowed=False``.

        Returns:
            :class:`AgentDecision` with the capsule outcome.

        Raises:
            AgentAuthzDenied: When *raise_on_deny* is True and the capsule
                              returns Deny.
            requests.HTTPError: On non-2xx responses.
        """
        args_hash = self._hash_args(args or {})
        token = self._ensure_token()

        resp = self._session.post(
            f"{self.base_url}/api/v1/agents/{self.agent_id}/authorize",
            json={
                "tool_name": tool_name,
                "tool_args_hash": args_hash,
                "task_id": self.task_id,
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        decision = AgentDecision(
            allowed=data.get("allowed", False),
            reason=data.get("reason"),
            attestation=data.get("attestation"),
            decision_ref=data.get("decision_ref"),
            risk_score=data.get("risk_score"),
        )

        if raise_on_deny and not decision.allowed:
            raise AgentAuthzDenied(
                reason=decision.reason,
                attestation=decision.attestation,
                decision_ref=decision.decision_ref,
            )

        return decision

    def record_execution(
        self,
        tool_name: str,
        allowed: bool,
        tool_args_hash: Optional[str] = None,
        denial_reason: Optional[str] = None,
        decision_ref: Optional[str] = None,
        eiaa_execution_id: Optional[str] = None,
    ) -> AgentExecution:
        """
        Record that a tool call was executed after receiving an authorization decision.

        Sends ``POST /api/v1/agents/{agent_id}/executions``.  The *tool_args_hash*
        should be ``SHA-256(canonical_json(args))`` — raw arguments never leave
        the caller's process.

        Args:
            tool_name:         Name of the tool that was invoked.
            allowed:           Whether the tool call was authorized (True) or denied (False).
            tool_args_hash:    Hex SHA-256 of the serialised tool arguments (optional).
            denial_reason:     Reason string if allowed=False (optional).
            decision_ref:      The ``decision_ref`` from the preceding /authorize call —
                               stored as ``eiaa_execution_id`` for audit linkage.
            eiaa_execution_id: Foreign key to the parent ``eiaa_executions`` row (optional).

        Returns:
            :class:`AgentExecution` confirmation.
        """
        token = self._ensure_token()

        resp = self._session.post(
            f"{self.base_url}/api/v1/agents/{self.agent_id}/executions",
            json={
                "tool_name": tool_name,
                "task_id": self.task_id,
                "allowed": allowed,
                "tool_args_hash": tool_args_hash,
                "denial_reason": denial_reason,
                "eiaa_execution_id": eiaa_execution_id or decision_ref,
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        return AgentExecution(
            execution_id=data["execution_id"],
            tool_name=data["tool_name"],
            task_id=data["task_id"],
            recorded_at=data["recorded_at"],
        )

    def get_task_chain(
        self,
        task_id: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> AgentChainResponse:
        """
        G-1 FIX: Fetch the full causal audit chain for a task.

        Returns all EIAA execution records belonging to *task_id*, cursor-paginated.
        Pass the ``next_cursor`` from a previous response to retrieve the next page.

        GET /api/v1/audit/task/{task_id}

        Args:
            task_id: Task identifier to query (defaults to ``self.task_id``).
            cursor:  Opaque pagination cursor from a previous response.

        Returns:
            :class:`AgentChainResponse` with items and an optional ``next_cursor``.
        """
        tid = task_id or self.task_id
        token = self._ensure_token()
        params: Dict[str, str] = {}
        if cursor is not None:
            params["cursor"] = cursor

        resp = self._session.get(
            f"{self.base_url}/api/v1/audit/task/{tid}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return self._parse_chain_response(resp.json())

    def get_agent_history(
        self,
        agent_id: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> AgentChainResponse:
        """
        G-1 FIX: Fetch all EIAA executions for an agent across all tasks.

        Returns a cursor-paginated list of every execution record associated
        with *agent_id*.

        GET /api/v1/audit/agent/{agent_id}

        Args:
            agent_id: Agent principal ID to query (defaults to ``self.agent_id``).
            cursor:   Opaque pagination cursor from a previous response.

        Returns:
            :class:`AgentChainResponse` with items and an optional ``next_cursor``.
        """
        aid = agent_id or self.agent_id
        token = self._ensure_token()
        params: Dict[str, str] = {}
        if cursor is not None:
            params["cursor"] = cursor

        resp = self._session.get(
            f"{self.base_url}/api/v1/audit/agent/{aid}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return self._parse_chain_response(resp.json())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_token(self) -> str:
        """
        G-6 FIX: Return a valid agent JWT, re-minting when fewer than 60 s remain.

        Previously the token was cached forever — a session running longer than
        the TTL (default 3600 s) would receive a stale token and every subsequent
        API call would fail with HTTP 401.
        """
        _refresh_margin = 60  # seconds before expiry to proactively refresh
        if self._agent_token and time.monotonic() < self._token_expires_at - _refresh_margin:
            return self._agent_token

        resp = self._session.post(
            f"{self.base_url}/api/v1/agents/token",
            json={
                "agent_id": self.agent_id,
                "task_id": self.task_id,
                "ttl_seconds": self._token_ttl_seconds,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        self._agent_token = data["token"]
        # expires_in is the TTL granted by the server; fall back to our requested TTL.
        expires_in: int = data.get("expires_in", self._token_ttl_seconds)
        self._token_expires_at = time.monotonic() + expires_in
        return self._agent_token  # type: ignore[return-value]

    @staticmethod
    def _hash_args(args: Dict[str, Any]) -> str:
        """Return the hex-encoded SHA-256 of the canonically-serialised args."""
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _parse_chain_response(data: Dict[str, Any]) -> AgentChainResponse:
        """Deserialise a raw JSON dict into an :class:`AgentChainResponse`."""
        items = [
            AgentTaskChainItem(
                id=item["id"],
                decision_ref=item["decision_ref"],
                action=item["action"],
                capsule_hash_b64=item["capsule_hash_b64"],
                decision=item.get("decision"),
                attestation_signature_b64=item["attestation_signature_b64"],
                attestation_timestamp=item["attestation_timestamp"],
                created_at=item["created_at"],
                task_id=item.get("task_id"),
                parent_action_id=item.get("parent_action_id"),
                delegation_depth=item.get("delegation_depth", 0),
                principal_type=item.get("principal_type", ""),
                agent_id=item.get("agent_id"),
                model_id=item.get("model_id"),
                tool_name=item.get("tool_name"),
                tool_args_hash=item.get("tool_args_hash"),
            )
            for item in data.get("items", [])
        ]
        return AgentChainResponse(
            items=items,
            next_cursor=data.get("next_cursor"),
        )


# ---------------------------------------------------------------------------
# AsyncAgentAuthz client (G-5)
# ---------------------------------------------------------------------------

try:
    import httpx as _httpx  # optional dependency for async support

    class AsyncAgentAuthz:
        """
        G-5 FIX: Async variant of :class:`AgentAuthz` for use in asyncio/FastAPI/LangGraph.

        Uses ``httpx.AsyncClient`` so callers can ``await`` every method without
        blocking the event loop.  Requires the ``httpx`` package::

            pip install httpx

        Usage::

            async with AsyncAgentAuthz(...) as authz:
                decision = await authz.authorize_tool_call("send_email", args={...})

        Or manage the lifecycle manually::

            authz = AsyncAgentAuthz(...)
            try:
                decision = await authz.authorize_tool_call(...)
            finally:
                await authz.close()
        """

        def __init__(
            self,
            tenant_id: str,
            api_key: str,
            agent_id: str,
            task_id: str,
            base_url: str = "https://api.authstar.com",
            agent_token: Optional[str] = None,
            token_ttl_seconds: int = 3600,
            timeout: int = 10,
        ) -> None:
            self.tenant_id = tenant_id
            self.api_key = api_key
            self.agent_id = agent_id
            self.task_id = task_id
            self.base_url = base_url.rstrip("/")
            self.timeout = timeout
            self._token_ttl_seconds = token_ttl_seconds
            self._agent_token: Optional[str] = agent_token
            self._token_expires_at: float = (
                time.monotonic() + token_ttl_seconds if agent_token else 0.0
            )
            self._http = _httpx.AsyncClient(
                headers={"X-API-Key": api_key},
                timeout=timeout,
            )

        async def __aenter__(self) -> "AsyncAgentAuthz":
            return self

        async def __aexit__(self, *_: Any) -> None:
            await self.close()

        async def close(self) -> None:
            """Close the underlying HTTP client."""
            await self._http.aclose()

        async def authorize_tool_call(
            self,
            tool_name: str,
            args: Optional[Dict[str, Any]] = None,
            *,
            raise_on_deny: bool = False,
        ) -> AgentDecision:
            """Async version of :meth:`AgentAuthz.authorize_tool_call`."""
            args_hash = AgentAuthz._hash_args(args or {})
            token = await self._ensure_token()

            resp = await self._http.post(
                f"{self.base_url}/api/v1/agents/{self.agent_id}/authorize",
                json={
                    "tool_name": tool_name,
                    "tool_args_hash": args_hash,
                    "task_id": self.task_id,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            data = resp.json()

            decision = AgentDecision(
                allowed=data.get("allowed", False),
                reason=data.get("reason"),
                attestation=data.get("attestation"),
                decision_ref=data.get("decision_ref"),
                risk_score=data.get("risk_score"),
            )

            if raise_on_deny and not decision.allowed:
                raise AgentAuthzDenied(
                    reason=decision.reason,
                    attestation=decision.attestation,
                    decision_ref=decision.decision_ref,
                )

            return decision

        async def record_execution(
            self,
            tool_name: str,
            allowed: bool,
            tool_args_hash: Optional[str] = None,
            denial_reason: Optional[str] = None,
            decision_ref: Optional[str] = None,
            eiaa_execution_id: Optional[str] = None,
        ) -> AgentExecution:
            """Async version of :meth:`AgentAuthz.record_execution`."""
            token = await self._ensure_token()

            resp = await self._http.post(
                f"{self.base_url}/api/v1/agents/{self.agent_id}/executions",
                json={
                    "tool_name": tool_name,
                    "task_id": self.task_id,
                    "allowed": allowed,
                    "tool_args_hash": tool_args_hash,
                    "denial_reason": denial_reason,
                    "eiaa_execution_id": eiaa_execution_id or decision_ref,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            data = resp.json()

            return AgentExecution(
                execution_id=data["execution_id"],
                tool_name=data["tool_name"],
                task_id=data["task_id"],
                recorded_at=data["recorded_at"],
            )

        async def get_task_chain(
            self,
            task_id: Optional[str] = None,
            cursor: Optional[str] = None,
        ) -> AgentChainResponse:
            """Async version of :meth:`AgentAuthz.get_task_chain`."""
            tid = task_id or self.task_id
            token = await self._ensure_token()
            params: Dict[str, str] = {}
            if cursor is not None:
                params["cursor"] = cursor

            resp = await self._http.get(
                f"{self.base_url}/api/v1/audit/task/{tid}",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return AgentAuthz._parse_chain_response(resp.json())

        async def get_agent_history(
            self,
            agent_id: Optional[str] = None,
            cursor: Optional[str] = None,
        ) -> AgentChainResponse:
            """Async version of :meth:`AgentAuthz.get_agent_history`."""
            aid = agent_id or self.agent_id
            token = await self._ensure_token()
            params: Dict[str, str] = {}
            if cursor is not None:
                params["cursor"] = cursor

            resp = await self._http.get(
                f"{self.base_url}/api/v1/audit/agent/{aid}",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return AgentAuthz._parse_chain_response(resp.json())

        async def _ensure_token(self) -> str:
            """G-6 FIX: Async token refresh with expiry tracking."""
            _refresh_margin = 60
            if self._agent_token and time.monotonic() < self._token_expires_at - _refresh_margin:
                return self._agent_token

            resp = await self._http.post(
                f"{self.base_url}/api/v1/agents/token",
                json={
                    "agent_id": self.agent_id,
                    "task_id": self.task_id,
                    "ttl_seconds": self._token_ttl_seconds,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._agent_token = data["token"]
            expires_in: int = data.get("expires_in", self._token_ttl_seconds)
            self._token_expires_at = time.monotonic() + expires_in
            return self._agent_token  # type: ignore[return-value]

except ImportError:
    # httpx not installed — AsyncAgentAuthz is not available.
    # Importing the module still works; only async usage requires httpx.
    pass
