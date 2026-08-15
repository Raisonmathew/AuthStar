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
"""

import hashlib
import json
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
# AgentAuthz client
# ---------------------------------------------------------------------------

class AgentAuthz:
    """
    AuthStar AI Agent Authorization client.

    Wraps the ``/api/v1/agents/{agent_id}/authorize`` and
    ``/api/v1/agents/{agent_id}/executions`` API endpoints.  Every call is
    authenticated with a per-request Bearer token obtained from
    ``POST /api/v1/agents/token`` (or supplied directly via *agent_token*).

    Args:
        tenant_id:   Tenant slug or ID.
        api_key:     Service API key for minting agent tokens on behalf of the
                     tenant.  Sent as ``X-API-Key``.
        agent_id:    Registered agent principal ID (``agt_…``).
        task_id:     Task identifier grouping all tool calls in this session.
        base_url:    Base URL of the AuthStar API (no trailing slash).
        agent_token: Pre-minted agent JWT.  When supplied, *api_key* is not
                     used for token issuance.
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
        timeout: int = 10,
    ) -> None:
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.agent_id = agent_id
        self.task_id = task_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update({"X-API-Key": api_key})
        self._agent_token: Optional[str] = agent_token

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

        CRIT-1 FIX: Aligned with the updated `tool_call_audits` schema.
        - ``task_id`` is now required (NOT NULL) and taken from ``self.task_id``.
        - ``allowed`` (bool) is now required (NOT NULL).
        - ``result_hash``, ``decision_ref``, ``executed_at`` have been removed
          from the INSERT — they do not exist in the DB schema.
        - ``tool_args_hash`` replaces ``result_hash`` for argument audit hashing.

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_token(self) -> str:
        """Return a valid agent JWT, minting one if not already held."""
        if self._agent_token:
            return self._agent_token

        resp = self._session.post(
            f"{self.base_url}/api/v1/agents/token",
            json={
                "agent_id": self.agent_id,
                "task_id": self.task_id,
                "ttl_seconds": 3600,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        self._agent_token = resp.json()["token"]
        return self._agent_token  # type: ignore[return-value]

    @staticmethod
    def _hash_args(args: Dict[str, Any]) -> str:
        """Return the hex-encoded SHA-256 of the canonically-serialised args."""
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
