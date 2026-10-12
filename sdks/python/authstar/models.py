"""
authstar.models — Pydantic v2 response models for the AuthStar SDK.

These models are returned by :class:`~authstar.client.AuthstarClient` methods
and can also be imported directly for type annotations in application code.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuthzDecision(BaseModel):
    """The outcome of a single authorization request.

    Returned by :meth:`~authstar.client.AuthstarClient.authorize`.

    Attributes:
        allowed: ``True`` when the action is permitted.
        decision_ref: Opaque unique reference string for this decision.
            Pass it to :meth:`~authstar.client.AuthstarClient.verify_decision`
            to replay and cryptographically verify the outcome.
        attestation_sig: Base64-encoded attestation signature (Ed25519/ES256)
            produced by the EIAA capsule runtime.  ``None`` if the backend did
            not return one (e.g. in a degraded / fallback path).
        reason: Human-readable explanation for the decision, e.g.
            ``"Delegation chain depth exceeded"`` or ``"Policy allowed"``.
    """

    allowed: bool = Field(..., description="Whether the action is permitted.")
    decision_ref: str = Field(
        ..., description="Unique reference for this decision record."
    )
    attestation_sig: Optional[str] = Field(
        None, description="Base64 attestation signature from the capsule runtime."
    )
    reason: Optional[str] = Field(
        None, description="Human-readable reason for the decision."
    )


class TaskChainItem(BaseModel):
    """A single EIAA execution record within an agent task chain.

    Returned as items in :class:`TaskChainPage`.

    Attributes:
        id: Database row UUID.
        decision_ref: Unique reference for this execution record.
        action: The EIAA action string (e.g. ``"agent:read_customer_data"``).
        allowed: Whether the action was permitted; ``None`` for records where
            the allow/deny outcome was not stored explicitly.
        capsule_hash_b64: SHA-256 hash (base64) of the capsule WASM bytecode
            that evaluated this decision.
        attestation_signature_b64: Base64 attestation signature.
        attestation_timestamp: When the attestation was produced.
        created_at: When this execution record was written to the audit log.
        task_id: Agent task this execution belongs to.
        parent_action_id: ID of the parent action in the causal chain, if any.
        delegation_depth: How deep in the delegation chain this principal sat.
        principal_type: ``"agent"`` or ``"human"``.
        agent_id: Agent principal identifier, if applicable.
        model_id: LLM model identifier, e.g. ``"claude-3-5-sonnet-20241022"``.
        tool_name: The tool that was called (without the ``"agent:"`` prefix).
        tool_args_hash: SHA-256 hash (base64) of the serialized tool arguments.
        user_id: Human user who ultimately delegated this action, if available.
    """

    id: str
    decision_ref: str
    action: str
    allowed: Optional[bool] = None
    capsule_hash_b64: str
    attestation_signature_b64: str
    attestation_timestamp: datetime
    created_at: datetime
    task_id: Optional[str] = None
    parent_action_id: Optional[str] = None
    delegation_depth: int = 0
    principal_type: str
    agent_id: Optional[str] = None
    model_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args_hash: Optional[str] = None
    user_id: Optional[str] = None


class TaskChainPage(BaseModel):
    """A single page of task-chain execution records.

    Returned by :meth:`~authstar.client.AuthstarClient.get_task_chain`.

    Attributes:
        items: Execution records for this page, ordered oldest-first so the
            causal chain can be reconstructed by iterating in order.
        next_cursor: ISO-8601 timestamp to pass as ``cursor`` in the next
            call to retrieve the following page.  ``None`` means this is the
            last page.
    """

    items: List[TaskChainItem] = Field(default_factory=list)
    next_cursor: Optional[str] = Field(
        None,
        description=(
            "ISO-8601 cursor timestamp. Pass as `cursor` to fetch the next page."
        ),
    )


class VerificationResult(BaseModel):
    """Result of re-executing and verifying a past authorization decision.

    Returned by :meth:`~authstar.client.AuthstarClient.verify_decision`.

    Attributes:
        verified: ``True`` when the replayed decision matches the original.
        original_decision: The allow/deny outcome stored in the audit log.
        replayed_decision: The allow/deny outcome produced by re-running the
            same inputs through the capsule.
        decisions_match: Whether ``original_decision == replayed_decision``.
        status: One of ``"verified"``, ``"discrepancy"``,
            ``"capsule_not_found"``, or ``"execution_error"``.
    """

    verified: bool
    original_decision: bool
    replayed_decision: bool
    decisions_match: bool
    status: str = Field(
        ...,
        description=(
            "One of: verified, discrepancy, capsule_not_found, execution_error."
        ),
    )


class HealthStatus(BaseModel):
    """Result of a health check against the AuthStar API.

    Returned by :meth:`~authstar.client.AuthstarClient.health`.

    Attributes:
        ok: ``True`` when both ``/health`` and ``/health/ready`` returned 200.
        latency_ms: Round-trip latency in milliseconds for the ``/health`` call.
        version: Server version string, if returned by the ``/health`` endpoint.
    """

    ok: bool
    latency_ms: float
    version: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal-only types (not exported from the package __init__)
# ---------------------------------------------------------------------------


class _UserInfo(BaseModel):
    """Partial representation of the /api/v1/user response."""

    id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @property
    def display_name(self) -> str:
        parts = [p for p in (self.first_name, self.last_name) if p]
        return " ".join(parts) if parts else self.email


class _AgentAuthorizeResponse(BaseModel):
    """Internal model for the POST /api/v1/agents/:id/authorize response."""

    allowed: bool
    reason: Optional[str] = None
    decision_ref: str
    attestation_ref: Optional[str] = None


class _ReExecutionResult(BaseModel):
    """Internal model for the GET /api/v1/audit/reexecution/verify/:ref response."""

    decision_ref: str
    original_decision: bool
    replayed_decision: bool
    decisions_match: bool
    verification_status: str
    discrepancy_reason: Optional[str] = None


class _VerifyResponse(BaseModel):
    """Wrapper returned by the /verify/:decision_ref endpoint."""

    result: _ReExecutionResult


class _TaskChainResponse(BaseModel):
    """Internal model for GET /api/v1/audit/task/:task_id."""

    items: List[Dict[str, Any]]
    next_cursor: Optional[str] = None
