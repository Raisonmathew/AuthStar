"""
authstar.client — Synchronous HTTP client for the AuthStar API.

This module exposes :class:`AuthstarClient`, the primary entry point for the
SDK.  All methods are synchronous and use ``httpx`` under the hood.  An async
variant is not provided yet; wrap calls in ``asyncio.to_thread`` when using from
an async context.

API key format
--------------
AuthStar API keys begin with ``ask_`` and are passed as a Bearer token in the
``Authorization`` header::

    Authorization: Bearer ask_your_key_here

Endpoint overview
-----------------
+----------------------------------------------+-------------------------------+
| SDK method                                   | HTTP call                     |
+==============================================+===============================+
| authorize(action, subject, context)          | POST /api/v1/decisions        |
+----------------------------------------------+-------------------------------+
| revoke(agent_id)                             | POST /api/v1/agents/          |
|                                              |      :id/revoke               |
+----------------------------------------------+-------------------------------+
| get_task_chain(task_id, cursor, limit)       | GET  /api/v1/audit/task/:id   |
+----------------------------------------------+-------------------------------+
| verify_decision(decision_ref)                | GET  /api/v1/audit/           |
|                                              |      reexecution/verify/:ref  |
+----------------------------------------------+-------------------------------+
| health()                                     | GET  /health                  |
+----------------------------------------------+-------------------------------+
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import httpx

from authstar.exceptions import (
    AuthstarAuthError,
    AuthstarHTTPError,
    AuthstarNotFoundError,
    AuthstarRateLimitError,
)
from authstar.models import (
    AuthzDecision,
    HealthStatus,
    TaskChainItem,
    TaskChainPage,
    VerificationResult,
    _AgentAuthorizeResponse,
    _ReExecutionResult,
    _VerifyResponse,
)

# The default agent_id used when no per-call agent_id is supplied to authorize().
# In the current API design the authorize endpoint is POST /api/v1/decisions
# (human-bearer auth), not the agent-JWT-scoped endpoint.
_DECISIONS_PATH = "/api/v1/decisions"
_AGENTS_REVOKE_PATH = "/api/v1/agents/{agent_id}/revoke"
_TASK_CHAIN_PATH = "/api/v1/audit/task/{task_id}"
_REEXECUTION_VERIFY_PATH = "/api/v1/audit/reexecution/verify/{decision_ref}"
_HEALTH_PATH = "/health"
_HEALTH_READY_PATH = "/health/ready"
_USER_PATH = "/api/v1/user"


class AuthstarClient:
    """Synchronous client for the AuthStar AI Agent Authorization API.

    All requests authenticate via a Bearer API key::

        Authorization: Bearer ask_...

    and are scoped to the supplied ``tenant_id`` (passed as the
    ``X-Tenant-ID`` header).

    Parameters
    ----------
    base_url:
        Root URL of the AuthStar backend, e.g. ``"https://api.authstar.io"``.
        Trailing slashes are stripped automatically.
    api_key:
        A valid AuthStar API key (``ask_...``).
    tenant_id:
        Your tenant / organisation UUID.
    timeout:
        Per-request HTTP timeout in seconds.  Defaults to ``10.0``.

    Examples
    --------
    Basic authorization check::

        from authstar import AuthstarClient

        client = AuthstarClient(
            base_url="https://api.authstar.io",
            api_key="ask_abc123",
            tenant_id="tenant-uuid",
        )
        decision = client.authorize(
            action="agent:read_customer_data",
            subject="agent-abc",
            context={"resource": "customers", "task_id": "task-xyz"},
        )
        assert decision.allowed

    Using as a context manager to ensure the underlying transport is closed::

        with AuthstarClient(...) as client:
            decision = client.authorize("agent:write", "agent-001")
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        tenant_id: str,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._http = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "X-Tenant-ID": self._tenant_id,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"authstar-python/{_sdk_version()}",
            },
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "AuthstarClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP transport.  Idempotent."""
        self._http.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authorize(
        self,
        action: str,
        subject: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthzDecision:
        """Evaluate whether *subject* is permitted to perform *action*.

        Sends ``POST /api/v1/decisions`` with the supplied parameters and
        returns the EIAA capsule's authorization decision.

        Parameters
        ----------
        action:
            The EIAA action string, e.g. ``"agent:read_customer_data"`` or
            ``"data:write"``.
        subject:
            The identifier of the principal requesting the action (e.g. an
            ``agent_id`` or a user UUID).
        context:
            Arbitrary key/value pairs forwarded to the policy capsule as
            additional context.  Common keys include ``task_id``,
            ``resource``, ``delegation_chain``.

        Returns
        -------
        AuthzDecision
            Contains ``allowed``, ``decision_ref``, ``attestation_sig``, and
            ``reason``.

        Raises
        ------
        AuthstarAuthError
            On 401 / 403.
        AuthstarHTTPError
            On any other non-2xx response.
        httpx.TransportError
            On network-level failures (connection refused, timeout, etc.).
        """
        payload: Dict[str, Any] = {
            "action": action,
            "subject_id": subject,
            "context": context or {},
        }
        data = self._post(_DECISIONS_PATH, payload)
        return AuthzDecision(
            allowed=bool(data.get("allowed", False)),
            decision_ref=str(data.get("decision_ref", "")),
            attestation_sig=data.get("attestation_ref") or data.get("attestation_sig"),
            reason=data.get("reason"),
        )

    def revoke(self, agent_id: str) -> None:
        """Immediately revoke all active tokens for *agent_id*.

        Writes a Redis blocklist entry on the server so that any subsequent
        request bearing an agent JWT for this agent is denied.  The blocklist
        key expires automatically after the agent's registered
        ``token_ttl_seconds``.

        Parameters
        ----------
        agent_id:
            The ``agent_id`` of the principal to revoke.

        Returns
        -------
        None
            Returns silently on success (HTTP 204).

        Raises
        ------
        AuthstarNotFoundError
            If the agent does not exist in the tenant.
        AuthstarAuthError
            On 401 / 403.
        AuthstarHTTPError
            On any other non-2xx response.
        """
        path = _AGENTS_REVOKE_PATH.format(agent_id=agent_id)
        self._post(path, {}, expect_body=False)

    def get_task_chain(
        self,
        task_id: str,
        cursor: Optional[str] = None,
        limit: int = 50,
    ) -> TaskChainPage:
        """Retrieve a paginated page of EIAA execution records for *task_id*.

        Records are returned oldest-first so the causal execution chain can be
        reconstructed by iterating sequentially through pages.

        Parameters
        ----------
        task_id:
            The task identifier (set in the agent JWT when the token was
            issued).
        cursor:
            ISO-8601 timestamp from the previous page's ``next_cursor`` field.
            Omit to start from the beginning.
        limit:
            Maximum number of items per page (1–100, default 50).

        Returns
        -------
        TaskChainPage
            Contains ``items`` (list of :class:`TaskChainItem`) and
            ``next_cursor``.

        Raises
        ------
        AuthstarAuthError
            On 401 / 403.
        AuthstarHTTPError
            On any other non-2xx response.
        """
        path = _TASK_CHAIN_PATH.format(task_id=task_id)
        params: Dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        response = self._http.get(path, params=params)
        self._raise_for_status(response)

        raw = response.json()
        raw_items = raw.get("items", [])
        items = [TaskChainItem.model_validate(item) for item in raw_items]

        # next_cursor may be a datetime object or an ISO string
        next_cursor_raw = raw.get("next_cursor")
        next_cursor: Optional[str] = None
        if next_cursor_raw is not None:
            next_cursor = (
                next_cursor_raw.isoformat()
                if hasattr(next_cursor_raw, "isoformat")
                else str(next_cursor_raw)
            )

        return TaskChainPage(items=items, next_cursor=next_cursor)

    def verify_decision(self, decision_ref: str) -> VerificationResult:
        """Re-execute and verify a past authorization decision.

        The server replays the exact original inputs through the same EIAA
        capsule and compares the resulting decision against the one stored in
        the audit log.

        Parameters
        ----------
        decision_ref:
            The opaque decision reference string returned by
            :meth:`authorize`.

        Returns
        -------
        VerificationResult
            Contains ``verified``, ``original_decision``, ``replayed_decision``,
            ``decisions_match``, and ``status``.

        Raises
        ------
        AuthstarNotFoundError
            If the decision reference is unknown.
        AuthstarAuthError
            On 401 / 403.
        AuthstarHTTPError
            On any other non-2xx response.
        """
        path = _REEXECUTION_VERIFY_PATH.format(decision_ref=decision_ref)
        response = self._http.get(path)
        self._raise_for_status(response)

        raw = response.json()
        # The endpoint wraps the result in {"result": {...}}
        result_raw = raw.get("result", raw)

        r = _ReExecutionResult.model_validate(result_raw)
        return VerificationResult(
            verified=r.verification_status == "verified",
            original_decision=r.original_decision,
            replayed_decision=r.replayed_decision,
            decisions_match=r.decisions_match,
            status=r.verification_status,
        )

    def health(self) -> HealthStatus:
        """Check the liveness of the AuthStar API.

        Performs a single ``GET /health`` request (no authentication required)
        and returns a :class:`HealthStatus` capturing whether the server
        responded with 200 and the round-trip latency.

        Returns
        -------
        HealthStatus
            ``ok=True`` when the server returned HTTP 200.

        Raises
        ------
        httpx.TransportError
            On network-level failures.
        """
        t0 = time.monotonic()
        try:
            response = self._http.get(_HEALTH_PATH)
            latency_ms = (time.monotonic() - t0) * 1000
            ok = response.status_code == 200
            version: Optional[str] = None
            if ok:
                try:
                    version = response.json().get("version")
                except Exception:
                    pass
            return HealthStatus(ok=ok, latency_ms=round(latency_ms, 2), version=version)
        except httpx.TransportError:
            latency_ms = (time.monotonic() - t0) * 1000
            return HealthStatus(ok=False, latency_ms=round(latency_ms, 2))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(
        self,
        path: str,
        payload: Dict[str, Any],
        *,
        expect_body: bool = True,
    ) -> Dict[str, Any]:
        """POST *payload* to *path* and return the parsed JSON body."""
        response = self._http.post(path, json=payload)
        self._raise_for_status(response)
        if not expect_body:
            return {}
        return response.json()  # type: ignore[no-any-return]

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        """Raise an appropriate :class:`AuthstarHTTPError` subclass."""
        if response.is_success:
            return

        status = response.status_code
        try:
            body = response.text
        except Exception:
            body = None

        # Try to extract a human-readable message from the JSON body.
        message = f"AuthStar API error {status}"
        if body:
            try:
                detail = response.json()
                message = detail.get("message") or detail.get("error") or message
            except Exception:
                pass

        if status in (401, 403):
            raise AuthstarAuthError(message, status_code=status, response_body=body)
        if status == 404:
            raise AuthstarNotFoundError(message, status_code=status, response_body=body)
        if status == 429:
            raise AuthstarRateLimitError(message, status_code=status, response_body=body)
        raise AuthstarHTTPError(message, status_code=status, response_body=body)


def _sdk_version() -> str:
    """Return the installed SDK version string."""
    try:
        from authstar import __version__
        return __version__
    except Exception:
        return "unknown"
