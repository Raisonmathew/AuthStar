"""
authstar.exceptions — SDK-specific exception hierarchy.

All exceptions raised by :class:`~authstar.client.AuthstarClient` derive from
:class:`AuthstarError` so callers can catch the base class for blanket handling
or use the sub-classes for fine-grained error recovery.

Example::

    from authstar import AuthstarClient
    from authstar.exceptions import AuthstarAuthError, AuthstarRateLimitError

    client = AuthstarClient(base_url=..., api_key=..., tenant_id=...)

    try:
        decision = client.authorize("agent:write", "agent-abc")
    except AuthstarAuthError:
        # 401 / 403 — check API key and tenant ID
        raise
    except AuthstarRateLimitError:
        # 429 — back off and retry
        time.sleep(1)
"""

from __future__ import annotations

from typing import Optional


class AuthstarError(Exception):
    """Base class for all errors raised by the authstar SDK."""


class AuthstarHTTPError(AuthstarError):
    """Raised when the server responds with an unexpected HTTP status code.

    Attributes:
        status_code: The HTTP status code returned by the server.
        response_body: The raw response body text, if available.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"status_code={self.status_code!r}, "
            f"message={str(self)!r})"
        )


class AuthstarAuthError(AuthstarHTTPError):
    """Raised on HTTP 401 (Unauthorized) or 403 (Forbidden).

    Typical causes:
    - Missing or invalid ``api_key``.
    - The API key does not belong to the given ``tenant_id``.
    - The agent has been revoked.
    """


class AuthstarNotFoundError(AuthstarHTTPError):
    """Raised on HTTP 404.

    Typical causes:
    - The ``agent_id`` passed to :meth:`~authstar.client.AuthstarClient.revoke`
      does not exist in the tenant.
    - The ``decision_ref`` or ``task_id`` is unknown.
    """


class AuthstarRateLimitError(AuthstarHTTPError):
    """Raised on HTTP 429 (Too Many Requests).

    The caller should back off and retry.  A ``Retry-After`` header may be
    present in the server response when available.
    """
