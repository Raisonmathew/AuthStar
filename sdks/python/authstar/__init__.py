"""
authstar — Python SDK for the AuthStar AI Agent Authorization platform.

Usage::

    from authstar import AuthstarClient

    client = AuthstarClient(
        base_url="https://api.authstar.io",
        api_key="ask_...",
        tenant_id="your-tenant-id",
    )

    decision = client.authorize(action="agent:read_data", subject="agent-123")
    if decision.allowed:
        # proceed
        ...
"""

from authstar.client import AuthstarClient
from authstar.exceptions import (
    AuthstarError,
    AuthstarHTTPError,
    AuthstarAuthError,
    AuthstarNotFoundError,
    AuthstarRateLimitError,
)
from authstar.models import (
    AuthzDecision,
    TaskChainItem,
    TaskChainPage,
    VerificationResult,
    HealthStatus,
)

__version__ = "0.1.0"

__all__ = [
    # Client
    "AuthstarClient",
    # Models
    "AuthzDecision",
    "TaskChainItem",
    "TaskChainPage",
    "VerificationResult",
    "HealthStatus",
    # Exceptions
    "AuthstarError",
    "AuthstarHTTPError",
    "AuthstarAuthError",
    "AuthstarNotFoundError",
    "AuthstarRateLimitError",
    # Metadata
    "__version__",
]
