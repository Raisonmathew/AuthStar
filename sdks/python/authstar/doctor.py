"""
authstar.doctor — CLI health-check command.

Usage
-----
::

    authstar doctor [--url URL] [--api-key KEY] [--tenant-id TENANT]

Environment variable fallbacks
-------------------------------
``AUTHSTAR_URL``, ``AUTHSTAR_API_KEY``, ``AUTHSTAR_TENANT_ID``

Checks performed
----------------
1. **Liveness** — ``GET /health``               (no auth required)
2. **Readiness** — ``GET /health/ready``         (no auth required)
3. **Identity** — ``GET /api/v1/user``           (Bearer auth)

Each check prints ``PASS`` or ``FAIL`` with the latency and any relevant info.
The exit code is 0 when all checks pass, 1 when any check fails.

Example output
--------------
::

    AuthStar Doctor
    ===============
    URL       : https://api.authstar.io
    Tenant    : tenant-abc123
    SDK ver   : 0.1.0

    [1/3] Liveness  (GET /health)
          ✓ PASS  200  12.3 ms  version=2.4.1

    [2/3] Readiness (GET /health/ready)
          ✓ PASS  200  8.7 ms

    [3/3] Identity  (GET /api/v1/user)
          ✓ PASS  200  15.2 ms  user=alice@example.com

    All checks passed.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

import httpx


def _check_liveness(base_url: str, timeout: float) -> tuple[bool, float, Optional[str]]:
    """GET /health — returns (passed, latency_ms, version_or_None)."""
    url = f"{base_url}/health"
    t0 = time.monotonic()
    try:
        resp = httpx.get(url, timeout=timeout)
        latency = (time.monotonic() - t0) * 1000
        ok = resp.status_code == 200
        version: Optional[str] = None
        if ok:
            try:
                version = resp.json().get("version")
            except Exception:
                pass
        return ok, round(latency, 1), version
    except Exception as exc:
        latency = (time.monotonic() - t0) * 1000
        return False, round(latency, 1), str(exc)


def _check_readiness(base_url: str, timeout: float) -> tuple[bool, float]:
    """GET /health/ready — returns (passed, latency_ms)."""
    url = f"{base_url}/health/ready"
    t0 = time.monotonic()
    try:
        resp = httpx.get(url, timeout=timeout)
        latency = (time.monotonic() - t0) * 1000
        return resp.status_code == 200, round(latency, 1)
    except Exception as exc:
        latency = (time.monotonic() - t0) * 1000
        return False, round(latency, 1)


def _check_identity(
    base_url: str,
    api_key: str,
    tenant_id: Optional[str],
    timeout: float,
) -> tuple[bool, float, Optional[str]]:
    """GET /api/v1/user — returns (passed, latency_ms, email_or_error)."""
    url = f"{base_url}/api/v1/user"
    headers = {"Authorization": f"Bearer {api_key}"}
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id
    t0 = time.monotonic()
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        latency = (time.monotonic() - t0) * 1000
        if resp.status_code == 200:
            try:
                data = resp.json()
                email = data.get("email") or data.get("user", {}).get("email")
            except Exception:
                email = None
            return True, round(latency, 1), email
        return False, round(latency, 1), f"HTTP {resp.status_code}"
    except Exception as exc:
        latency = (time.monotonic() - t0) * 1000
        return False, round(latency, 1), str(exc)


def _sdk_version() -> str:
    try:
        from authstar import __version__
        return __version__
    except Exception:
        return "unknown"


def _print_check_header(index: int, total: int, label: str, endpoint: str) -> None:
    print(f"\n[{index}/{total}] {label:<12} ({endpoint})")


def _print_result(passed: bool, status_str: str) -> None:
    symbol = "✓" if passed else "✗"
    tag = "PASS" if passed else "FAIL"
    print(f"      {symbol} {tag}  {status_str}")


def run_doctor(
    base_url: str,
    api_key: Optional[str],
    tenant_id: Optional[str],
    timeout: float = 10.0,
) -> int:
    """Execute all doctor checks.  Returns exit code (0 = all pass, 1 = any fail)."""
    base_url = base_url.rstrip("/")

    print("AuthStar Doctor")
    print("===============")
    print(f"  URL       : {base_url}")
    if tenant_id:
        print(f"  Tenant    : {tenant_id}")
    if api_key:
        masked = api_key[:8] + "..." if len(api_key) > 8 else "***"
        print(f"  API Key   : {masked}")
    print(f"  SDK ver   : {_sdk_version()}")

    all_passed = True
    total = 3 if api_key else 2

    # ── Check 1: Liveness ────────────────────────────────────────────────
    _print_check_header(1, total, "Liveness", "GET /health")
    passed, latency, version = _check_liveness(base_url, timeout)
    all_passed = all_passed and passed
    suffix = f"version={version}" if version else ""
    _print_result(passed, f"{'200' if passed else 'ERR'}  {latency} ms  {suffix}".strip())

    # ── Check 2: Readiness ───────────────────────────────────────────────
    _print_check_header(2, total, "Readiness", "GET /health/ready")
    passed, latency = _check_readiness(base_url, timeout)
    all_passed = all_passed and passed
    _print_result(passed, f"{'200' if passed else 'ERR'}  {latency} ms")

    # ── Check 3: Identity (only when an API key is provided) ─────────────
    if api_key:
        _print_check_header(3, total, "Identity", "GET /api/v1/user")
        passed, latency, info = _check_identity(base_url, api_key, tenant_id, timeout)
        all_passed = all_passed and passed
        detail = f"user={info}" if (passed and info) else (info or "")
        _print_result(passed, f"{'200' if passed else 'ERR'}  {latency} ms  {detail}".strip())

    print()
    if all_passed:
        print("All checks passed.")
    else:
        print("One or more checks FAILED.", file=sys.stderr)

    return 0 if all_passed else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authstar doctor",
        description=(
            "Verify connectivity to an AuthStar API endpoint.\n\n"
            "Environment variable fallbacks: AUTHSTAR_URL, AUTHSTAR_API_KEY, "
            "AUTHSTAR_TENANT_ID."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("AUTHSTAR_URL", "https://api.authstar.io"),
        metavar="URL",
        help="Base URL of the AuthStar API (default: %(default)s).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("AUTHSTAR_API_KEY"),
        metavar="KEY",
        help="AuthStar API key (ask_...).  Required for the identity check.",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("AUTHSTAR_TENANT_ID"),
        metavar="TENANT",
        help="Tenant UUID (optional; adds X-Tenant-ID header to identity check).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Per-request HTTP timeout in seconds (default: %(default)s).",
    )
    return parser


def main() -> None:
    """Entry point for the ``authstar`` CLI command."""
    parser = _build_parser()
    args = parser.parse_args()

    # Support `authstar doctor` as a sub-command or plain `authstar`
    # (the pyproject.toml entry point maps `authstar` → `authstar.doctor:main`).
    exit_code = run_doctor(
        base_url=args.url,
        api_key=args.api_key,
        tenant_id=args.tenant_id,
        timeout=args.timeout,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
