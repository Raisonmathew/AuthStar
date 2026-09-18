from __future__ import annotations

"""
AuthStar Demo App — Python Agent Service

A minimal FastAPI service that exercises the Python SDK's AsyncAgentAuthz
against a live AuthStar backend. Playwright tests call this service's HTTP
endpoints to verify Python SDK behaviour (G-5 async, G-6 TTL refresh, G-1
audit chain queries).

Run:
    pip install -r requirements.txt
    uvicorn main:app --port 8001 --reload

Environment variables:
    AUTHSTAR_BASE_URL           default: http://localhost:3000
    ADMIN_EMAIL                 default: admin@example.com
    IDAAS_BOOTSTRAP_PASSWORD    required — set via environment, no default
"""
import hashlib
import json
import os
import sys
import time
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Add the Python SDK to the path (relative to this file)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../sdks/python'))
from idaas.agent import AsyncAgentAuthz, AgentAuthzDenied, AgentDecision  # noqa: E402

BASE_URL = os.environ.get('AUTHSTAR_BASE_URL', 'http://localhost:3000').rstrip('/')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
ADMIN_PASSWORD = os.environ.get('IDAAS_BOOTSTRAP_PASSWORD', '')
TEST_SEED_TOKEN = os.environ.get('TEST_SEED_TOKEN', '')

app = FastAPI(title='AuthStar Python Agent Sidecar', version='0.1.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)


# ---------------------------------------------------------------------------
# Admin JWT helper (walks the EIAA flow just like the Python integration tests)
# ---------------------------------------------------------------------------

async def get_admin_jwt() -> tuple[str, str]:
    """Return (jwt, org_id) for the bootstrap admin account."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        # CSRF
        csrf_resp = await client.get('/api/csrf-token')
        csrf_resp.raise_for_status()
        csrf_token = csrf_resp.json()['csrf_token']
        headers = {'X-CSRF-Token': csrf_token, 'Origin': BASE_URL}

        # Init flow
        init = await client.post('/api/auth/flow/init', json={'org_id': 'system'}, headers=headers)
        init.raise_for_status()
        flow = init.json()
        flow_headers = {**headers, 'Authorization': f"Bearer {flow['flow_token']}"}

        # Identify
        await client.post(f"/api/auth/flow/{flow['flow_id']}/identify",
                          json={'identifier': ADMIN_EMAIL}, headers=flow_headers)

        # Submit password
        submit = await client.post(f"/api/auth/flow/{flow['flow_id']}/submit",
                                   json={'capability': 'password', 'value': ADMIN_PASSWORD},
                                   headers=flow_headers)
        submit.raise_for_status()

        # Complete
        complete = await client.post(f"/api/auth/flow/{flow['flow_id']}/complete",
                                     headers=flow_headers)
        complete.raise_for_status()
        data = complete.json()
        jwt = data.get('jwt') or data.get('token', '')
        org_id = data.get('tenant_id') or data.get('org_id') or 'system'
        session_id = data.get('session_id')
        # Elevate to AAL3 so agent:manage routes pass (requires AAL2+)
        if session_id and TEST_SEED_TOKEN:
            await client.post('/api/test/elevate-session',
                              json={'session_id': session_id, 'aal_level': 3},
                              headers={'X-Test-Seed-Token': TEST_SEED_TOKEN,
                                       'Content-Type': 'application/json'})
        return jwt, org_id


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AuthorizeRequest(BaseModel):
    agent_id: str
    task_id: str
    tool_name: str
    args: dict = {}
    agent_token: Optional[str] = None


class RecordRequest(BaseModel):
    agent_id: str
    task_id: str
    tool_name: str
    allowed: bool
    agent_token: str


class HistoryRequest(BaseModel):
    agent_id: str
    task_id: str
    query_type: str = 'task'   # 'task' | 'agent'
    agent_token: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get('/health')
async def health():
    return {'status': 'ok', 'service': 'py-agent-sidecar'}


@app.post('/py/register-agent')
async def register_agent(body: dict):
    """Register an agent using admin credentials. Returns agent_id."""
    jwt, org_id = await get_admin_jwt()
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        res = await client.post(
            '/api/v1/agents/register',
            json=body,
            headers={'Authorization': f'Bearer {jwt}', 'Content-Type': 'application/json'},
        )
        res.raise_for_status()
        return res.json()


@app.post('/py/issue-token')
async def issue_token(body: dict):
    """Issue an agent token via admin JWT. Returns { token, expires_in }."""
    jwt, _ = await get_admin_jwt()
    agent_id = body.get('agent_id')
    task_id = body.get('task_id', f'task_{uuid.uuid4().hex[:8]}')
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        res = await client.post(
            '/api/v1/agents/token',
            json={'agent_id': agent_id, 'task_id': task_id},
            headers={'Authorization': f'Bearer {jwt}', 'Content-Type': 'application/json'},
        )
        res.raise_for_status()
        data = res.json()
        return {**data, 'task_id': task_id}


@app.post('/py/authorize')
async def py_authorize(req: AuthorizeRequest):
    """
    Authorize a tool call using AsyncAgentAuthz (G-5 async SDK path).

    Playwright tests call this endpoint and verify:
    - The response contains allowed + decision_ref
    - The asyncio event loop is not blocked (response arrives within timeout)
    """
    authz = AsyncAgentAuthz(
        tenant_id='system',
        api_key='',
        agent_id=req.agent_id,
        task_id=req.task_id,
        base_url=BASE_URL,
        agent_token=req.agent_token,
    )
    try:
        decision = await authz.authorize_tool_call(
            tool_name=req.tool_name,
            args=req.args,
        )
        return {
            'allowed': decision.allowed,
            'decision_ref': decision.decision_ref,
            'reason': decision.reason,
        }
    except AgentAuthzDenied as e:
        return {'allowed': False, 'decision_ref': None, 'reason': str(e)}
    finally:
        await authz.close()


@app.post('/py/record')
async def py_record(req: RecordRequest):
    """Record a tool execution via AsyncAgentAuthz."""
    authz = AsyncAgentAuthz(
        tenant_id='system',
        api_key='',
        agent_id=req.agent_id,
        task_id=req.task_id,
        base_url=BASE_URL,
        agent_token=req.agent_token,
    )
    try:
        execution = await authz.record_execution(
            tool_name=req.tool_name,
            allowed=req.allowed,
        )
        return {
            'execution_id': execution.execution_id,
            'tool_name': execution.tool_name,
            'task_id': execution.task_id,
        }
    finally:
        await authz.close()


@app.post('/py/history')
async def py_history(req: HistoryRequest):
    """
    Fetch task chain or agent history via AsyncAgentAuthz (G-1 fix verification).

    Playwright tests verify:
    - get_task_chain() returns paginated items
    - get_agent_history() returns paginated items
    - Both work without raw HTTP calls (SDK methods)
    """
    authz = AsyncAgentAuthz(
        tenant_id='system',
        api_key='',
        agent_id=req.agent_id,
        task_id=req.task_id,
        base_url=BASE_URL,
        agent_token=req.agent_token,
    )
    try:
        if req.query_type == 'task':
            result = await authz.get_task_chain()
        else:
            result = await authz.get_agent_history()
        # result is an AgentChainResponse dataclass or dict
        if hasattr(result, '__dict__'):
            return {'items': result.items if hasattr(result, 'items') else [], 'next_cursor': getattr(result, 'next_cursor', None)}
        return result
    finally:
        await authz.close()


@app.get('/py/agent-history/{agent_id}')
async def get_agent_history(agent_id: str, request: Request):
    """
    GET convenience endpoint for agent history.
    Used by Playwright 9.3 golden-path test.
    Calls GET /api/v1/audit/agent/:agent_id using the admin JWT from the request.
    """
    auth_header = request.headers.get('Authorization', '')
    org_id = request.headers.get('X-Org-Id', 'system')
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        res = await client.get(
            f'/api/v1/audit/agent/{agent_id}',
            headers={'Authorization': auth_header, 'X-Organization-Id': org_id},
        )
        if res.status_code == 200:
            return res.json()
        return {'items': [], 'next_cursor': None}


@app.get('/py/task-chain/{task_id}')
async def get_task_chain(task_id: str, request: Request):
    """
    GET convenience endpoint for task chain.
    Used by Playwright 8.11 Python SDK test.
    Calls GET /api/v1/audit/task/:task_id using the admin JWT from the request.
    """
    auth_header = request.headers.get('Authorization', '')
    org_id = request.headers.get('X-Org-Id', 'system')
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        res = await client.get(
            f'/api/v1/audit/task/{task_id}',
            headers={'Authorization': auth_header, 'X-Organization-Id': org_id},
        )
        if res.status_code == 200:
            return res.json()
        return {'items': [], 'next_cursor': None}




@app.post('/py/token-ttl-refresh-test')
async def ttl_refresh_test(body: dict):
    """
    G-6 fix verification: confirm _ensure_token() re-mints when token is near expiry.

    Accepts a pre-minted token with a very short TTL (or an already-expired one)
    and verifies the SDK transparently refreshes it before making the API call.
    Returns { refreshed: bool, decision_allowed: bool }.
    """
    agent_id = body.get('agent_id')
    task_id = body.get('task_id', f'task_ttl_{uuid.uuid4().hex[:8]}')
    old_token = body.get('old_token', '')
    tool_name = body.get('tool_name', 'web_search')

    # Build authz with the stale token — set _token_expires_at to 0 to
    # force immediate refresh on the next call.
    authz = AsyncAgentAuthz(
        tenant_id='system',
        api_key='',
        agent_id=agent_id,
        task_id=task_id,
        base_url=BASE_URL,
        agent_token=old_token,
    )
    # Force the TTL to appear expired (bypass cache)
    if hasattr(authz, '_token_expires_at'):
        authz._token_expires_at = 0  # type: ignore[assignment]

    try:
        decision = await authz.authorize_tool_call(tool_name=tool_name)
        current_token = authz._agent_token if hasattr(authz, '_agent_token') else None  # type: ignore[attr-defined]
        return {
            'refreshed': current_token != old_token,
            'decision_allowed': decision.allowed,
            'decision_ref': decision.decision_ref,
        }
    finally:
        await authz.close()
