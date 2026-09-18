/**
 * Suite 03-B — Agent Lifecycle Management
 *
 * Tests 3.7–3.12: ListAgents, GetAgent, UpdateAgent, DeactivateAgent,
 * RevokeAgentTokens, and cross-tenant isolation.
 */
import {
  test,
  expect,
  BACKEND,
  unique,
  bearerHeaders,
  registerAgent,
  issueAgentToken,
} from '../../fixtures/test-utils';

test.describe('Agent Lifecycle', () => {
  // ── 3.7 ListAgents returns paginated results ──────────────────────────────
  test('3.7 — ListAgents returns the registered agent in the list', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const res = await request.get(`${BACKEND}/api/v1/agents`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    // Backend returns agents directly as an array or wrapped in { agents: [...] }
    const agents = Array.isArray(body) ? body : (body.agents ?? []);
    expect(Array.isArray(agents)).toBe(true);
    const found = agents.find((a: { agent_id: string }) => a.agent_id === agent.agent_id);
    expect(found).toBeDefined();
  });

  // ── 3.8 GetAgent returns the correct record ───────────────────────────────
  test('3.8 — GetAgent returns the correct agent record', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const res = await request.get(`${BACKEND}/api/v1/agents/${agent.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.agent_id).toBe(agent.agent_id);
    expect(body.name).toBe(agent.name);
    // Backend returns active=true (boolean), not status='active' string
    expect(body.active).toBe(true);
  });

  // ── 3.9 UpdateAgent patches allowed_tools ────────────────────────────────
  test('3.9 — UpdateAgent patches allowed_tools and persists', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    // Backend uses PUT, not PATCH, for agent updates
    const patchRes = await request.put(`${BACKEND}/api/v1/agents/${agent.agent_id}`, {
      data: { allowed_tools: 'web_search send_email make_payment read_calendar' },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(patchRes.ok()).toBeTruthy();

    // Read back and verify
    const getRes = await request.get(`${BACKEND}/api/v1/agents/${agent.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    const body = await getRes.json();
    expect(body.allowed_tools).toContain('make_payment');
    expect(body.allowed_tools).toContain('read_calendar');
  });

  // ── 3.10 DeactivateAgent transitions status to "inactive" ────────────────
  test('3.10 — DeactivateAgent transitions agent to inactive', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    // Create a dedicated agent for this test (fixture agent is auto-cleaned but
    // we need to observe the transition, not use the fixture's cleanup)
    const a = await registerAgent(request, adminJwt, adminOrgId);

    const delRes = await request.delete(`${BACKEND}/api/v1/agents/${a.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(delRes.ok()).toBeTruthy();

    // Status should be inactive (soft-delete)
    const getRes = await request.get(`${BACKEND}/api/v1/agents/${a.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend soft-deletes: GET on an inactive agent returns 404 (active=FALSE filtered)
    expect(getRes.status()).toBe(404);
  });

  // ── 3.11 RevokeAgentTokens invalidates existing tokens ───────────────────
  test('3.11 — RevokeAgentTokens makes outstanding tokens return 401', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
    taskId,
  }) => {
    // Issue a token first
    const token = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, taskId);
    expect(token).toBeTruthy();

    // Revoke all tokens for this agent
    const revokeRes = await request.post(
      `${BACKEND}/api/v1/agents/${agent.agent_id}/revoke`,
      { headers: bearerHeaders(adminJwt, adminOrgId) },
    );
    expect(revokeRes.ok()).toBeTruthy();

    // The revoked token should no longer authorize a tool call
    const authzRes = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'abc123',
      },
      headers: bearerHeaders(token, adminOrgId),
    });
    // Revoked token → backend returns 403 (forbidden) or 401 (unauthorized)
    expect([401, 403]).toContain(authzRes.status());
  });

  // ── 3.12 Deleted agent cannot issue new tokens ────────────────────────────
  test('3.12 — token issuance fails for deactivated agent', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const a = await registerAgent(request, adminJwt, adminOrgId);

    // Deactivate
    await request.delete(`${BACKEND}/api/v1/agents/${a.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });

    // Try to issue token — should fail
    const tokenRes = await request.post(`${BACKEND}/api/v1/agents/token`, {
      data: { agent_id: a.agent_id, task_id: unique('task') },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect([400, 404, 422]).toContain(tokenRes.status());
  });
});
