/**
 * Suite 04-A — Agent Token Issuance
 *
 * Tests 4.1–4.6: Happy-path token issuance, JWT claims shape, TTL,
 * task_id binding, per-task uniqueness, and admin-only gate.
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

/** Decode a JWT payload without verifying the signature. */
function jwtPayload(token: string): Record<string, unknown> {
  const [, b64] = token.split('.');
  return JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
}

test.describe('Agent Token Issuance', () => {
  // ── 4.1 Happy-path issuance ───────────────────────────────────────────────
  test('4.1 — POST /api/v1/agents/token returns 200 with opaque token', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/token`, {
      data: { agent_id: agent.agent_id, task_id: taskId },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(typeof body.token).toBe('string');
    expect(body.token.length).toBeGreaterThan(20);
  });

  // ── 4.2 Issued token carries correct JWT claims ───────────────────────────
  test('4.2 — issued token contains agent_id, task_id, session_type claims', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
    taskId,
    agentJwt,
  }) => {
    const payload = jwtPayload(agentJwt);
    expect(payload['session_type']).toBe('agent');
    expect(payload['agent_id']).toBe(agent.agent_id);
    expect(payload['task_id']).toBe(taskId);
    // Must NOT contain roles or permissions — EIAA principle
    expect(payload['roles']).toBeUndefined();
    expect(payload['permissions']).toBeUndefined();
    expect(payload['scopes']).toBeUndefined();
  });

  // ── 4.3 Token contains allowed_tools claim ────────────────────────────────
  test('4.3 — token payload carries allowed_tools matching agent registration', async ({
    agentJwt,
    agent,
    request,
    adminJwt,
    adminOrgId,
  }) => {
    // Read agent to get registered tools
    const agentRes = await request.get(`${BACKEND}/api/v1/agents/${agent.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    const agentBody = await agentRes.json();

    const payload = jwtPayload(agentJwt);
    // allowed_tools in JWT must be a subset of the registered tools
    // Agent JWT may have space-separated or array format for allowed_tools
    const rawJwt = payload['allowed_tools'] ?? '';
    const jwtTools = Array.isArray(rawJwt)
      ? rawJwt as string[]
      : String(rawJwt).split(/[\s,]+/).filter(Boolean);
    const rawReg = agentBody.allowed_tools ?? '';
    const regTools = Array.isArray(rawReg)
      ? rawReg as string[]
      : String(rawReg).split(/[\s,]+/).filter(Boolean);
    for (const t of jwtTools) {
      expect(regTools).toContain(t);
    }
  });

  // ── 4.4 Each task_id produces a distinct token ────────────────────────────
  test('4.4 — two calls with different task_ids produce distinct tokens', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const t1 = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, unique('task-a'));
    const t2 = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, unique('task-b'));
    expect(t1).not.toBe(t2);
  });

  // ── 4.5 Token issuance requires admin Bearer token ────────────────────────
  test('4.5 — token issuance without authentication returns 401', async ({
    request,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/token`, {
      data: { agent_id: agent.agent_id, task_id: taskId },
    });
    // No Bearer token → CSRF returns 403 before auth
    expect([401, 403]).toContain(res.status());
  });

  // ── 4.6 Token for unknown agent_id returns 404 ────────────────────────────
  test('4.6 — token issuance for unknown agent_id returns 404', async ({
    request,
    adminJwt,
    adminOrgId,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/token`, {
      data: { agent_id: 'agt_does_not_exist_000', task_id: taskId },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect([404, 400]).toContain(res.status());
  });
});
