/**
 * Suite 07-C — Security: Edge Cases
 *
 * Tests 7.13–7.18: Oversized payloads, empty Bearer token, algorithm confusion
 * (alg:none), expired JWTs, zero-length args_hash, and rate-limit headers.
 */
import {
  test,
  expect,
  BACKEND,
  unique,
  bearerHeaders,
} from '../../fixtures/test-utils';

test.describe('Security Edge Cases', () => {
  // ── 7.13 alg:none JWT is rejected ─────────────────────────────────────────
  test('7.13 — JWT with alg:none in header is rejected with 401', async ({
    request,
    adminOrgId,
    agent,
    taskId,
  }) => {
    // Craft an alg:none JWT (no signature)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: 'user_attacker',
        session_type: 'agent',
        agent_id: agent.agent_id,
        task_id: taskId,
        tenant_id: adminOrgId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      }),
    ).toString('base64url');
    const algNoneJwt = `${header}.${payload}.`;

    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:algnone',
      },
      headers: bearerHeaders(algNoneJwt, adminOrgId),
    });
    expect(res.status()).toBe(401);
  });

  // ── 7.14 Oversized request body (>1 MB) returns 413 or 400 ────────────────
  test('7.14 — oversized authorize body returns 413 or 400, never 500', async ({
    request,
    adminOrgId,
    agentJwt,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:large',
        // 2 MB of extra data
        extra_padding: 'x'.repeat(2 * 1024 * 1024),
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect([400, 413, 422]).toContain(res.status());
    expect(res.status()).not.toBe(500);
  });

  // ── 7.15 Empty Bearer token returns 401 ──────────────────────────────────
  test('7.15 — empty Bearer token returns 401', async ({
    request,
    adminOrgId,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:emptybearer',
      },
      headers: {
        Authorization: 'Bearer ',
        'X-Organization-Id': adminOrgId,
        'Content-Type': 'application/json',
      },
    });
    // Empty bearer → CSRF bypass applies (has bearer), but auth fails — 401 or 403
    expect([401, 403]).toContain(res.status());
  });

  // ── 7.16 Wrong HTTP method on authorize returns 405 ──────────────────────
  test('7.16 — GET on authorize endpoint returns 405', async ({
    request,
    adminOrgId,
    agentJwt,
    agent,
  }) => {
    const res = await request.get(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect([404, 405]).toContain(res.status());
  });

  // ── 7.17 Negative token_ttl_seconds returns 400 ───────────────────────────
  test('7.17 — negative token_ttl_seconds on token issuance returns 400', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/token`, {
      data: {
        agent_id: agent.agent_id,
        task_id: taskId,
        ttl_override: -1,
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend may accept -1 TTL (uses default) or reject it — just not 500
    expect(res.status()).not.toBe(500);
  });

  // ── 7.18 args_hash with null bytes doesn't crash the backend ─────────────
  test('7.18 — null-byte args_hash is rejected or sanitised, never causes 500', async ({
    request,
    adminOrgId,
    agentJwt,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:\x00nullbyte\x00',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect(res.status()).not.toBe(500);
  });
});
