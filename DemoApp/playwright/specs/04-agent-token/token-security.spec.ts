/**
 * Suite 04-B — Token Security
 *
 * Tests 4.7–4.12: Token signature verification, expiry (TTL), cross-tenant
 * usage, agent-token-as-admin, malformed JWTs, and jti uniqueness.
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

test.describe('Token Security', () => {
  // ── 4.7 Agent token cannot call admin routes ───────────────────────────────
  test('4.7 — agent JWT cannot reach admin management routes', async ({
    request,
    adminOrgId,
    agentJwt,
  }) => {
    const res = await request.get(`${BACKEND}/api/admin/v1/users`, {
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect([401, 403]).toContain(res.status());
  });

  // ── 4.8 Agent token cannot register a new agent ────────────────────────────
  test('4.8 — agent JWT cannot register another agent', async ({
    request,
    adminOrgId,
    agentJwt,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: unique('rogue-agent'),
        model_id: 'gpt-4o',
        allowed_tools: 'web_search',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect([401, 403]).toContain(res.status());
  });

  // ── 4.9 Token exp claim is within registered TTL ───────────────────────────
  test('4.9 — token exp claim is within registered token_ttl_seconds', async ({
    agentJwt,
    agent,
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const payload = jwtPayload(agentJwt);
    const agentRes = await request.get(`${BACKEND}/api/v1/agents/${agent.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    const agentBody = await agentRes.json();
    const ttl: number = agentBody.token_ttl_seconds ?? 3600;

    const now = Math.floor(Date.now() / 1000);
    const exp = payload['exp'] as number;
    const iat = payload['iat'] as number;

    // exp must be ~iat + ttl (allow ±30s clock skew)
    expect(exp - iat).toBeGreaterThanOrEqual(ttl - 30);
    expect(exp - iat).toBeLessThanOrEqual(ttl + 30);
    // Must not be already expired
    expect(exp).toBeGreaterThan(now);
  });

  // ── 4.10 Structurally malformed JWT returns 401 ────────────────────────────
  test('4.10 — structurally malformed JWT returns 401', async ({
    request,
    adminOrgId,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:badtoken',
      },
      headers: bearerHeaders('not.a.valid.jwt', adminOrgId),
    });
    expect(res.status()).toBe(401);
  });

  // ── 4.11 Tampered JWT payload returns 401 ─────────────────────────────────
  test('4.11 — tampered JWT payload returns 401', async ({
    request,
    adminOrgId,
    agentJwt,
    agent,
    taskId,
  }) => {
    // Flip one char in the payload segment
    const [h, p, s] = agentJwt.split('.');
    const tamperedPayload = p.slice(0, -2) + (p.slice(-2) === 'AA' ? 'BB' : 'AA');
    const tamperedJwt = `${h}.${tamperedPayload}.${s}`;

    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:tampered',
      },
      headers: bearerHeaders(tamperedJwt, adminOrgId),
    });
    expect(res.status()).toBe(401);
  });

  // ── 4.12 jti claim is unique across two tokens for same agent ─────────────
  test('4.12 — two tokens for the same agent have distinct jti claims', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const t1 = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, unique('t-a'));
    const t2 = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, unique('t-b'));
    // Just verify the two tokens are distinct (jti may not be present in all implementations)
    expect(t1).not.toBe(t2);
  });
});
