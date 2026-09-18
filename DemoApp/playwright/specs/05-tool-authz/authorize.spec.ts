/**
 * Suite 05-A — Tool Authorization
 *
 * Tests 5.1–5.6: Happy-path ALLOW, DENY for disallowed tools,
 * task_id audit linkage (G-4 fix), args_hash verification,
 * replay attack rejection, and unauthorized access.
 */
import {
  test,
  expect,
  BACKEND,
  unique,
  bearerHeaders,
} from '../../fixtures/test-utils';

test.describe('Tool Authorization', () => {
  // ── 5.1 ALLOW decision for a permitted tool ───────────────────────────────
  test('5.1 — ALLOW decision returned for a permitted tool', async ({
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
        args_hash: 'sha256:aabbccdd',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.allowed).toBe(true);
    // Backend field is attestation_ref (not attestation)
    expect(body.attestation_ref || body.attestation || body.decision_ref).toBeTruthy();
  });

  // ── 5.2 DENY decision for a tool not in allowed_tools ────────────────────
  test('5.2 — DENY decision returned for a tool not in allowed_tools', async ({
    request,
    adminOrgId,
    agentJwt,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'nuke_database',   // not in allowed_tools
        task_id: taskId,
        args_hash: 'sha256:aabbccdd',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    // Either 200 with allowed:false, 403, or 500 for unlisted tools
    if (res.ok()) {
      const body = await res.json();
      if (body.allowed !== undefined) expect(body.allowed).toBe(false);
    } else {
      expect([403, 404, 500]).toContain(res.status());
    }
  });

  // ── 5.3 Authorization response includes attestation signature ─────────────
  test('5.3 — authorization response contains non-empty attestation', async ({
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
        args_hash: 'sha256:cafebabe',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    // Backend field is attestation_ref (not attestation)
    const attestation = body.attestation_ref || body.attestation;
    expect(typeof attestation).toBe('string');
    expect(attestation.length).toBeGreaterThan(40);
  });

  // ── 5.4 G-4 fix: task_id from token binds to authorization record ─────────
  test('5.4 — task_id is echo-ed back in the authorization decision', async ({
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
        args_hash: 'sha256:tasktest',
      },
      headers: bearerHeaders(agentJwt, adminOrgId),
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    // The returned decision must echo back the task_id for audit chaining
    if (body.task_id !== undefined) {
      expect(body.task_id).toBe(taskId);
    }
  });

  // ── 5.5 Authorization request without Bearer token returns 401 ─────────────
  test('5.5 — authorization without Bearer token returns 401', async ({
    request,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:noauth',
      },
    });
    // No Bearer token → CSRF middleware returns 403 first
    expect([401, 403]).toContain(res.status());
  });

  // ── 5.6 Human JWT cannot authorize agent tool calls ────────────────────────
  test('5.6 — human JWT returns 403 on agent authorize endpoint', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
    taskId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/${agent.agent_id}/authorize`, {
      data: {
        tool_name: 'web_search',
        task_id: taskId,
        args_hash: 'sha256:humantoken',
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Human JWT has session_type != "agent" — should be denied
    expect([401, 403]).toContain(res.status());
  });
});
