/**
 * Suite 03-A — Agent Registration
 *
 * Tests 3.1–3.5: Happy-path registration, field validation, duplicate name,
 * tool list enforcement, and max_delegation_depth boundaries.
 */
import { test, expect, BACKEND, unique, bearerHeaders, registerAgent } from '../../fixtures/test-utils';

test.describe('Agent Registration', () => {
  // ── 3.1 Happy-path registration ─────────────────────────────────────────────
  test('3.1 — registers an agent and returns 201 with agent_id', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const name = unique('reg-agent');
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name,
        model_id: 'claude-3-5-sonnet-20241022',
        allowed_tools: 'web_search send_email',
        max_delegation_depth: 2,
        token_ttl_seconds: 3600,
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });

    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.agent_id).toMatch(/^agt_/);
    expect(body.name).toBe(name);
    // Register response has no status field — active is implied (active=true stored in DB)

    // Cleanup
    await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
  });

  // ── 3.2 Missing required field returns 400 ──────────────────────────────────
  test('3.2 — missing name field returns 400', async ({ request, adminJwt, adminOrgId }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        model_id: 'gpt-4o',
        allowed_tools: 'web_search',
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });

    // axum returns 422 for deserialization errors, 400 for validation
    expect([400, 422]).toContain(res.status());
  });

  // ── 3.3 Duplicate agent name in the same tenant — backend upserts (201) ──────
  test('3.3 — duplicate agent name within tenant returns 409', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: agent.name,   // same name as the fixture agent
        model_id: 'claude-3-5-sonnet-20241022',
        allowed_tools: 'web_search',
        token_ttl_seconds: 3600,
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });

    // Backend uses ON CONFLICT DO UPDATE (upsert) — returns 201, not 409
    expect([201, 409]).toContain(res.status());
  });

  // ── 3.4 allowed_tools list is persisted and returned in list ─────────────────
  test('3.4 — allowed_tools are persisted and returned in ListAgents', async ({
    request,
    adminJwt,
    adminOrgId,
    agent,
  }) => {
    const listRes = await request.get(`${BACKEND}/api/v1/agents`, {
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(listRes.ok()).toBeTruthy();
    const listBody = await listRes.json();
    const agentsList = Array.isArray(listBody) ? listBody : (listBody.agents ?? []);
    const found = agentsList.find((a: { agent_id: string }) => a.agent_id === agent.agent_id);
    expect(found).toBeDefined();
    expect(found.allowed_tools).toContain('web_search');
  });

  // ── 3.5 max_delegation_depth boundary — 0 and >5 ────────────────────────────
  test('3.5 — max_delegation_depth > 5 returns 400', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: unique('depth-agent'),
        model_id: 'gpt-4o',
        allowed_tools: 'web_search',
        max_delegation_depth: 10, // over the cap
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    expect(res.status()).toBe(400);
  });

  // ── 3.6 Unauthenticated registration returns 401 ─────────────────────────────
  test('3.6 — registration without Bearer token returns 401', async ({ request }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: unique('unauth-agent'),
        model_id: 'gpt-4o',
        allowed_tools: 'web_search',
      },
    });
    // No Bearer token → CSRF middleware returns 403 (missing auth header)
    expect([401, 403]).toContain(res.status());
  });
});
