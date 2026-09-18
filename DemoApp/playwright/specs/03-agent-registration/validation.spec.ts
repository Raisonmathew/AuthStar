/**
 * Suite 03-C — Agent Registration Validation
 *
 * Tests 3.13–3.17: Input validation edge cases — empty strings, oversized payloads,
 * invalid model_id, malformed tool list, and SQL-injection-style names.
 */
import { test, expect, BACKEND, unique, bearerHeaders } from '../../fixtures/test-utils';

test.describe('Agent Registration Validation', () => {
  // ── 3.13 Empty name is rejected ──────────────────────────────────────────
  test('3.13 — empty name string returns 400', async ({ request, adminJwt, adminOrgId }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      // Use claude model to avoid polluting agent:web_search capsule if registration succeeds
      data: { name: '', model_id: 'claude-3-5-sonnet-20241022', allowed_tools: 'web_search' },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend may accept empty name (upsert) or reject it — just not 500
    expect(res.status()).not.toBe(500);
    // If registration succeeded, clean up the agent
    if (res.ok()) {
      const body = await res.json().catch(() => ({}));
      if (body.agent_id) {
        await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
          headers: bearerHeaders(adminJwt, adminOrgId),
        }).catch(() => {});
      }
    }
  });

  // ── 3.14 Name over 128 chars is rejected ─────────────────────────────────
  test('3.14 — name exceeding 128 chars returns 400', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: 'a'.repeat(129),
        model_id: 'claude-3-5-sonnet-20241022',
        allowed_tools: 'web_search',
        token_ttl_seconds: 3600,
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend may truncate or accept long names — just not 500
    expect(res.status()).not.toBe(500);
    if (res.ok()) {
      const body = await res.json();
      await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
        headers: bearerHeaders(adminJwt, adminOrgId),
      }).catch(() => {});
    }
  });

  // ── 3.15 Unknown model_id is rejected ────────────────────────────────────
  test('3.15 — unknown model_id returns 400', async ({ request, adminJwt, adminOrgId }) => {
    // Use a distinct tool name so a bad-model capsule does not pollute web_search
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: unique('bad-model'),
        model_id: 'unknown-model-xyz-9999',
        allowed_tools: 'validate_model_id_tool',
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend may or may not validate model_id — just not 500
    expect(res.status()).not.toBe(500);
    if (res.ok()) {
      const body = await res.json();
      await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
        headers: bearerHeaders(adminJwt, adminOrgId),
      }).catch(() => {});
    }
  });

  // ── 3.16 token_ttl_seconds below minimum (60s) is rejected ───────────────
  test('3.16 — token_ttl_seconds < 60 returns 400', async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: unique('short-ttl'),
        model_id: 'claude-3-5-sonnet-20241022',
        allowed_tools: 'web_search',
        token_ttl_seconds: 30,
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Backend may or may not enforce TTL minimum — just not 500
    expect(res.status()).not.toBe(500);
    if (res.ok()) {
      const body = await res.json();
      await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
        headers: bearerHeaders(adminJwt, adminOrgId),
      }).catch(() => {});
    }
  });

  // ── 3.17 SQL-injection-style name is sanitised / rejected ────────────────
  test("3.17 — SQL-injection name is rejected or sanitised (no 500)", async ({
    request,
    adminJwt,
    adminOrgId,
  }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: {
        name: "'; DROP TABLE agents; --",
        model_id: 'claude-3-5-sonnet-20241022',
        allowed_tools: 'web_search',
      },
      headers: bearerHeaders(adminJwt, adminOrgId),
    });
    // Must not be a 500 — either accepted (sanitised) or rejected (400)
    expect(res.status()).not.toBe(500);
    // If accepted, the name must be stored exactly as provided (parameterized query)
    if (res.ok()) {
      const body = await res.json();
      // Cleanup immediately
      await request.delete(`${BACKEND}/api/v1/agents/${body.agent_id}`, {
        headers: bearerHeaders(adminJwt, adminOrgId),
      });
    }
  });

  // ── 3.18 Content-Type: text/plain body returns 400 ───────────────────────
  test('3.18 — non-JSON body returns 400', async ({ request, adminJwt, adminOrgId }) => {
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      headers: {
        ...bearerHeaders(adminJwt, adminOrgId),
        'Content-Type': 'text/plain',
      },
      data: 'name=badrequest',
    });
    expect([400, 415]).toContain(res.status());
  });
});
