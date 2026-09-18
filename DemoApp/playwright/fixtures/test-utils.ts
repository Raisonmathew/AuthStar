/**
 * DemoApp Playwright — shared test fixtures and helpers
 *
 * Mirrors the patterns from frontend/tests/fixtures/test-utils.ts but
 * targets the DemoApp (port 4000) and the AuthStar backend (port 3000)
 * directly for API tests.
 */
import { test as base, expect, type Page, type APIRequestContext } from '@playwright/test';

export { expect };

// ─── Environment constants ──────────────────────────────────────────────────

export const BACKEND = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';
export const PY_SIDECAR = process.env.PYTHON_AGENT_SERVICE_URL || 'http://localhost:8001';
export const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
// IDAAS_BOOTSTRAP_PASSWORD must be set via environment (GitHub Actions secret in CI,
// or a local .env file when running locally). No hardcoded fallback — tests that
// require admin credentials will skip or fail fast if the variable is absent.
export const ADMIN_PASSWORD = process.env.IDAAS_BOOTSTRAP_PASSWORD ?? '';
export const SEED_TOKEN = process.env.TEST_SEED_TOKEN || 'dev-test-seed-token-change-for-staging';

// ─── Unique ID helper ────────────────────────────────────────────────────────

export function unique(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
}

// ─── EIAA auth-flow walker ───────────────────────────────────────────────────

/**
 * Obtain an admin Bearer JWT by walking the EIAA auth flow against the backend.
 * Uses page.request so cookies and CSRF tokens land in the Playwright context.
 *
 * Steps:
 *   1. GET  /api/csrf-token
 *   2. POST /api/auth/flow/init        → flow_id + flow_token
 *   3. POST /api/auth/flow/:id/identify
 *   4. POST /api/auth/flow/:id/submit  (password)
 *   5. POST /api/auth/flow/:id/complete
 *
 * Bearer tokens bypass CSRF on all subsequent requests (csrf.rs line 92–96).
 */
export async function getAdminJwt(request: APIRequestContext): Promise<{ jwt: string; orgId: string }> {
  // Step 1
  const csrfRes = await request.get(`${BACKEND}/api/csrf-token`);
  const { csrf_token } = await csrfRes.json();
  const headers = { 'X-CSRF-Token': csrf_token, Origin: BACKEND };

  // Step 2
  const initRes = await request.post(`${BACKEND}/api/auth/flow/init`, {
    data: { org_id: 'system' },
    headers,
  });
  const { flow_id, flow_token } = await initRes.json();
  const flowHeaders = { ...headers, Authorization: `Bearer ${flow_token}` };

  // Step 3
  await request.post(`${BACKEND}/api/auth/flow/${flow_id}/identify`, {
    data: { identifier: ADMIN_EMAIL },
    headers: flowHeaders,
  });

  // Step 4
  const submitRes = await request.post(`${BACKEND}/api/auth/flow/${flow_id}/submit`, {
    data: { capability: 'password', value: ADMIN_PASSWORD },
    headers: flowHeaders,
  });
  expect(submitRes.ok()).toBeTruthy();

  // Step 5
  const completeRes = await request.post(`${BACKEND}/api/auth/flow/${flow_id}/complete`, {
    headers: flowHeaders,
  });
  expect(completeRes.ok()).toBeTruthy();
  const data = await completeRes.json();
  const jwt = data.jwt || data.token;
  expect(jwt, 'JWT missing from complete response').toBeTruthy();

  // Elevate this new session to AAL3 so agent:manage routes pass (requires AAL2+).
  // Uses the /api/test/elevate-session bypass — only available in non-production.
  const sessionId = data.session_id;
  if (sessionId) {
    await request.post(`${BACKEND}/api/test/elevate-session`, {
      data: { session_id: sessionId, aal_level: 3 },
      headers: { 'X-Test-Seed-Token': SEED_TOKEN, 'Content-Type': 'application/json' },
    });
  }

  return { jwt, orgId: data.tenant_id || data.org_id || 'system' };
}

/** Bearer auth headers used by all agent API requests. */
export function bearerHeaders(jwt: string, orgId = ''): Record<string, string> {
  const h: Record<string, string> = { Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' };
  if (orgId) h['X-Organization-Id'] = orgId;
  return h;
}

// ─── Agent lifecycle helpers (used as fixture setup/teardown) ────────────────

export async function registerAgent(
  request: APIRequestContext,
  jwt: string,
  orgId: string,
  overrides: Record<string, unknown> = {},
): Promise<{ agent_id: string; name: string }> {
  const name = unique('demo-agent');
  const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
    data: {
      name,
      model_id: 'claude-3-5-sonnet-20241022',
      allowed_tools: 'web_search send_email make_payment',
      max_delegation_depth: 3,
      token_ttl_seconds: 3600,
      ...overrides,
    },
    headers: bearerHeaders(jwt, orgId),
  });
  expect(res.status()).toBe(201);
  const body = await res.json();
  return { agent_id: body.agent_id, name: body.name };
}

export async function issueAgentToken(
  request: APIRequestContext,
  jwt: string,
  orgId: string,
  agentId: string,
  taskId: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const res = await request.post(`${BACKEND}/api/v1/agents/token`, {
    data: { agent_id: agentId, task_id: taskId, ...overrides },
    headers: bearerHeaders(jwt, orgId),
  });
  expect(res.status()).toBe(200);
  return (await res.json()).token;
}

export async function deactivateAgent(
  request: APIRequestContext,
  jwt: string,
  orgId: string,
  agentId: string,
): Promise<void> {
  await request.delete(`${BACKEND}/api/v1/agents/${agentId}`, {
    headers: bearerHeaders(jwt, orgId),
  });
}

// ─── Extended test fixture ───────────────────────────────────────────────────

type Fixtures = {
  /** Admin JWT obtained via EIAA flow */
  adminJwt: string;
  /** Admin org ID */
  adminOrgId: string;
  /** Freshly registered agent (auto-deactivated after test) */
  agent: { agent_id: string; name: string };
  /** Agent JWT for a single test task */
  agentJwt: string;
  /** Task ID for the test */
  taskId: string;
};

export const test = base.extend<Fixtures>({
  adminJwt: async ({ request }, use) => {
    const { jwt } = await getAdminJwt(request);
    await use(jwt);
  },
  adminOrgId: async ({ request }, use) => {
    const { orgId } = await getAdminJwt(request);
    await use(orgId);
  },
  agent: async ({ request, adminJwt, adminOrgId }, use) => {
    const a = await registerAgent(request, adminJwt, adminOrgId);
    await use(a);
    // Auto-cleanup: deactivate agent after test
    await deactivateAgent(request, adminJwt, adminOrgId, a.agent_id).catch(() => {});
  },
  taskId: async ({}, use) => {
    await use(unique('task'));
  },
  agentJwt: async ({ request, adminJwt, adminOrgId, agent, taskId }, use) => {
    const token = await issueAgentToken(request, adminJwt, adminOrgId, agent.agent_id, taskId);
    await use(token);
  },
});
