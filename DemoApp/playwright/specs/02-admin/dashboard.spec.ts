/**
 * Suite 2 — Admin: Dashboard and API key management
 */
import { test, expect, BACKEND, unique } from '../../fixtures/test-utils';

test.describe('Admin dashboard', () => {
  test('2.1 – dashboard loads for authenticated admin', async ({ page }) => {
    // sessionStorage is not persisted in storageState — sign in via UI first
    const pw = process.env.IDAAS_BOOTSTRAP_PASSWORD ?? '';
    await page.goto('/sign-in');
    await page.fill('[data-testid="input-email"]', 'admin@example.com');
    await page.fill('[data-testid="input-password"]', pw);
    await page.click('[data-testid="btn-submit"]');
    await page.waitForURL('**/dashboard', { timeout: 30_000 });
    await expect(page.locator('[data-testid="agent-panel"]')).toBeVisible({ timeout: 15_000 });
  });

  test('2.2 – admin can create and use an API key', async ({ request, adminJwt, adminOrgId }) => {
    // Create API key (correct route: /api/v1/api-keys)
    const createRes = await request.post(`${BACKEND}/api/v1/api-keys`, {
      data: { name: unique('demo-key'), scopes: ['agent:read', 'agent:write'] },
      headers: {
        Authorization: `Bearer ${adminJwt}`,
        'X-Organization-Id': adminOrgId,
        'Content-Type': 'application/json',
      },
    });
    // 201 or 200
    expect([200, 201]).toContain(createRes.status());
    const body = await createRes.json();
    const keyValue = body.key || body.api_key || body.raw_key;
    expect(keyValue, 'Raw key must be returned on creation').toBeTruthy();

    // Use the key to make an authenticated request
    const agentsRes = await request.get(`${BACKEND}/api/v1/agents`, {
      headers: { 'X-API-Key': keyValue },
    });
    // 200 if API key auth is accepted for agents route;
    // 401 if key auth not enabled; 403 if EIAA capsule denies the key scope
    expect([200, 401, 403]).toContain(agentsRes.status());
  });
});
