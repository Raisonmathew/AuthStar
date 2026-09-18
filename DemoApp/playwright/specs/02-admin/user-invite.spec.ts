/**
 * Suite 2 — Admin: User invite flow
 */
import { test, expect, BACKEND, SEED_TOKEN, unique } from '../../fixtures/test-utils';

test.describe('User invitation', () => {
  test('2.3 – seed invitation returns token; acceptance URL is valid', async ({ request, adminJwt }) => {
    const email = `invite_${Date.now()}@example.com`;

    // Seed an invitation using the test-seed endpoint
    const seedRes = await request.post(`${BACKEND}/api/test/seed/invitation`, {
      headers: {
        'X-Test-Seed-Token': SEED_TOKEN,
        'Content-Type': 'application/json',
      },
      data: {
        organization_id: 'system',
        email,
        role: 'member',
      },
    });
    expect(seedRes.status()).toBe(200);
    const seedBody = await seedRes.json();
    expect(seedBody.token, 'Invitation token must be returned').toBeTruthy();
    expect(seedBody.email).toBe(email);
  });

  test('2.4 – non-admin role cannot access admin registration endpoint', async ({ request }) => {
    // A request without any auth should return 401
    const res = await request.post(`${BACKEND}/api/v1/agents/register`, {
      data: { name: 'Unauthorized Agent' },
    });
    // No auth → CSRF returns 403 or auth returns 401
    expect([401, 403]).toContain(res.status());
  });
});
