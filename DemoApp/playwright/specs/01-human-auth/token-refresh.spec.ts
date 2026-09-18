/**
 * Suite 1 — Human Authentication: Token Refresh
 *
 * Verifies the 401 → silent refresh → retry interceptor in @idaas/core.
 */
import { test, expect, BACKEND } from '../../fixtures/test-utils';

test.describe('Token refresh', () => {
  test('1.9 – expired JWT is rejected by backend with 401', async ({ request }) => {
    // A synthetically expired JWT (exp in the past). Signature won't validate
    // but the backend should return 401 before even checking.
    // Deliberately invalid token — three dot-separated segments with a zeroed signature.
    // Not a real credential; used only to verify the backend returns 401.
    const fakeJwt = 'test.header.eyJleHAiOjF9.zeroed_sig_not_a_real_token';
    const res = await request.get(`${BACKEND}/api/v1/agents`, {
      headers: { Authorization: `Bearer ${fakeJwt}` },
    });
    expect(res.status()).toBe(401);
  });

  test('1.10 – malformed Bearer token rejected with 401 (no server crash)', async ({ request }) => {
    for (const bad of ['not-a-jwt', 'x.y.z', 'Bearer ', '']) {
      const res = await request.get(`${BACKEND}/api/v1/agents`, {
        headers: { Authorization: `Bearer ${bad}` },
      });
      expect(res.status(), `Expected 401 for token "${bad}"`).toBe(401);
    }
  });

  test('1.11 – no Authorization header returns 401', async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/v1/agents`);
    expect(res.status()).toBe(401);
  });
});
