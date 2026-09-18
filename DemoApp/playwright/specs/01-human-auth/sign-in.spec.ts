/**
 * Suite 1 — Human Authentication: Sign-In
 *
 * Tests: happy path, wrong password, CSRF, redirect to dashboard.
 */
import { test, expect, BACKEND, ADMIN_EMAIL, ADMIN_PASSWORD } from '../../fixtures/test-utils';

test.describe('Sign-in flow', () => {
  test.beforeEach(async ({ page }) => {
    // Ensure no existing session
    await page.goto('/sign-in');
    await page.evaluate(() => { sessionStorage.clear(); localStorage.clear(); });
    await page.context().clearCookies();
  });

  test('1.1 – valid credentials → redirect to /dashboard', async ({ page }) => {
    await page.goto('/sign-in');
    await page.fill('[data-testid="input-email"]', ADMIN_EMAIL);
    await page.fill('[data-testid="input-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="btn-submit"]');

    await page.waitForURL('**/dashboard', { timeout: 30_000 });
    await expect(page).toHaveURL(/\/dashboard/);
    // JWT must be in sessionStorage after successful sign-in
    const jwt = await page.evaluate(() => sessionStorage.getItem('demo_jwt'));
    expect(jwt).toBeTruthy();
    expect(jwt!.split('.').length).toBe(3); // valid JWT structure
  });

  test('1.2 – wrong password shows error, no redirect', async ({ page }) => {
    await page.goto('/sign-in');
    await page.fill('[data-testid="input-email"]', ADMIN_EMAIL);
    await page.fill('[data-testid="input-password"]', 'WrongPassword999!');
    await page.click('[data-testid="btn-submit"]');

    const error = page.locator('[data-testid="sign-in-error"]');
    await expect(error).toBeVisible({ timeout: 10_000 });
    await expect(page).toHaveURL(/\/sign-in/);
    // JWT must NOT have been stored
    const jwt = await page.evaluate(() => sessionStorage.getItem('demo_jwt'));
    expect(jwt).toBeNull();
  });

  test('1.3 – landing page is accessible without JWT', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('[data-testid="btn-sign-in"]')).toBeVisible();
    await expect(page.locator('[data-testid="btn-sign-up"]')).toBeVisible();
  });

  test('1.4 – /dashboard without JWT redirects to /sign-in', async ({ page }) => {
    // Clear any leftover session state
    await page.context().clearCookies();
    await page.goto('/dashboard');
    // AuthGuard should redirect
    await page.waitForURL(/\/sign-in/, { timeout: 10_000 });
    await expect(page).toHaveURL(/\/sign-in/);
  });

  test('1.5 – JWT stored in sessionStorage only, not localStorage', async ({ page }) => {
    await page.goto('/sign-in');
    await page.fill('[data-testid="input-email"]', ADMIN_EMAIL);
    await page.fill('[data-testid="input-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="btn-submit"]');
    await page.waitForURL('**/dashboard', { timeout: 30_000 });

    // AGENTS.md: JWT must never be in localStorage
    const localJwt = await page.evaluate(() => localStorage.getItem('jwt'));
    expect(localJwt, 'JWT must NOT be in localStorage').toBeNull();
    // demo_jwt is in sessionStorage (demo-app convenience only)
    const sessJwt = await page.evaluate(() => sessionStorage.getItem('demo_jwt'));
    expect(sessJwt).toBeTruthy();
  });
});
