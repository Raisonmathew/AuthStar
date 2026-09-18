/**
 * Suite 1 — Human Authentication: Logout
 */
import { test, expect, ADMIN_EMAIL, ADMIN_PASSWORD } from '../../fixtures/test-utils';

test.describe('Logout', () => {
  test('1.12 – sign-out clears session and redirects to home', async ({ page }) => {
    // Sign in first
    await page.goto('/sign-in');
    await page.fill('[data-testid="input-email"]', ADMIN_EMAIL);
    await page.fill('[data-testid="input-password"]', ADMIN_PASSWORD);
    await page.click('[data-testid="btn-submit"]');
    await page.waitForURL('**/dashboard', { timeout: 30_000 });

    // Confirm we're on the dashboard
    await expect(page).toHaveURL(/\/dashboard/);

    // Sign out
    await page.click('[data-testid="btn-sign-out"]');
    await page.waitForURL('**/', { timeout: 10_000 });

    // JWT cleared from sessionStorage
    const jwt = await page.evaluate(() => sessionStorage.getItem('demo_jwt'));
    expect(jwt).toBeNull();

    // Navigating to dashboard again should redirect to sign-in
    await page.goto('/dashboard');
    await page.waitForURL(/\/sign-in/, { timeout: 10_000 });
  });
});
