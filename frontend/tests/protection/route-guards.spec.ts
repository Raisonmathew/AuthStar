import { test, expect, clearSession, getSessionStorageItem } from '../fixtures/test-utils';

test.describe('Route Protection', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
    });

    test('admin dashboard redirects to login without auth', async ({ page }) => {
        await page.goto('/admin/dashboard');

        // Should redirect to admin login
        await page.waitForURL('**/u/admin', { timeout: 5000 });
        expect(page.url()).toContain('/u/admin');
    });

    test('user dashboard redirects to login without auth', async ({ page }) => {
        await page.goto('/dashboard');

        // Should redirect to sign-in (which goes to /u/default)
        await page.waitForURL('**/u/default', { timeout: 5000 });
    });

    test('admin routes not accessible after session clear', async ({ page }) => {
        // Simulate having a potentially stale URL
        await page.goto('/admin/apps');

        // Should be redirected
        await page.waitForURL('**/u/admin', { timeout: 5000 });
    });

});
