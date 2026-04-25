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
        // The user account area requires authentication
        await page.goto('/account/profile');

        // Should redirect to the user login (/u/default)
        await page.waitForURL('**/u/default', { timeout: 10000 });
        expect(page.url()).toContain('/u/default');
    });

    test('admin routes not accessible after session clear', async ({ page }) => {
        // Simulate having a potentially stale URL
        await page.goto('/admin/apps');

        // Should be redirected
        await page.waitForURL('**/u/admin', { timeout: 5000 });
    });

});
