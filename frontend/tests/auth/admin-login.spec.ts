import { test, expect, loginAsAdmin, getSessionStorageItem, clearSession } from '../fixtures/test-utils';

test.describe('Admin Authentication', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
    });

    test('successful admin login redirects to dashboard', async ({ page }) => {
        await loginAsAdmin(page);

        // Verify URL
        expect(page.url()).toContain('/admin/dashboard');

        // Verify org context is set correctly
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        expect(orgId).toBe('system');

        // Verify JWT is stored
        const jwt = await getSessionStorageItem(page, 'jwt');
        expect(jwt).toBeTruthy();
    });

    test('invalid password shows error', async ({ page }) => {
        await page.goto('/u/admin');
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');

        // Wait for password input to be visible AND enabled
        await page.waitForSelector('input[type="password"]:not([disabled])');
        await page.fill('input[type="password"]', 'wrongpassword');

        // Wait for button to be enabled before clicking
        await page.waitForSelector('button[type="submit"]:not([disabled])');
        await page.click('button[type="submit"]');

        // Should show error, not redirect
        await page.waitForSelector('.text-red-700, .text-red-500, [class*="error"], [role="alert"]', { timeout: 10000 });
        expect(page.url()).not.toContain('/admin/dashboard');
    });

    test('logout clears session and redirects', async ({ page }) => {
        // First login
        await loginAsAdmin(page);

        // Click logout
        await page.click('button:has-text("Sign out")');

        // Verify redirect
        await page.waitForURL('**/u/admin', { timeout: 5000 });

        // Verify session cleared
        const jwt = await getSessionStorageItem(page, 'jwt');
        expect(jwt).toBeNull();
    });

});
