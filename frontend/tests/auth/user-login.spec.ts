import { test, expect, loginAsUser, getSessionStorageItem, clearSession } from '../fixtures/test-utils';

test.describe('User Authentication', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
    });

    test('successful user login redirects to dashboard', async ({ page }) => {
        await loginAsUser(page);

        // User portal redirects to /account/profile after EIAA flow completes
        expect(page.url()).toContain('/account');

        // Verify org context is set correctly
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        expect(orgId).toBeTruthy();
    });

    test('invalid password shows error', async ({ page }) => {
        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');

        // Wait for password input to be visible AND enabled
        await page.waitForSelector('input[type="password"]:not([disabled])');
        await page.fill('input[type="password"]', 'wrongpassword');

        // Wait for button to be enabled before clicking
        await page.waitForSelector('button[type="submit"]:not([disabled])');
        await page.click('button[type="submit"]');

        // Should show error
        await page.waitForSelector('.text-red-700, .text-red-500, [class*="error"], [role="alert"]', { timeout: 10000 });
        expect(page.url()).not.toContain('/dashboard');
    });

});
