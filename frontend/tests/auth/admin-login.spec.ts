import { test, expect, loginAsAdmin, getSessionStorageItem, clearSession } from '../fixtures/test-utils';

test.describe('Admin Authentication', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
    });

    test('successful admin login redirects to dashboard', async ({ page }) => {
        await loginAsAdmin(page);

        // Verify URL
        expect(page.url()).toContain('/admin/dashboard');

        // Verify org context is set correctly (set by AuthContext after silentRefresh)
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        // Admin org_id is set during bootstrap — it may be 'system', 'default', or a UUID.
        // Just verify it's populated.
        expect(orgId).toBeTruthy();
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
        // A fresh password login yields AAL1. Dashboard background API calls
        // that require AAL2 return 403 + AUTH_STEP_UP_REQUIRED, which would
        // repeatedly open the StepUpModal and block the Sign Out button.
        // Suppress the custom event in the capture phase (before React's
        // listener) for this test — we only need to verify logout redirects,
        // not the step-up flow itself. addInitScript ensures the suppressor
        // is installed before loginAsAdmin's page.goto('/u/admin') fires.
        await page.addInitScript(() => {
            window.addEventListener('auth:step-up-required', (e) => {
                e.stopImmediatePropagation();
            }, true); // capture phase — runs before React handlers
        });

        // First login
        await loginAsAdmin(page);

        const signOutBtn = page.locator('button:has-text("Sign Out"), button:has-text("Sign out"), button:has-text("Logout"), button:has-text("Log out")');
        await signOutBtn.first().click();

        // Verify redirect to admin login
        await page.waitForURL('**/u/admin', { timeout: 10000 });

        // Verify session storage cleared
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        expect(orgId).toBeNull();
    });

});
