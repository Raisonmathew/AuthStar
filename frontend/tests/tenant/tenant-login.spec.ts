import { test, expect, clearSession, getSessionStorageItem } from '../fixtures/test-utils';

test.describe('Tenant Authentication', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
    });

    test('login to tenant org sets correct context', async ({ page }) => {
        // Note: This test assumes a tenant 'default' exists
        // In a real scenario, you would create a test tenant first

        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');

        // Wait for redirect
        await page.waitForURL('/dashboard', { timeout: 10000 });

        // Verify tenant context
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        expect(orgId).toBe('default');
    });

    test('different tenants have different contexts', async ({ page }) => {
        // Test that /u/admin sets 'system' context
        await page.goto('/u/admin');
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');

        await page.waitForURL('/admin/dashboard', { timeout: 10000 });

        const adminOrgId = await getSessionStorageItem(page, 'active_org_id');
        expect(adminOrgId).toBe('system');

        // Clear and login to default
        await clearSession(page);
        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');

        await page.waitForURL('/dashboard', { timeout: 10000 });

        const userOrgId = await getSessionStorageItem(page, 'active_org_id');
        expect(userOrgId).toBe('default');
    });

});
