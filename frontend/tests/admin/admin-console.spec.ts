import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Admin Console', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('dashboard loads with correct elements', async ({ page }) => {
        // Verify we're on admin dashboard
        expect(page.url()).toContain('/admin/dashboard');

        // Check for sidebar navigation (doesn't depend on API)
        await expect(page.locator('aside nav')).toBeVisible();
    });

    test('can navigate to App Registry', async ({ page }) => {
        await page.click('a[href="/admin/applications"]');
        await page.waitForURL('**/admin/applications', { timeout: 10000 });

        expect(page.url()).toContain('/admin/applications');
    });

    test('can navigate to Policies', async ({ page }) => {
        await page.click('a[href="/admin/policies"]');
        await page.waitForURL('**/admin/policies', { timeout: 10000 });

        expect(page.url()).toContain('/admin/policies');
    });

    test('can navigate to Branding', async ({ page }) => {
        await page.click('a[href="/admin/branding/login"]');
        await page.waitForURL('**/admin/branding/login', { timeout: 10000 });

        expect(page.url()).toContain('/admin/branding/login');
    });

    test('can navigate to SSO Connections', async ({ page }) => {
        await page.click('a[href="/admin/authentication/sso"]');
        await page.waitForURL('**/admin/authentication/sso', { timeout: 10000 });

        expect(page.url()).toContain('/admin/authentication/sso');
    });

    test('can navigate to Custom Domains', async ({ page }) => {
        await page.click('a[href="/admin/branding/domains"]');
        await page.waitForURL('**/admin/branding/domains', { timeout: 10000 });

        expect(page.url()).toContain('/admin/branding/domains');
    });

    test('can navigate to Audit Logs', async ({ page }) => {
        await page.click('a[href="/admin/monitoring/logs"]');
        await page.waitForURL('**/admin/monitoring/logs', { timeout: 10000 });

        expect(page.url()).toContain('/admin/monitoring/logs');
    });

});
