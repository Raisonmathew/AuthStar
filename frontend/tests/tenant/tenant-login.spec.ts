import { test, expect, clearSession, getSessionStorageItem } from '../fixtures/test-utils';

const ADMIN_PASSWORD = process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly';

test.describe('Tenant Authentication', () => {

    // Each test gets a unique fake IP to avoid hitting the per-IP
    // auth-flow rate limit (10/minute) shared across tests.
    let _ipCounter = 0;

    test.beforeEach(async ({ page }) => {
        _ipCounter = (_ipCounter % 250) + 1;
        await page.setExtraHTTPHeaders({ 'X-Forwarded-For': `10.10.4.${_ipCounter}` });
        // Mock EIAA runtime keys so React mounts without gRPC service
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        await clearSession(page);
    });

    test('login to tenant org sets correct context', async ({ page }) => {
        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.fill('input[type="password"]', ADMIN_PASSWORD);
        await page.click('button[type="submit"]');

        // User portal redirects to /account/profile after EIAA completion
        await page.waitForURL('**/account/**', { timeout: 30_000 });

        // Verify org context is set by AuthContext
        const orgId = await getSessionStorageItem(page, 'active_org_id');
        expect(orgId).toBeTruthy();
    });

    test('different tenants have different contexts', async ({ page }) => {
        // Login to admin portal (/u/admin → system org → /admin/dashboard)
        await page.goto('/u/admin');
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.fill('input[type="password"]', ADMIN_PASSWORD);
        await page.click('button[type="submit"]');

        await page.waitForURL('**/admin/dashboard', { timeout: 30_000 });

        const adminOrgId = await getSessionStorageItem(page, 'active_org_id');
        expect(adminOrgId).toBe('system');

        // Clear and login to default tenant (/u/default → default org → /account/profile)
        await clearSession(page);
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.fill('input[type="password"]', ADMIN_PASSWORD);
        await page.click('button[type="submit"]');

        await page.waitForURL('**/account/**', { timeout: 30_000 });

        const userOrgId = await getSessionStorageItem(page, 'active_org_id');
        expect(userOrgId).toBeTruthy();
    });

});
