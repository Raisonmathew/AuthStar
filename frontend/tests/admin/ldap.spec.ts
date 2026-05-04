/**
 * LDAP / Active Directory page tests.
 *
 * All backend API calls are intercepted via page.route() so the suite runs
 * without a live backend. Tests verify:
 *  - Navigation and page load
 *  - Empty-state messaging
 *  - Add Connection modal: field rendering, SSL port toggle
 *  - Create connection happy-path (mocked POST)
 *  - Test connection (mocked POST → success banner)
 *  - Delete connection (confirm dialog + mocked DELETE)
 */
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from '../fixtures/test-utils';

const BASE = '/api/admin/v1/ldap';

const MOCK_CONN = {
    id: 'ldap-test-id-1',
    name: 'Corporate LDAP',
    host: 'ldap.corp.example.com',
    port: 636,
    use_ssl: true,
    bind_dn: 'cn=svc,dc=corp,dc=example,dc=com',
    base_dn: 'dc=corp,dc=example,dc=com',
    user_search_filter: '(sAMAccountName={{username}})',
    attr_map_email: 'mail',
    attr_map_name: 'displayName',
    enabled: true,
    last_sync_at: new Date().toISOString(),
    sync_status: 'ok',
};

async function mockLdapApi(page: import('@playwright/test').Page, connections: typeof MOCK_CONN[] = []) {
    await page.route(`**${BASE}`, async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(connections) });
        } else if (route.request().method() === 'POST') {
            const body = await route.request().postDataJSON();
            const created = { ...MOCK_CONN, ...body, id: `ldap-new-${Date.now()}` };
            connections.push(created);
            await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(created) });
        } else {
            await route.continue();
        }
    });

    await page.route(`**${BASE}/**`, async (route) => {
        const method = route.request().method();
        const url = route.request().url();

        if (url.endsWith('/test') && method === 'POST') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) });
        } else if (url.endsWith('/sync') && method === 'POST') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ synced: 5 }) });
        } else if (method === 'DELETE') {
            const id = url.split('/').pop()?.replace(/\?.*$/, '');
            const idx = id ? connections.findIndex(c => c.id === id) : -1;
            if (idx > -1) connections.splice(idx, 1);
            await route.fulfill({ status: 204, body: '' });
        } else if (method === 'PUT') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(MOCK_CONN) });
        } else if (method === 'PATCH') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...MOCK_CONN, enabled: !MOCK_CONN.enabled }) });
        } else {
            await route.continue();
        }
    });
}

test.describe('LDAP / Active Directory', () => {
    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('nav link navigates to LDAP page', async ({ page }) => {
        await mockLdapApi(page);
        await page.goto('/admin/dashboard');
        await page.click('a[href="/admin/authentication/ldap"]');
        await page.waitForURL('**/admin/authentication/ldap', { timeout: 10_000 });
        await expect(page.locator('h1:has-text("LDAP")')).toBeVisible({ timeout: 10_000 });
    });

    test('empty state is shown when no connections exist', async ({ page }) => {
        await mockLdapApi(page, []);
        await page.goto('/admin/authentication/ldap');
        await expect(page.locator('h1:has-text("LDAP")')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText('No LDAP connections', { exact: false })).toBeVisible();
    });

    test('existing connections are listed', async ({ page }) => {
        await mockLdapApi(page, [MOCK_CONN]);
        await page.goto('/admin/authentication/ldap');
        await expect(page.getByText('Corporate LDAP')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText('ldap.corp.example.com')).toBeVisible();
    });

    test('Add Connection button opens modal', async ({ page }) => {
        await mockLdapApi(page, []);
        await page.goto('/admin/authentication/ldap');
        await page.getByRole('button', { name: /Add Connection/i }).first().click();
        await expect(page.getByRole('heading', { name: /New LDAP Connection/i })).toBeVisible();
    });

    test('SSL toggle auto-switches port 389 ↔ 636', async ({ page }) => {
        await mockLdapApi(page, []);
        await page.goto('/admin/authentication/ldap');
        await page.getByRole('button', { name: /Add Connection/i }).first().click();
        await expect(page.getByRole('heading', { name: /New LDAP Connection/i })).toBeVisible();

        // Port input is the only number input in the modal
        const portInput = page.locator('input[type="number"]').first();
        const initialPort = await portInput.inputValue();
        expect(['389', '636']).toContain(initialPort);

        // SSL toggle is a <button> immediately before the "Use SSL/TLS (LDAPS)" label
        const sslToggle = page.locator('xpath=//label[contains(text(),"SSL")]/preceding-sibling::button');

        // Toggle SSL — port should switch 389 ↔ 636
        const portBefore = await portInput.inputValue();
        await sslToggle.click();
        await page.waitForTimeout(100);
        const portAfter = await portInput.inputValue();
        expect(portBefore).not.toBe(portAfter);
    });

    test('can create a new LDAP connection', async ({ page }) => {
        const connections: typeof MOCK_CONN[] = [];
        await mockLdapApi(page, connections);
        await page.goto('/admin/authentication/ldap');

        await page.getByRole('button', { name: /Add Connection/i }).first().click();
        await expect(page.getByRole('heading', { name: /New LDAP Connection/i })).toBeVisible();

        // Labels have no for/id — use sibling selector
        await page.locator('label:has-text("Connection Name") + input').fill('Test Directory');
        await page.locator('label:has-text("Hostname") + input').fill('ldap.example.com');
        await page.locator('label:has-text("Bind DN") + input').fill('cn=admin,dc=example,dc=com');
        await page.locator('label:has-text("Bind Password") + input').fill('secret');
        await page.locator('label:has-text("Base DN") + input').fill('dc=example,dc=com');

        const submitBtn = page.getByRole('button', { name: /Create Connection/i });
        await submitBtn.click();

        // Modal should close after successful submit
        await expect(page.getByRole('heading', { name: /New LDAP Connection/i })).not.toBeVisible({ timeout: 5_000 });
    });

    test('test connection shows success feedback', async ({ page }) => {
        await mockLdapApi(page, [MOCK_CONN]);
        await page.goto('/admin/authentication/ldap');

        await expect(page.getByText('Corporate LDAP')).toBeVisible({ timeout: 10_000 });

        // Click the Test button for the connection
        const testBtn = page.getByRole('button', { name: /Test/i }).first();
        await testBtn.click();

        // Should show success toast or update
        await expect(page.locator('[data-sonner-toast]').or(page.getByText(/success|ok/i)).first()).toBeVisible({ timeout: 8_000 });
    });

    test('delete connection requires confirmation', async ({ page }) => {
        const connections = [{ ...MOCK_CONN }];
        await mockLdapApi(page, connections);
        await page.goto('/admin/authentication/ldap');
        await expect(page.getByText('Corporate LDAP')).toBeVisible({ timeout: 10_000 });

        page.once('dialog', (d) => d.accept());
        await page.getByRole('button', { name: /Delete/i }).first().click();

        // Connection should disappear from list after delete
        await expect(page.getByText('Corporate LDAP')).not.toBeVisible({ timeout: 8_000 });
    });
});
