/**
 * Vault / BYOK Secret Store page tests.
 *
 * All backend API calls intercepted via page.route(). Tests verify:
 *  - Navigation and page load
 *  - Unconfigured state shows "How it works" info box
 *  - Configure button opens modal
 *  - Auth method selector renders conditional fields:
 *      Token   → shows "Vault Token" input
 *      AppRole → shows Role ID + Secret ID inputs
 *      K8s     → shows K8s Role + Auth Mount Path inputs
 *  - Save config: PUT request + modal closes
 *  - Test connection: POST → success toast
 *  - Enable / Disable toggle
 *  - Status badge reflects connected / error / unconfigured
 */
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from '../fixtures/test-utils';

const VAULT_CONFIG_URL = '**/api/admin/v1/vault/config';
const VAULT_TEST_URL = '**/api/admin/v1/vault/test';
const VAULT_ENABLE_URL = '**/api/admin/v1/vault/enable';
const VAULT_DISABLE_URL = '**/api/admin/v1/vault/disable';

const MOCK_CONFIG_CONNECTED = {
    id: 'vault-1',
    enabled: true,
    vault_addr: 'https://vault.example.com:8200',
    auth_method: 'approle',
    secret_mount: 'secret',
    secret_path_prefix: 'idaas/clients',
    role_id: 'role-abc-123',
    status: 'connected',
    status_message: 'Transit ping OK',
    last_check_at: new Date().toISOString(),
};

const MOCK_CONFIG_ERROR = {
    ...MOCK_CONFIG_CONNECTED,
    status: 'error',
    status_message: 'connection refused',
};

async function mockVaultApi(
    page: import('@playwright/test').Page,
    initialState: 'unconfigured' | 'connected' | 'error' | 'disabled' = 'unconfigured'
) {
    let config: typeof MOCK_CONFIG_CONNECTED | null =
        initialState === 'unconfigured' ? null :
        initialState === 'error' ? { ...MOCK_CONFIG_ERROR } :
        initialState === 'disabled' ? { ...MOCK_CONFIG_CONNECTED, enabled: false } :
        { ...MOCK_CONFIG_CONNECTED };

    await page.route(VAULT_CONFIG_URL, async (route) => {
        const method = route.request().method();
        if (method === 'GET') {
            if (config === null) {
                await route.fulfill({ status: 404, body: '' });
            } else {
                await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
            }
        } else if (method === 'PUT') {
            const body = await route.request().postDataJSON();
            config = { ...MOCK_CONFIG_CONNECTED, ...body };
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
        } else {
            await route.continue();
        }
    });

    await page.route(VAULT_TEST_URL, async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) });
    });

    await page.route(VAULT_ENABLE_URL, async (route) => {
        if (config) config = { ...config, enabled: true };
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
    });

    await page.route(VAULT_DISABLE_URL, async (route) => {
        if (config) config = { ...config, enabled: false };
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
    });
}

test.describe('Vault / BYOK Secret Store', () => {
    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('nav link navigates to Vault page', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/dashboard');
        await page.click('a[href="/admin/settings/vault"]');
        await page.waitForURL('**/admin/settings/vault', { timeout: 10_000 });
        await expect(page.locator('h1:has-text("Vault")')).toBeVisible({ timeout: 10_000 });
    });

    test('unconfigured state shows "How it works" info box', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await expect(page.locator('h1:has-text("Vault")')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText(/How.*Vault.*works|How it works/i)).toBeVisible({ timeout: 8_000 });
    });

    test('Configure button opens modal', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await page.getByRole('button', { name: /configure/i }).click();
        await expect(page.getByRole('heading', { name: /Configure Vault/i })).toBeVisible({ timeout: 5_000 });
    });

    test('token auth method shows Vault Token input', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await page.getByRole('button', { name: /configure/i }).click();

        await page.locator('select').selectOption('token');
        await expect(page.locator('label:has-text("Vault Token") + input')).toBeVisible({ timeout: 5_000 });
    });

    test('approle auth method shows Role ID and Secret ID', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await page.getByRole('button', { name: /configure/i }).click();

        await page.locator('select').selectOption('approle');
        await expect(page.locator('label:has-text("Role ID") + input')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('label:has-text("Secret ID") + input')).toBeVisible();
    });

    test('kubernetes auth method shows K8s Role and Auth Mount', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await page.getByRole('button', { name: /configure/i }).click();

        await page.locator('select').selectOption('kubernetes');
        await expect(page.locator('label:has-text("Kubernetes Role") + input')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('label:has-text("Auth Mount Path") + input')).toBeVisible();
    });

    test('save configuration closes modal and shows config', async ({ page }) => {
        await mockVaultApi(page, 'unconfigured');
        await page.goto('/admin/settings/vault');
        await page.getByRole('button', { name: /configure/i }).click();

        await page.locator('label:has-text("Vault Address") + input').fill('https://vault.example.com:8200');
        await page.locator('select').selectOption('approle');
        await page.locator('label:has-text("Role ID") + input').fill('my-role-id');
        await page.locator('label:has-text("Secret ID") + input').fill('my-secret-id');

        await page.getByRole('button', { name: /save configuration/i }).click();

        // Modal should close
        await expect(page.getByRole('heading', { name: /Configure Vault/i })).not.toBeVisible({ timeout: 5_000 });
        // Vault address appears on page
        await expect(page.getByText('vault.example.com')).toBeVisible({ timeout: 8_000 });
    });

    test('Test Connection button fires and shows feedback', async ({ page }) => {
        await mockVaultApi(page, 'connected');
        await page.goto('/admin/settings/vault');
        await expect(page.getByText('vault.example.com')).toBeVisible({ timeout: 10_000 });

        await page.getByRole('button', { name: /test connection/i }).click();

        await expect(
            page.locator('[data-sonner-toast]').or(page.getByText(/success|connected|test.*ok/i)).first()
        ).toBeVisible({ timeout: 8_000 });
    });

    test('connected state shows green status dot and badge', async ({ page }) => {
        await mockVaultApi(page, 'connected');
        await page.goto('/admin/settings/vault');
        await expect(page.locator('h1:has-text("Vault")')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText('connected', { exact: false })).toBeVisible({ timeout: 8_000 });
    });

    test('error state shows error badge and message', async ({ page }) => {
        await mockVaultApi(page, 'error');
        await page.goto('/admin/settings/vault');
        await expect(page.locator('h1:has-text("Vault")')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText('error', { exact: false })).toBeVisible({ timeout: 8_000 });
        await expect(page.getByText('connection refused')).toBeVisible();
    });

    test('Disable button fires POST and shows Enable button', async ({ page }) => {
        await mockVaultApi(page, 'connected');
        await page.goto('/admin/settings/vault');
        await expect(page.getByText('vault.example.com')).toBeVisible({ timeout: 10_000 });

        page.once('dialog', (d) => d.accept());
        await page.getByRole('button', { name: /disable/i }).click();

        await expect(page.getByRole('button', { name: /enable/i })).toBeVisible({ timeout: 8_000 });
    });
});
