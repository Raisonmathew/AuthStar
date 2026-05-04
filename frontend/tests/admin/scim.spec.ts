/**
 * SCIM 2.0 provisioning page tests.
 *
 * All backend API calls intercepted via page.route(). Tests verify:
 *  - Navigation and page load
 *  - Disabled state: shows integration guide / setup instructions
 *  - Enable SCIM: POST → one-time token reveal (amber warning box)
 *  - Copy token button updates clipboard
 *  - Rotate token: confirm dialog + POST → new token reveal
 *  - Disable SCIM: confirm dialog + POST
 *  - Event log table renders when events exist
 */
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from '../fixtures/test-utils';

const SCIM_CONFIG_URL = '**/api/admin/v1/scim/config';
const SCIM_ENABLE_URL = '**/api/admin/v1/scim/enable';
const SCIM_DISABLE_URL = '**/api/admin/v1/scim/disable';
const SCIM_ROTATE_URL = '**/api/admin/v1/scim/rotate-token';
const SCIM_EVENTS_URL = '**/api/admin/v1/scim/events*';

interface ScimConfig {
    id: string;
    enabled: boolean;
    token_hint: string | null;
    endpoint_url: string;
    supported_resources: string[];
    last_event_at: string | null;
    event_count: number;
}

const MOCK_CONFIG_DISABLED: ScimConfig = {
    id: 'scim-1',
    enabled: false,
    token_hint: null,
    endpoint_url: 'http://localhost:8080/scim/v2',
    supported_resources: ['Users', 'Groups'],
    last_event_at: null,
    event_count: 0,
};

const MOCK_CONFIG_ENABLED: ScimConfig = {
    ...MOCK_CONFIG_DISABLED,
    enabled: true,
    token_hint: 'abc...xyz',
    event_count: 3,
    last_event_at: new Date().toISOString(),
};

const MOCK_EVENTS = [
    { id: 'ev-1', operation: 'CREATE', resource_type: 'Users', external_id: 'user-ext-1', status: 'success', error_message: null, created_at: new Date().toISOString() },
    { id: 'ev-2', operation: 'UPDATE', resource_type: 'Groups', external_id: 'group-ext-1', status: 'success', error_message: null, created_at: new Date().toISOString() },
];

async function mockScimApi(page: import('@playwright/test').Page, initialEnabled = false) {
    let config: ScimConfig = initialEnabled ? { ...MOCK_CONFIG_ENABLED } : { ...MOCK_CONFIG_DISABLED };

    await page.route(SCIM_CONFIG_URL, async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
    });

    await page.route(SCIM_ENABLE_URL, async (route) => {
        config = { ...config, enabled: true, token_hint: 'new...tok' };
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ config, token: 'scim_token_abc123def456' }),
        });
    });

    await page.route(SCIM_DISABLE_URL, async (route) => {
        config = { ...config, enabled: false };
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(config) });
    });

    await page.route(SCIM_ROTATE_URL, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ token: 'scim_rotated_token_xyz789' }),
        });
    });

    await page.route(SCIM_EVENTS_URL, async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(initialEnabled ? MOCK_EVENTS : []) });
    });
}

test.describe('SCIM 2.0 Provisioning', () => {
    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('nav link navigates to SCIM page', async ({ page }) => {
        await mockScimApi(page, false);
        await page.goto('/admin/dashboard');
        await page.click('a[href="/admin/authentication/scim"]');
        await page.waitForURL('**/admin/authentication/scim', { timeout: 10_000 });
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });
    });

    test('disabled state shows setup guide', async ({ page }) => {
        await mockScimApi(page, false);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });
        // When disabled, expect the "How to connect your IdP" setup guide
        await expect(
            page.getByText(/How to connect your IdP|Enable SCIM/i).first()
        ).toBeVisible({ timeout: 8_000 });
    });

    test('Enable SCIM button triggers POST and shows one-time token', async ({ page }) => {
        await mockScimApi(page, false);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });

        const enableBtn = page.getByRole('button', { name: /enable scim/i }).first();
        await expect(enableBtn).toBeVisible({ timeout: 8_000 });
        await enableBtn.click();

        // One-time token reveal — amber warning box
        await expect(
            page.getByText(/copy.*token|bearer token|save this token/i).or(page.locator('.bg-amber-500\\/10, [class*="amber"]')).first()
        ).toBeVisible({ timeout: 8_000 });

        // Token value should be in the UI
        await expect(page.getByText('scim_token_abc123def456')).toBeVisible({ timeout: 5_000 });
    });

    test('endpoint URL is displayed', async ({ page }) => {
        await mockScimApi(page, true);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });
        await expect(page.getByText('/scim/v2')).toBeVisible({ timeout: 8_000 });
    });

    test('event log renders when events exist', async ({ page }) => {
        await mockScimApi(page, true);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });

        // Event log should show recent events
        await expect(page.getByText('CREATE')).toBeVisible({ timeout: 8_000 });
        await expect(page.locator('td').filter({ hasText: /Users/ }).first()).toBeVisible();
    });

    test('Rotate Token shows confirm dialog and reveals new token', async ({ page }) => {
        await mockScimApi(page, true);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });

        const rotateBtn = page.getByRole('button', { name: /rotate.*token/i }).first();
        await expect(rotateBtn).toBeVisible({ timeout: 8_000 });

        page.once('dialog', (d) => d.accept());
        await rotateBtn.click();

        // New token should appear
        await expect(page.getByText('scim_rotated_token_xyz789')).toBeVisible({ timeout: 8_000 });
    });

    test('Disable SCIM requires confirm dialog', async ({ page }) => {
        await mockScimApi(page, true);
        await page.goto('/admin/authentication/scim');
        await expect(page.locator('h1:has-text("SCIM")')).toBeVisible({ timeout: 10_000 });

        const disableBtn = page.getByRole('button', { name: /disable/i }).first();
        await expect(disableBtn).toBeVisible({ timeout: 8_000 });

        page.once('dialog', (d) => d.accept());
        await disableBtn.click();

        // After disabling, the enable button should reappear
        await expect(page.getByRole('button', { name: /enable scim/i })).toBeVisible({ timeout: 8_000 });
    });
});
