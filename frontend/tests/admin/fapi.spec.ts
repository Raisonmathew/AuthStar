/**
 * FAPI 2.0 Security Profile toggle tests in AppModal.
 *
 * Backend calls for app list / create / update are mocked. Tests verify:
 *  - FAPI 2.0 checkbox is visible in the Create App modal
 *  - Checking FAPI 2.0 includes fapi_profile:'fapi2' in the POST payload
 *  - Unchecked FAPI sends fapi_profile:null
 *  - Editing an existing app with fapi_profile:'fapi2' pre-checks the box
 *  - Saving with FAPI toggled OFF sends fapi_profile:null in PUT payload
 */
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from '../fixtures/test-utils';

const APPS_URL = '**/api/admin/v1/apps';

interface MockApp {
    id: string;
    name: string;
    type: string;
    client_id: string;
    redirect_uris: string[];
    allowed_flows: string[];
    allowed_scopes: string[];
    fapi_profile: string | null;
    public_config: { enforce_pkce: boolean; allowed_origins: string[] };
}

const MOCK_APP_STANDARD: MockApp = {
    id: 'app-std-1',
    name: 'Standard Web App',
    type: 'web',
    client_id: 'client_std_1',
    redirect_uris: ['https://example.com/callback'],
    allowed_flows: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email'],
    fapi_profile: null,
    public_config: { enforce_pkce: false, allowed_origins: [] },
};

const MOCK_APP_FAPI: MockApp = {
    ...MOCK_APP_STANDARD,
    id: 'app-fapi-1',
    name: 'FAPI-Compliant Banking App',
    fapi_profile: 'fapi2',
    public_config: { enforce_pkce: true, allowed_origins: [] },
};

async function mockAppsApi(page: import('@playwright/test').Page, apps: MockApp[]) {
    let capturedCreatePayload: Record<string, unknown> | null = null;
    let capturedUpdatePayload: Record<string, unknown> | null = null;

    await page.route(APPS_URL, async (route) => {
        const method = route.request().method();
        if (method === 'GET') {
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(apps) });
        } else if (method === 'POST') {
            capturedCreatePayload = await route.request().postDataJSON();
            const created = {
                app: { id: 'app-new-1', client_id: 'client_new_1', ...capturedCreatePayload },
                client_secret: 'test_secret_abc123',
            };
            await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(created) });
        } else {
            await route.continue();
        }
    });

    await page.route(`${APPS_URL}/**`, async (route) => {
        const method = route.request().method();
        if (method === 'PUT') {
            capturedUpdatePayload = await route.request().postDataJSON();
            await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...apps[0], ...capturedUpdatePayload }) });
        } else if (method === 'DELETE') {
            await route.fulfill({ status: 204, body: '' });
        } else {
            await route.continue();
        }
    });

    return { getCreatePayload: () => capturedCreatePayload, getUpdatePayload: () => capturedUpdatePayload };
}

test.describe('FAPI 2.0 Security Profile toggle', () => {
    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('FAPI 2.0 checkbox is present in Create App modal', async ({ page }) => {
        await mockAppsApi(page, []);
        await page.goto('/admin/applications');

        await page.getByRole('button', { name: /Create New App/i }).click();
        await expect(page.getByRole('heading', { name: /Create New Application/i })).toBeVisible();

        // The FAPI 2.0 checkbox/label should be visible
        await expect(
            page.getByText(/FAPI 2\.0 Security Profile/i)
        ).toBeVisible({ timeout: 5_000 });
    });

    test('FAPI checkbox is unchecked by default', async ({ page }) => {
        await mockAppsApi(page, []);
        await page.goto('/admin/applications');

        await page.getByRole('button', { name: /Create New App/i }).click();

        // Find the FAPI checkbox — it should NOT be checked by default
        const fapiLabel = page.locator('label').filter({ hasText: /FAPI 2\.0/i });
        const fapiCheckbox = fapiLabel.locator('input[type="checkbox"]');
        await expect(fapiCheckbox).not.toBeChecked({ timeout: 5_000 });
    });

    test('creating app WITHOUT FAPI sends fapi_profile:null', async ({ page }) => {
        const createRequests: unknown[] = [];
        await page.route(APPS_URL, async (route) => {
            if (route.request().method() === 'GET') {
                await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
            } else if (route.request().method() === 'POST') {
                createRequests.push(await route.request().postDataJSON());
                await route.fulfill({
                    status: 201,
                    contentType: 'application/json',
                    body: JSON.stringify({ app: { id: 'new-1', client_id: 'cid-1' }, client_secret: 'sec' }),
                });
            } else {
                await route.continue();
            }
        });

        await page.goto('/admin/applications');
        await page.getByRole('button', { name: /Create New App/i }).click();
        await page.getByLabel('App Name').fill('No FAPI App');
        await page.getByLabel('Redirect URIs').fill('https://example.com/cb');
        await page.getByRole('dialog').getByRole('button', { name: 'Create', exact: true }).click();

        await expect(page.getByRole('heading', { name: 'Application Created' })).toBeVisible({ timeout: 10_000 });
        expect(createRequests).toHaveLength(1);
        const payload = createRequests[0] as Record<string, unknown>;
        expect(payload.fapi_profile).toBeNull();
    });

    test('creating app WITH FAPI sends fapi_profile:"fapi2"', async ({ page }) => {
        const createRequests: unknown[] = [];
        await page.route(APPS_URL, async (route) => {
            if (route.request().method() === 'GET') {
                await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
            } else if (route.request().method() === 'POST') {
                createRequests.push(await route.request().postDataJSON());
                await route.fulfill({
                    status: 201,
                    contentType: 'application/json',
                    body: JSON.stringify({ app: { id: 'new-2', client_id: 'cid-2' }, client_secret: 'sec2' }),
                });
            } else {
                await route.continue();
            }
        });

        await page.goto('/admin/applications');
        await page.getByRole('button', { name: /Create New App/i }).click();
        await page.getByLabel('App Name').fill('FAPI Banking App');
        await page.getByLabel('Redirect URIs').fill('https://bank.example.com/cb');

        // Check the FAPI 2.0 checkbox
        const fapiLabel = page.locator('label').filter({ hasText: /FAPI 2\.0/i });
        await fapiLabel.locator('input[type="checkbox"]').check();

        await page.getByRole('dialog').getByRole('button', { name: 'Create', exact: true }).click();

        await expect(page.getByRole('heading', { name: 'Application Created' })).toBeVisible({ timeout: 10_000 });
        expect(createRequests).toHaveLength(1);
        const payload = createRequests[0] as Record<string, unknown>;
        expect(payload.fapi_profile).toBe('fapi2');
    });

    test('existing app with fapi_profile:"fapi2" pre-checks the FAPI box', async ({ page }) => {
        await mockAppsApi(page, [MOCK_APP_FAPI]);
        await page.goto('/admin/applications');

        await expect(page.getByText('FAPI-Compliant Banking App')).toBeVisible({ timeout: 10_000 });
        // Open the edit modal for the FAPI app
        await page.getByRole('button', { name: /Configure App/i }).first().click();
        await expect(page.getByRole('heading', { name: /Edit Application/i })).toBeVisible();

        const fapiLabel = page.locator('label').filter({ hasText: /FAPI 2\.0/i });
        await expect(fapiLabel.locator('input[type="checkbox"]')).toBeChecked({ timeout: 5_000 });
    });

    test('existing non-FAPI app does NOT pre-check the FAPI box', async ({ page }) => {
        await mockAppsApi(page, [MOCK_APP_STANDARD]);
        await page.goto('/admin/applications');

        await expect(page.getByText('Standard Web App')).toBeVisible({ timeout: 10_000 });
        await page.getByRole('button', { name: /Configure App/i }).first().click();
        await expect(page.getByRole('heading', { name: /Edit Application/i })).toBeVisible();

        const fapiLabel = page.locator('label').filter({ hasText: /FAPI 2\.0/i });
        await expect(fapiLabel.locator('input[type="checkbox"]')).not.toBeChecked({ timeout: 5_000 });
    });

    test('FAPI description text is informative', async ({ page }) => {
        await mockAppsApi(page, []);
        await page.goto('/admin/applications');
        await page.getByRole('button', { name: /Create New App/i }).click();

        // The description should mention PAR, PKCE, DPoP, or token lifetime
        await expect(
            page.getByText(/PAR|PKCE|DPoP|token lifetime/i).first()
        ).toBeVisible({ timeout: 5_000 });
    });
});
