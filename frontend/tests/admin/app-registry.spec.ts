import { test, expect } from '@playwright/test';
import { loginAsAdmin } from '../fixtures/test-utils';

test.describe('App Registry CRUD + Security', () => {
  test('create, update, rotate secret, and delete app', async ({ page }) => {
    const suffix = Date.now().toString();
    const appName = `Playwright Managed App ${suffix}`;
    const updatedAppName = `Playwright Managed App Updated ${suffix}`;

    await loginAsAdmin(page);

    await page.goto('/admin/applications');
    await expect(page.getByRole('heading', { name: 'App Registry' })).toBeVisible();

    await page.getByRole('button', { name: 'Create New App' }).click();
    await expect(page.getByRole('heading', { name: 'Create New Application' })).toBeVisible();

    await page.getByLabel('App Name').fill(appName);
    await page.locator('select[name="app-type"]').selectOption('web');
    await page.getByLabel('Redirect URIs (comma separated)').fill('https://example.com/callback');

    await page.getByRole('checkbox', { name: 'Client Credentials' }).check();
    await page.getByRole('checkbox', { name: 'Enforce PKCE' }).check();
    await page.getByLabel('Allowed Origins (comma separated)').fill('https://example.com');

    await page.getByRole('dialog').getByRole('button', { name: 'Create', exact: true }).click();

    await expect(page.getByRole('heading', { name: 'Application Created' })).toBeVisible();
    await expect(page.getByText('Client Secret', { exact: true })).toBeVisible();

      // Hardening check: the app list API must not expose client_secret_hash.
      const listResponse = await page.request.get('/api/admin/v1/apps');
      expect(listResponse.ok()).toBeTruthy();
      const listedApps = await listResponse.json();
      expect(Array.isArray(listedApps)).toBeTruthy();
      const createdApp = listedApps.find((app: Record<string, unknown>) => app.name === appName);
      expect(createdApp).toBeTruthy();
      expect('client_secret_hash' in (createdApp as Record<string, unknown>)).toBeFalsy();

    await page.getByRole('button', { name: 'I have copied this secret' }).click();

    await expect(page.getByRole('heading', { name: appName }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Configure App' }).first().click();
    await expect(page.getByRole('dialog', { name: 'Edit Application' }).getByText('Client Secret', { exact: true })).toHaveCount(0);

    await page.getByLabel('App Name').fill(updatedAppName);
    await page.getByLabel('Redirect URIs (comma separated)').fill('https://example.com/callback, https://example.com/callback-2');
    await page.getByRole('dialog').getByRole('button', { name: 'Save Changes', exact: true }).click();

    await expect(page.getByRole('heading', { name: updatedAppName }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Configure App' }).first().click();

    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    await page.getByRole('button', { name: 'Rotate Client Secret' }).click();
    await expect(page.getByRole('heading', { name: 'Client Secret Rotated' })).toBeVisible();
    await page.getByRole('button', { name: 'I have copied this secret' }).click();

    await page.getByRole('button', { name: 'Configure App' }).first().click();
    await expect(page.getByRole('dialog', { name: 'Edit Application' }).getByText('Client Secret', { exact: true })).toHaveCount(0);
    page.once('dialog', async (dialog) => {
      await dialog.accept();
    });
    await page.getByRole('button', { name: 'Delete Application' }).click();

    await expect(page.getByRole('heading', { name: updatedAppName })).toHaveCount(0);
  });
});
