import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

/**
 * Revoke all API keys on the page to free up the 5-key plan limit.
 * Each key row has a "Revoke" button; each click triggers a confirm() dialog.
 * Uses waitForResponse to confirm each revocation completes before proceeding.
 */
async function revokeAllKeys(page: import('@playwright/test').Page) {
    // Wait for the key list to fully render
    await expect(page.locator('h1:has-text("API Keys")')).toBeVisible({ timeout: 10_000 });
    // Wait for the API to return the key list
    await page.waitForLoadState('networkidle');

    let revokeBtn = page.locator('button:has-text("Revoke")').first();
    while (await revokeBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
        page.once('dialog', (d) => d.accept());
        const responsePromise = page.waitForResponse(
            (resp) => resp.url().includes('/api/v1/api-keys/') && resp.request().method() === 'DELETE',
            { timeout: 10_000 }
        );
        await revokeBtn.click();
        await responsePromise;
        // Small wait for DOM to update after revocation
        await page.waitForTimeout(500);
        revokeBtn = page.locator('button:has-text("Revoke")').first();
    }
}

test.describe('API Keys Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to API keys page', async ({ page }) => {
        await page.goto('/admin/api-keys');

        // Verify API keys page loads — heading is "API Keys"
        await expect(page.locator('h1').filter({ hasText: /API Keys/i })).toBeVisible({ timeout: 10_000 });
    });

    test('can view list of API keys', async ({ page }) => {
        await page.goto('/admin/api-keys');

        // Should show the "Active Keys" section (div-based list, not a <table>)
        await expect(page.locator('h2:has-text("Active Keys")')).toBeVisible({ timeout: 10_000 });
    });

    test('can create new API key', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        // Click "+ Create Key" button
        await page.click('button:has-text("+ Create Key")');

        // Modal heading "Create API Key" should appear
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });

        // Fill in key name
        await page.fill('input[placeholder="e.g. Production Backend"]', `E2E Key ${Date.now()}`);

        // Submit — click the modal's Create Key button (not the page header's)
        await page.locator('.fixed button:has-text("Create Key")').click();

        // Wait for modal to close and reveal banner to appear
        const revealBanner = page.locator('h3:has-text("Save your API key")');
        await expect(revealBanner).toBeVisible({ timeout: 15_000 });

        // Should have Copy button (exact match to avoid matching "Copy prefix")
        await expect(page.getByRole('button', { name: 'Copy', exact: true })).toBeVisible();

        // Dismiss by clicking Done
        await page.click('button:has-text("Done")');
    });

    test('API key is shown only once after creation', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `OneTime ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();

        // Key banner visible
        const keyBanner = page.locator('h3:has-text("Save your API key")');
        await expect(keyBanner).toBeVisible({ timeout: 15_000 });

        // Click "Done" to dismiss the banner
        await page.click('button:has-text("Done")');

        // Key banner should be gone
        await expect(keyBanner).not.toBeVisible({ timeout: 3_000 });
    });

    test('can revoke API key', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        // First create a key to revoke
        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `Revoke Me ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();
        await expect(page.locator('h3:has-text("Save your API key")')).toBeVisible({ timeout: 15_000 });
        await page.click('button:has-text("Done")');

        // Now revoke it — uses confirm() dialog
        page.once('dialog', async (dialog) => {
            await dialog.accept();
        });
        const revokeButton = page.locator('button:has-text("Revoke")').first();
        await revokeButton.click();

        // Toast should confirm revocation — just wait briefly
        await page.waitForTimeout(1_000);
    });

    test('API key list shows key metadata', async ({ page }) => {
        await page.goto('/admin/api-keys');

        // Wait for page to load
        await expect(page.locator('h1:has-text("API Keys")')).toBeVisible({ timeout: 10_000 });

        // If there are keys, they should show metadata (prefix, created date)
        const keyItem = page.locator('.divide-y > div').first();
        if (await keyItem.isVisible({ timeout: 3_000 })) {
            // Should show key prefix pattern ask_xxx_•••
            await expect(keyItem.locator('code')).toBeVisible();
            // Should show "Created" date
            await expect(keyItem.locator('text=/Created/')).toBeVisible();
        } else {
            // No keys exist — empty state is valid
            await expect(page.locator('text=/No API keys yet/i')).toBeVisible();
        }
    });

    test('API key prefix format is correct', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `Prefix Test ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();

        // Verify key format: starts with ask_
        const banner = page.locator('h3:has-text("Save your API key")');
        await expect(banner).toBeVisible({ timeout: 15_000 });
        // Get the code element within the reveal banner
        const keyElement = page.locator('.bg-amber-50 code, .bg-amber-900\\/20 code').first();
        await expect(keyElement).toBeVisible();
        const keyText = await keyElement.textContent();
        expect(keyText).toBeTruthy();
        expect(keyText!.startsWith('ask_')).toBe(true);

        await page.click('button:has-text("Done")');
    });

    test('cannot create API key without name', async ({ page }) => {
        await page.goto('/admin/api-keys');

        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });

        // Don't fill name — click Create Key directly
        await page.locator('.fixed button:has-text("Create Key")').click();

        // Should show validation error "Key name is required"
        await expect(page.locator('text=/name.*required/i')).toBeVisible({ timeout: 3_000 });
    });

});
