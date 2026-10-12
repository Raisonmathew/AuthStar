import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

/**
 * Revoke all active API keys on the page to free up the 5-key plan limit.
 *
 * Uses the "type prefix to confirm" modal (US-06 — window.confirm replaced).
 * For each key: click Revoke → read prefix from modal → type it → confirm.
 */
async function revokeAllKeys(page: import('@playwright/test').Page) {
    await expect(page.locator('h1:has-text("API Keys")')).toBeVisible({ timeout: 10_000 });
    await page.waitForLoadState('networkidle');

    const MAX_REVOCATIONS = 20;
    let count = 0;

    while (count < MAX_REVOCATIONS) {
        const revokeBtn = page.locator('button:has-text("Revoke")').first();
        const visible = await revokeBtn.isVisible({ timeout: 3_000 }).catch(() => false);
        if (!visible) break;
        count++;

        await revokeBtn.click();

        // Wait for the modal
        const modal = page.locator('h3:has-text("Revoke API Key")');
        const modalVisible = await modal.isVisible({ timeout: 5_000 }).catch(() => false);
        if (!modalVisible) {
            // No modal — key may already be gone; try next
            await page.waitForTimeout(300);
            continue;
        }

        // Read the required prefix and type it
        const prefix = await page.locator('.fixed code.font-semibold').textContent().catch(() => null);
        if (!prefix) {
            await page.locator('.fixed button:has-text("Cancel")').click().catch(() => {});
            break;
        }
        await page.locator('.fixed input[type="text"]').fill(prefix);

        try {
            const responsePromise = page.waitForResponse(
                (resp) => resp.url().includes('/api/v1/api-keys/') && resp.request().method() === 'DELETE',
                { timeout: 10_000 },
            );
            await page.locator('.fixed button:has-text("Revoke Key")').click();
            await responsePromise;
        } catch {
            break;
        }

        await page.waitForTimeout(300);
    }
}

test.describe('API Keys Management', () => {

    test.beforeEach(async ({ page }) => {
        // Mock EIAA runtime keys at the context level so it survives every
        // navigation within the test (goto('/admin/api-keys'), internal redirects,
        // etc.). Without this the AppLoadingGuard spinner never resolves and the
        // test times out with a blank "Loading..." page.
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
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

    test('can revoke API key using prefix-confirmation modal (US-06)', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        // Create a key to revoke
        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `Revoke Me ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();
        await expect(page.locator('h3:has-text("Save your API key")')).toBeVisible({ timeout: 15_000 });
        await page.click('button:has-text("Done")');

        // Click Revoke — must open the confirmation modal (not window.confirm)
        const revokeButton = page.locator('button:has-text("Revoke")').first();
        await revokeButton.click();

        // Confirmation modal must be visible (US-06 AC: "Type the key prefix to confirm")
        await expect(page.locator('h3:has-text("Revoke API Key")')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('text=/type the key prefix/i')).toBeVisible();

        // Revoke button in modal is disabled until prefix is typed
        const confirmRevokeBtn = page.locator('.fixed button:has-text("Revoke Key")');
        await expect(confirmRevokeBtn).toBeDisabled();

        // Type the prefix into the confirmation input
        const prefixCode = page.locator('.fixed code.font-semibold');
        const prefix = await prefixCode.textContent();
        expect(prefix).toBeTruthy();
        await page.locator('.fixed input[type="text"]').fill(prefix!);

        // Revoke button becomes enabled once prefix matches
        await expect(confirmRevokeBtn).toBeEnabled({ timeout: 2_000 });

        // Confirm the revocation
        const deleteResponse = page.waitForResponse(
            (resp) => resp.url().includes('/api/v1/api-keys/') && resp.request().method() === 'DELETE',
            { timeout: 10_000 },
        );
        await confirmRevokeBtn.click();
        await deleteResponse;

        // Modal must close
        await expect(page.locator('h3:has-text("Revoke API Key")')).not.toBeVisible({ timeout: 5_000 });

        // Toast confirms revocation — use the front-most Sonner toast (data-front=true).
        // Multiple stale toasts from revokeAllKeys may still be in the DOM; .first()
        // picks the one with data-front="true" which is the most recent.
        await expect(
            page.locator('[data-sonner-toast][data-front="true"]')
        ).toBeVisible({ timeout: 5_000 });
    });

    test('revoke confirmation modal blocks revocation when wrong prefix typed', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        // Create a key
        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `Block Test ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();
        await expect(page.locator('h3:has-text("Save your API key")')).toBeVisible({ timeout: 15_000 });
        await page.click('button:has-text("Done")');

        // Open revoke modal
        await page.locator('button:has-text("Revoke")').first().click();
        await expect(page.locator('h3:has-text("Revoke API Key")')).toBeVisible({ timeout: 5_000 });

        // Type wrong prefix
        await page.locator('.fixed input[type="text"]').fill('wrongprefix');

        // Confirm button must remain disabled
        await expect(page.locator('.fixed button:has-text("Revoke Key")')).toBeDisabled();

        // Cancel closes modal without revoking
        await page.locator('.fixed button:has-text("Cancel")').click();
        await expect(page.locator('h3:has-text("Revoke API Key")')).not.toBeVisible({ timeout: 3_000 });
    });

    test('revoked keys appear in Revoked section (US-06)', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await revokeAllKeys(page);

        // Create a key
        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")')).toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', `Revoked Section ${Date.now()}`);
        await page.locator('.fixed button:has-text("Create Key")').click();
        await expect(page.locator('h3:has-text("Save your API key")')).toBeVisible({ timeout: 15_000 });
        await page.click('button:has-text("Done")');

        // Revoke via modal
        await page.locator('button:has-text("Revoke")').first().click();
        await expect(page.locator('h3:has-text("Revoke API Key")')).toBeVisible({ timeout: 5_000 });
        const prefix = await page.locator('.fixed code.font-semibold').textContent();
        await page.locator('.fixed input[type="text"]').fill(prefix!);
        const deleteResp = page.waitForResponse(
            (r) => r.url().includes('/api/v1/api-keys/') && r.request().method() === 'DELETE',
            { timeout: 10_000 },
        );
        await page.locator('.fixed button:has-text("Revoke Key")').click();
        await deleteResp;

        // "Revoked Keys" section must appear with revocation timestamp
        await expect(page.locator('h2:has-text("Revoked Keys")')).toBeVisible({ timeout: 5_000 });
        // The revoked key row should show "Revoked" badge
        await expect(page.locator('span:has-text("Revoked")').first()).toBeVisible({ timeout: 3_000 });
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
