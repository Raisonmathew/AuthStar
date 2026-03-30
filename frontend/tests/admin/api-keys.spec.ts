import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('API Keys Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to API keys page', async ({ page }) => {
        await page.goto('/api-keys');
        
        // Verify API keys page loads
        await expect(page.locator('h1, h2').filter({ hasText: /api.*key/i })).toBeVisible();
    });

    test('can view list of API keys', async ({ page }) => {
        await page.goto('/api-keys');
        
        // Should show table or list of API keys
        await expect(page.locator('table, [role="table"], [data-testid="api-keys-list"]')).toBeVisible({ timeout: 10000 });
    });

    test('can create new API key', async ({ page }) => {
        await page.goto('/api-keys');
        
        // Click create button
        const createButton = page.locator('button:has-text("Create"), button:has-text("New"), button:has-text("Add")');
        await createButton.first().click();
        
        // Fill in API key details
        const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
        if (await nameInput.isVisible({ timeout: 2000 })) {
            await nameInput.fill('Test API Key');
        }
        
        const descInput = page.locator('input[name="description"], textarea[name="description"]');
        if (await descInput.isVisible({ timeout: 2000 })) {
            await descInput.fill('Test API key for E2E testing');
        }
        
        // Submit
        await page.click('button[type="submit"]:has-text("Create"), button:has-text("Generate")');
        
        // Should show the generated API key (only shown once)
        await expect(page.locator('code, pre, [data-testid="api-key-value"]').filter({ hasText: /ask_/ })).toBeVisible({ timeout: 5000 });
        
        // Should have copy button
        await expect(page.locator('button:has-text("Copy")')).toBeVisible();
    });

    test('API key is shown only once after creation', async ({ page }) => {
        await page.goto('/api-keys');
        
        const createButton = page.locator('button:has-text("Create"), button:has-text("New")');
        await createButton.first().click();
        
        const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
        if (await nameInput.isVisible({ timeout: 2000 })) {
            await nameInput.fill('One-time Display Key');
        }
        
        await page.click('button[type="submit"]:has-text("Create"), button:has-text("Generate")');
        
        // Key should be visible
        const keyElement = page.locator('code, pre, [data-testid="api-key-value"]').filter({ hasText: /ask_/ });
        await expect(keyElement).toBeVisible({ timeout: 5000 });
        
        // Close modal or navigate away
        const closeButton = page.locator('button:has-text("Close"), button:has-text("Done"), button[aria-label="Close"]');
        if (await closeButton.isVisible({ timeout: 2000 })) {
            await closeButton.click();
        }
        
        // Key should no longer be visible in the list (only prefix shown)
        await expect(keyElement).not.toBeVisible({ timeout: 2000 });
    });

    test('can revoke API key', async ({ page }) => {
        await page.goto('/api-keys');
        
        // Wait for list to load
        await page.waitForSelector('table, [role="table"], [data-testid="api-keys-list"]', { timeout: 10000 });
        
        // Look for revoke/delete button
        const revokeButton = page.locator('button:has-text("Revoke"), button:has-text("Delete")').first();
        
        if (await revokeButton.isVisible({ timeout: 2000 })) {
            await revokeButton.click();
            
            // Confirm revocation
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Revoke")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success message
            await expect(page.locator('text=/revoked|deleted|removed/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            // No API keys to revoke
            test.skip();
        }
    });

    test('API key list shows key metadata', async ({ page }) => {
        await page.goto('/api-keys');
        
        await page.waitForSelector('table, [role="table"], [data-testid="api-keys-list"]', { timeout: 10000 });
        
        // Should show key name
        await expect(page.locator('td, [role="cell"]').first()).toBeVisible();
        
        // Should show created date or last used
        const datePattern = /\d{4}-\d{2}-\d{2}|\d+\s+(second|minute|hour|day|week|month)s?\s+ago|never/i;
        await expect(page.locator(`text=${datePattern}`).first()).toBeVisible({ timeout: 5000 });
    });

    test('API key prefix format is correct', async ({ page }) => {
        await page.goto('/api-keys');
        
        const createButton = page.locator('button:has-text("Create"), button:has-text("New")');
        await createButton.first().click();
        
        const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
        if (await nameInput.isVisible({ timeout: 2000 })) {
            await nameInput.fill('Format Test Key');
        }
        
        await page.click('button[type="submit"]:has-text("Create"), button:has-text("Generate")');
        
        // Verify key format: ask_[32 hex chars]_[32 hex chars]
        const keyElement = page.locator('code, pre, [data-testid="api-key-value"]');
        const keyText = await keyElement.textContent();
        
        expect(keyText).toMatch(/^ask_[a-f0-9]{32}_[a-f0-9]{32}$/);
    });

    test('cannot create API key without name', async ({ page }) => {
        await page.goto('/api-keys');
        
        const createButton = page.locator('button:has-text("Create"), button:has-text("New")');
        await createButton.first().click();
        
        // Try to submit without filling name
        const submitButton = page.locator('button[type="submit"]:has-text("Create"), button:has-text("Generate")');
        
        // Button should be disabled or show validation error
        if (await submitButton.isEnabled()) {
            await submitButton.click();
            await expect(page.locator('text=/name.*required|required.*field/i, [role="alert"]')).toBeVisible({ timeout: 3000 });
        } else {
            expect(await submitButton.isDisabled()).toBe(true);
        }
    });

});

// Made with Bob
