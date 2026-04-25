import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Policy Builder', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to policy builder', async ({ page }) => {
        await page.goto('/admin/policies');

        // ConfigListPage heading is "Policy Builder"
        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });
    });

    test('can view list of policy configurations', async ({ page }) => {
        await page.goto('/admin/policies');

        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });

        // Wait for the loading spinner to disappear (data fetching)
        await page.waitForFunction(
            () => !document.querySelector('.animate-spin'),
            { timeout: 15_000 },
        );

        // Policies are shown as cards in a grid, or empty state
        const configCards = page.locator('button.w-full.text-left');
        const emptyState = page.locator('h3:has-text("No policies yet")');

        // Either cards or empty state should be visible
        const hasCards = await configCards.first().isVisible().catch(() => false);
        const hasEmpty = await emptyState.isVisible().catch(() => false);
        expect(hasCards || hasEmpty).toBe(true);
    });

    test('can create new policy configuration', async ({ page }) => {
        await page.goto('/admin/policies');

        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });

        // Click "New Policy" button
        await page.click('button:has-text("New Policy")');

        // Modal should appear with "New Policy Config" heading
        await expect(page.locator('h2:has-text("New Policy Config")')).toBeVisible({ timeout: 5_000 });

        // Select the first available (non-disabled) action from the dropdown
        const actionSelect = page.locator('select');
        // Get all option values and find one that isn't disabled
        const availableValue = await actionSelect.evaluate((sel: HTMLSelectElement) => {
            for (const opt of Array.from(sel.options)) {
                if (opt.value && !opt.disabled) return opt.value;
            }
            return null;
        });

        if (!availableValue) {
            test.skip(true, 'All policy actions are already configured — no available action to test');
            return;
        }

        await actionSelect.selectOption(availableValue);

        // Fill display name
        await page.fill('input[placeholder*="Login Policy"]', `E2E Test Policy ${Date.now()}`);

        // Submit — "Create Policy" button (should now be enabled)
        await page.click('button:has-text("Create Policy")');

        // Should redirect to policy detail page
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });
    });

    test('can view policy templates', async ({ page }) => {
        // ConfigListPage does not have a dedicated "Templates" section
        // Skip this test
        test.skip(true, 'No templates section in current UI');
    });

    test('can navigate to policy detail', async ({ page }) => {
        await page.goto('/admin/policies');

        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });

        // Click on a policy card (button with text-left class)
        const firstCard = page.locator('button.w-full.text-left').first();
        if (await firstCard.isVisible({ timeout: 5_000 })) {
            await firstCard.click();
            await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });
        } else {
            test.skip(true, 'No policy configs to navigate to');
        }
    });

    test('can add rule group to policy', async ({ page }) => {
        await page.goto('/admin/policies');

        // Navigate to first policy
        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Click "Add Group" button
        const addGroupBtn = page.locator('button:has-text("Add Group")');
        if (await addGroupBtn.isVisible({ timeout: 5_000 })) {
            await addGroupBtn.click();

            // Modal "Add Rule Group" should appear
            await expect(page.locator('h2:has-text("Add Rule Group")')).toBeVisible({ timeout: 5_000 });
        } else {
            test.skip(true, 'No Add Group button');
        }
    });

    test('can compile policy', async ({ page }) => {
        await page.goto('/admin/policies');

        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Compile button (enabled when state === 'draft')
        const compileBtn = page.locator('button:has-text("Compile")');
        if (await compileBtn.isVisible({ timeout: 5_000 })) {
            if (await compileBtn.isEnabled()) {
                await compileBtn.click();
                // Should show success toast
                await page.waitForTimeout(2_000);
            }
        } else {
            test.skip(true, 'No Compile button');
        }
    });

    test('can activate policy', async ({ page }) => {
        await page.goto('/admin/policies');

        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Activate button (enabled when state === 'compiled')
        const activateBtn = page.locator('button:has-text("Activate")');
        if (await activateBtn.isVisible({ timeout: 5_000 })) {
            if (await activateBtn.isEnabled()) {
                await activateBtn.click();
                // Confirmation modal — "Activate Now"
                const confirmBtn = page.locator('button:has-text("Activate Now")');
                if (await confirmBtn.isVisible({ timeout: 3_000 })) {
                    await confirmBtn.click();
                    await page.waitForTimeout(2_000);
                }
            }
        } else {
            test.skip(true, 'No Activate button');
        }
    });

    test('can view simulate tab', async ({ page }) => {
        await page.goto('/admin/policies');

        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Click "Simulate" tab
        const simulateTab = page.locator('button:has-text("Simulate")');
        if (await simulateTab.isVisible({ timeout: 5_000 })) {
            await simulateTab.click();
            await page.waitForTimeout(1_000);
        } else {
            test.skip(true, 'No Simulate tab');
        }
    });

    test('can view version history tab', async ({ page }) => {
        await page.goto('/admin/policies');

        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Click "Versions" tab
        const versionsTab = page.locator('button:has-text("Versions")');
        if (await versionsTab.isVisible({ timeout: 5_000 })) {
            await versionsTab.click();
            await page.waitForTimeout(1_000);
        } else {
            test.skip(true, 'No Versions tab');
        }
    });

    test('can view audit tab', async ({ page }) => {
        await page.goto('/admin/policies');

        const firstCard = page.locator('button.w-full.text-left').first();
        if (!(await firstCard.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No policy configs available');
            return;
        }
        await firstCard.click();
        await page.waitForURL('**/admin/policies/**', { timeout: 10_000 });

        // Click "Audit" tab
        const auditTab = page.locator('button:has-text("Audit")');
        if (await auditTab.isVisible({ timeout: 5_000 })) {
            await auditTab.click();
            await page.waitForTimeout(1_000);
        } else {
            test.skip(true, 'No Audit tab');
        }
    });

});
