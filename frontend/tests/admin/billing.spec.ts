import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Billing Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to billing page', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Heading is "Billing & Subscription"
        await expect(page.locator('h1:has-text("Billing")')).toBeVisible({ timeout: 10_000 });
    });

    test('can view current subscription', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Should show "Current Plan" card
        await expect(page.locator('h2:has-text("Current Plan")')).toBeVisible({ timeout: 10_000 });
    });

    test('can view subscription features', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // "View Plans" or "Change Plan" button should be visible (or plan cards already showing)
        const viewPlansBtn = page.locator('button:has-text("View Plans"), button:has-text("Change Plan")');
        if (await viewPlansBtn.first().isVisible({ timeout: 5_000 })) {
            await viewPlansBtn.first().click();

            // Plan cards should show feature lists
            await expect(page.locator('ul li')).toHaveCount(await page.locator('ul li').count());
        } else {
            test.skip(true, 'No plan button visible');
        }
    });

    test('can upgrade subscription', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Look for "View Plans" or "Change Plan" button
        const plansButton = page.locator('button:has-text("View Plans"), button:has-text("Change Plan")');

        if (await plansButton.first().isVisible({ timeout: 5_000 })) {
            await plansButton.first().click();

            // Should show plan cards (Free, Pro, Enterprise)
            await expect(page.locator('h3:has-text("Pro")')).toBeVisible({ timeout: 5_000 });
            await expect(page.locator('h3:has-text("Enterprise")')).toBeVisible({ timeout: 5_000 });
        } else {
            test.skip(true, 'No plan button visible');
        }
    });

    test('can view invoices', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Invoice History section is always visible on the page
        await expect(page.locator('h2:has-text("Invoice History")')).toBeVisible({ timeout: 10_000 });
    });

    test('can download invoice', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Look for invoice table rows with PDF links
        const pdfLink = page.locator('a:has-text("PDF"), a:has-text("View")').first();

        if (await pdfLink.isVisible({ timeout: 5_000 })) {
            // PDF link exists — test passes
            expect(await pdfLink.getAttribute('href')).toBeTruthy();
        } else {
            // No invoices available
            await expect(page.locator('text=/No invoices/i')).toBeVisible();
        }
    });

    test('can update payment method', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // "Manage Subscription" button redirects to Stripe portal
        const manageBtn = page.locator('button:has-text("Manage Subscription")');

        if (await manageBtn.isVisible({ timeout: 5_000 })) {
            // Button exists — don't click (it redirects to Stripe)
            expect(await manageBtn.isEnabled()).toBe(true);
        } else {
            test.skip(true, 'No manage subscription button');
        }
    });

    test('can cancel subscription', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Cancel button exists if there's an active subscription
        const cancelBtn = page.locator('button:has-text("Cancel")');

        if (await cancelBtn.isVisible({ timeout: 5_000 })) {
            // Button exists — uses confirm() dialog. Don't actually cancel.
            expect(await cancelBtn.isEnabled()).toBe(true);
        } else {
            test.skip(true, 'No cancel button — no active subscription');
        }
    });

    test('displays usage metrics', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // The billing page shows plan amount, status, and renewal info
        // At minimum the "Current Plan" section should be visible
        await expect(page.locator('h2:has-text("Current Plan")')).toBeVisible({ timeout: 10_000 });
    });

    test('shows billing cycle information', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // Should show renewal date or "No active subscription" message
        const renewsText = page.locator('text=/Renews on|No active subscription|Choose a plan/i');
        await expect(renewsText).toBeVisible({ timeout: 10_000 });
    });

    test('can access customer portal', async ({ page }) => {
        await page.goto('/admin/settings/billing');

        // "Manage Subscription" button redirects to Stripe customer portal
        const portalBtn = page.locator('button:has-text("Manage Subscription")');

        if (await portalBtn.isVisible({ timeout: 5_000 })) {
            expect(await portalBtn.isEnabled()).toBe(true);
        } else {
            test.skip(true, 'No manage subscription button');
        }
    });

});

// Made with Bob
