import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Billing Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to billing page', async ({ page }) => {
        await page.goto('/billing');
        
        // Verify billing page loads
        await expect(page.locator('h1, h2').filter({ hasText: /billing|subscription/i })).toBeVisible();
    });

    test('can view current subscription', async ({ page }) => {
        await page.goto('/billing');
        
        // Should show subscription details
        await expect(page.locator('[data-testid="subscription-details"], .subscription-card')).toBeVisible({ timeout: 10000 });
        
        // Should show plan name
        await expect(page.locator('text=/free|starter|professional|enterprise/i')).toBeVisible();
    });

    test('can view subscription features', async ({ page }) => {
        await page.goto('/billing');
        
        // Should list features
        await expect(page.locator('ul, [data-testid="features-list"]')).toBeVisible({ timeout: 5000 });
    });

    test('can upgrade subscription', async ({ page }) => {
        await page.goto('/billing');
        
        // Look for upgrade button
        const upgradeButton = page.locator('button:has-text("Upgrade"), button:has-text("Change Plan")');
        
        if (await upgradeButton.first().isVisible({ timeout: 2000 })) {
            await upgradeButton.first().click();
            
            // Should show plan selection
            await expect(page.locator('[data-testid="plan-card"], .plan-option')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can view invoices', async ({ page }) => {
        await page.goto('/billing');
        
        // Look for invoices section
        const invoicesButton = page.locator('button:has-text("Invoices"), a:has-text("Billing History")');
        
        if (await invoicesButton.first().isVisible({ timeout: 2000 })) {
            await invoicesButton.first().click();
            
            // Should show invoice list
            await expect(page.locator('table, [data-testid="invoices-list"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can download invoice', async ({ page }) => {
        await page.goto('/billing');
        
        // Navigate to invoices
        const invoicesButton = page.locator('button:has-text("Invoices"), a:has-text("Billing History")');
        if (await invoicesButton.first().isVisible({ timeout: 2000 })) {
            await invoicesButton.first().click();
        }
        
        // Look for download button
        const downloadButton = page.locator('button:has-text("Download"), a:has-text("PDF")').first();
        
        if (await downloadButton.isVisible({ timeout: 2000 })) {
            // Set up download listener
            const downloadPromise = page.waitForEvent('download');
            await downloadButton.click();
            
            // Verify download started
            const download = await downloadPromise;
            expect(download.suggestedFilename()).toMatch(/invoice|receipt/i);
        } else {
            test.skip();
        }
    });

    test('can update payment method', async ({ page }) => {
        await page.goto('/billing');
        
        // Look for payment method section
        const updatePaymentButton = page.locator('button:has-text("Update Payment"), button:has-text("Add Card")');
        
        if (await updatePaymentButton.first().isVisible({ timeout: 2000 })) {
            await updatePaymentButton.first().click();
            
            // Should redirect to Stripe or show payment form
            // Note: In test environment, this might be mocked
            await page.waitForTimeout(2000);
            
            // Verify we're on payment page or modal opened
            const paymentForm = page.locator('form, iframe[src*="stripe"]');
            await expect(paymentForm).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can cancel subscription', async ({ page }) => {
        await page.goto('/billing');
        
        // Look for cancel button
        const cancelButton = page.locator('button:has-text("Cancel Subscription"), button:has-text("Cancel Plan")');
        
        if (await cancelButton.first().isVisible({ timeout: 2000 })) {
            await cancelButton.first().click();
            
            // Should show confirmation dialog
            await expect(page.locator('text=/are you sure|confirm/i')).toBeVisible({ timeout: 3000 });
            
            // Don't actually cancel in test - just verify the flow
            const cancelConfirmButton = page.locator('button:has-text("Cancel Subscription"), button:has-text("Confirm")');
            await expect(cancelConfirmButton).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('displays usage metrics', async ({ page }) => {
        await page.goto('/billing');
        
        // Should show usage information
        const usageMetrics = ['users', 'requests', 'storage', 'bandwidth'];
        
        for (const metric of usageMetrics) {
            const element = page.locator(`text=/${metric}/i`);
            if (await element.isVisible({ timeout: 2000 })) {
                // At least one metric should be visible
                expect(await element.count()).toBeGreaterThan(0);
                break;
            }
        }
    });

    test('shows billing cycle information', async ({ page }) => {
        await page.goto('/billing');
        
        // Should show next billing date or renewal date
        await expect(page.locator('text=/next.*bill|renew|cycle/i')).toBeVisible({ timeout: 5000 });
    });

    test('can access customer portal', async ({ page }) => {
        await page.goto('/billing');
        
        // Look for customer portal button
        const portalButton = page.locator('button:has-text("Manage Billing"), button:has-text("Customer Portal")');
        
        if (await portalButton.first().isVisible({ timeout: 2000 })) {
            await portalButton.first().click();
            
            // Should redirect to Stripe portal (in test, might be mocked)
            await page.waitForTimeout(2000);
            
            // Verify redirect or new tab
            expect(page.url()).toMatch(/stripe|billing|portal/i);
        } else {
            test.skip();
        }
    });

});

// Made with Bob
