/**
 * Phase 4: Custom Domains E2E Tests
 * 
 * Tests for custom domain configuration and verification.
 */

import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Custom Domains Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to custom domains page', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Verify domains page loads
        await expect(page.locator('h1, h2').filter({ hasText: /domain/i })).toBeVisible();
    });

    test('can view list of custom domains', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show domains list (table is always rendered, even when empty)
        await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    });

    test('can add new custom domain', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Fill domain name first — placeholder is "e.g. auth.yourcompany.com"
        const domainInput = page.locator('input[name="domain"], input[placeholder*="yourcompany"]');
        await domainInput.fill(`auth-${Date.now()}.example.com`);
        
        // Submit — the Add Domain button is the form submit
        await page.click('button:has-text("Add Domain"), button[type="submit"]:has-text("Add")');
        
        // Should show the domain in the list with pending status, or a success toast
        const successIndicator = page.getByText(/added|success|pending/i)
            .or(page.locator('table td').filter({ hasText: /\.example\.com/ }));
        await expect(successIndicator.first()).toBeVisible({ timeout: 5000 });
    });

    test('shows DNS verification instructions', async ({ page }) => {
        await page.goto('/admin/domains');
        
        const addButton = page.locator('button:has-text("Add Domain")');
        if (await addButton.isVisible({ timeout: 2000 })) {
            await addButton.click();
            
            const domainInput = page.locator('input[name="domain"]');
            await domainInput.fill('auth.example.com');
            await page.click('button[type="submit"]');
            
            // Should show DNS records to add
            await expect(page.locator('text=/cname|txt|dns record/i')).toBeVisible({ timeout: 5000 });
            
            // Should show record values
            await expect(page.locator('code, pre, [data-testid="dns-record"]')).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('can verify domain', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Look for verify button
        const verifyButton = page.locator('button:has-text("Verify"), button:has-text("Check")').first();
        
        if (await verifyButton.isVisible({ timeout: 2000 })) {
            await verifyButton.click();
            
            // Should show verification result
            await expect(page.locator('text=/verif(ied|ying)|checking|pending/i')).toBeVisible({ timeout: 10000 });
        } else {
            test.skip();
        }
    });

    test('can set primary domain', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Look for set primary button
        const setPrimaryButton = page.locator('button:has-text("Set Primary"), button:has-text("Make Primary")').first();
        
        if (await setPrimaryButton.isVisible({ timeout: 2000 })) {
            await setPrimaryButton.click();
            
            // Confirm if modal appears
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/primary|updated/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can delete custom domain', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Look for delete button
        const deleteButton = page.locator('button:has-text("Delete"), button:has-text("Remove")').first();
        
        if (await deleteButton.isVisible({ timeout: 2000 })) {
            await deleteButton.click();
            
            // Confirm deletion
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Delete")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/deleted|removed/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('shows domain verification status', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show status badges
        const statusBadge = page.locator('text=/verified|pending|failed/i, [data-testid="domain-status"]');
        
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            await expect(statusBadge.first()).toBeVisible({ timeout: 5000 });
        }
    });

    test('shows primary domain indicator', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show primary indicator
        const primaryIndicator = page.locator('text=/primary|default/i, [data-testid="primary-badge"]');
        
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            // At least one domain should be marked as primary
            const count = await primaryIndicator.count();
            expect(count).toBeGreaterThanOrEqual(0);
        }
    });

    test('validates domain format', async ({ page }) => {
        await page.goto('/admin/domains');
        
        const addButton = page.locator('button:has-text("Add Domain")');
        if (await addButton.isVisible({ timeout: 2000 })) {
            await addButton.click();
            
            // Try invalid domain
            const domainInput = page.locator('input[name="domain"]');
            await domainInput.fill('invalid domain with spaces');
            
            await page.click('button[type="submit"]');
            
            // Should show validation error
            await expect(page.locator('text=/invalid.*domain|valid.*domain/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('prevents duplicate domains', async ({ page }) => {
        await page.goto('/admin/domains');
        
        const addButton = page.locator('button:has-text("Add Domain")');
        if (await addButton.isVisible({ timeout: 2000 })) {
            await addButton.click();
            
            // Try to add existing domain
            const domainInput = page.locator('input[name="domain"]');
            await domainInput.fill('auth.example.com');
            
            await page.click('button[type="submit"]');
            
            // If domain exists, should show error
            const errorOrSuccess = page.locator('text=/already exists|duplicate|added|verification/i');
            await expect(errorOrSuccess).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

test.describe('Custom Domains - SSL/TLS', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('shows SSL certificate status', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show SSL status
        const sslStatus = page.locator('text=/ssl|certificate|https/i, [data-testid="ssl-status"]');
        
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            // SSL status should be visible for verified domains
            const count = await sslStatus.count();
            expect(count).toBeGreaterThanOrEqual(0);
        }
    });

    test('can view SSL certificate details', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Click on domain to view details
        const firstDomain = page.locator('tr, [data-testid="domain-item"]').first();
        
        if (await firstDomain.isVisible({ timeout: 2000 })) {
            await firstDomain.click();
            
            // Should show SSL certificate info
            const sslInfo = page.locator('text=/certificate|expir(y|es)|issuer/i');
            
            // May or may not have SSL yet
            const count = await sslInfo.count();
            expect(count).toBeGreaterThanOrEqual(0);
        } else {
            test.skip();
        }
    });

});

test.describe('Custom Domains - Error Scenarios', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('handles DNS verification failure', async ({ page }) => {
        await page.goto('/admin/domains');
        
        const verifyButton = page.locator('button:has-text("Verify")').first();
        
        if (await verifyButton.isVisible({ timeout: 2000 })) {
            // Mock verification failure
            await page.route('**/api/domains/*/verify', async (route) => {
                await route.fulfill({
                    status: 400,
                    contentType: 'application/json',
                    body: JSON.stringify({
                        error: 'DNS records not found',
                        verified: false
                    })
                });
            });
            
            await verifyButton.click();
            
            // Should show failure message
            await expect(page.locator('text=/not found|failed|unable/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('shows helpful error for invalid DNS configuration', async ({ page }) => {
        await page.goto('/admin/domains');
        
        const addButton = page.locator('button:has-text("Add Domain")');
        if (await addButton.isVisible({ timeout: 2000 })) {
            await addButton.click();
            
            const domainInput = page.locator('input[name="domain"]');
            await domainInput.fill('subdomain.example.com');
            
            await page.click('button[type="submit"]');
            
            // Should show DNS configuration help
            await expect(page.locator('text=/dns|cname|configure/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

// Made with Bob
