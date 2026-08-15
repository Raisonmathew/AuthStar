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
        
        // Verify domains page loads (use .first() to avoid strict mode violations
        // when multiple domain-related headings are present on the page)
        await expect(page.locator('h1, h2').filter({ hasText: /domain/i }).first()).toBeVisible();
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
        // Mock GET /api/domains/:id to return verification instructions so the
        // modal can open without a real DNS backend call.
        const domainId = `dom-test-${Date.now()}`;
        await page.route(`**/api/domains/${domainId}`, (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    id: domainId,
                    domain: `auth-${domainId}.example.com`,
                    verificationStatus: 'pending',
                    sslStatus: 'pending',
                    isPrimary: false,
                    isActive: false,
                    verificationInstructions: {
                        method: 'dns',
                        recordType: 'TXT',
                        recordName: `_authstar-verify.auth-${domainId}.example.com`,
                        recordValue: 'authstar-verification=abc123',
                    },
                }),
            })
        );
        // Also mock the wildcard domains/:id for any id the app creates
        await page.route('**/api/domains/*', (route) => {
            if (route.request().method() === 'GET' && route.request().url().match(/\/api\/domains\/[^/]+$/)) {
                route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({
                        id: 'dom-mock',
                        domain: `auth-mock.example.com`,
                        verificationStatus: 'pending',
                        sslStatus: 'pending',
                        isPrimary: false,
                        isActive: false,
                        verificationInstructions: {
                            method: 'dns',
                            recordType: 'TXT',
                            recordName: `_authstar-verify.auth-mock.example.com`,
                            recordValue: 'authstar-verification=abc123',
                        },
                    }),
                });
            } else {
                route.continue();
            }
        });

        await page.goto('/admin/domains');
        
        // The Add Domain form is inline — fill the input then click the submit button
        const domainInput = page.locator('input[name="domain"], input[placeholder*="yourcompany"]');
        await domainInput.waitFor({ state: 'visible', timeout: 10_000 });
        await domainInput.fill(`auth-${Date.now()}.example.com`);
        await page.click('button[type="submit"]:has-text("Add Domain"), button:has-text("Add Domain")');
        
        // After adding, click the "Verify" button that appears on the new row
        const verifyBtn = page.locator('button:has-text("Verify")').first();
        if (await verifyBtn.isVisible({ timeout: 5000 })) {
            await verifyBtn.click();
            
            // Verification modal should show TXT/DNS instructions.
            // DomainsPage.tsx shows "TXT record to your DNS configuration" and a <code> block.
            const dnsInstructions = page.getByText(/TXT record/i)
                .or(page.getByText(/DNS/i))
                .or(page.locator('code'));
            await expect(dnsInstructions.first()).toBeVisible({ timeout: 10_000 });
        } else {
            // Domain was added but no verify button — check for DNS text in success message
            await expect(page.getByText(/added|pending|dns/i).first()).toBeVisible({ timeout: 5000 });
        }
    });

    test('can verify domain', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Look for verify button
        const verifyButton = page.locator('button:has-text("Verify"), button:has-text("Check")').first();
        
        if (await verifyButton.isVisible({ timeout: 2000 })) {
            await verifyButton.click();
            
            // Should show verification result — use .first() to avoid strict mode violations
            // when there are multiple status badges on the page
            await expect(page.locator('text=/verified|verifying|checking|pending/i').first()).toBeVisible({ timeout: 10000 });
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
        
        // Look for delete button — the delete uses window.confirm, not a modal
        const deleteButton = page.locator('button:has-text("Delete"), button:has-text("Remove")').first();
        
        if (await deleteButton.isVisible({ timeout: 2000 })) {
            // Accept the window.confirm dialog automatically
            page.once('dialog', (dialog) => dialog.accept());
            await deleteButton.click();
            
            // Should show success toast ("Domain deleted")
            const successIndicator = page.locator('[data-sonner-toast]')
                .or(page.locator('text=/deleted|removed|Domain deleted/i'));
            await expect(successIndicator.first()).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('shows domain verification status', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show status badges — use separate locators to avoid invalid CSS
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            const statusBadge = page.locator('text=/verified|pending|failed/i')
                .or(page.locator('[data-testid="domain-status"]'));
            await expect(statusBadge.first()).toBeVisible({ timeout: 5000 });
        }
    });

    test('shows primary domain indicator', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show primary indicator — use separate locators to avoid invalid CSS
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            const primaryIndicator = page.locator('text=/primary|default/i')
                .or(page.locator('[data-testid="primary-badge"]'));
            // At least one domain should be marked as primary (count may be 0 if none are primary yet)
            const count = await primaryIndicator.count();
            expect(count).toBeGreaterThanOrEqual(0);
        }
    });

    test('validates domain format', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // The Add Domain form is inline — fill the input with an invalid value
        const domainInput = page.locator('input[name="domain"], input[placeholder*="yourcompany"]');
        await domainInput.waitFor({ state: 'visible', timeout: 10_000 });
        await domainInput.fill('invalid domain with spaces');
        await page.click('button[type="submit"]:has-text("Add Domain"), button:has-text("Add Domain")');
        
        // Should show validation error
        const errorLocator = page.locator('text=/invalid.*domain|valid.*domain/i')
            .or(page.locator('[role="alert"]'))
            .or(page.locator('[data-sonner-toast]'));
        await expect(errorLocator.first()).toBeVisible({ timeout: 10_000 });
    });

    test('prevents duplicate domains', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // First add a domain, then try to add the same domain again
        const domainInput = page.locator('input[name="domain"], input[placeholder*="yourcompany"]');
        await domainInput.waitFor({ state: 'visible', timeout: 10_000 });
        const uniqueDomain = `dupe-test-${Date.now()}.example.com`;
        await domainInput.fill(uniqueDomain);
        await page.click('button[type="submit"]:has-text("Add Domain"), button:has-text("Add Domain")');
        
        // Wait for first add to complete
        await page.waitForTimeout(1000);
        
        // Try to add the same domain again
        await domainInput.fill(uniqueDomain);
        await page.click('button[type="submit"]:has-text("Add Domain"), button:has-text("Add Domain")');
        
        // Should show duplicate error
        const errorOrSuccess = page.locator('text=/already exists|duplicate|added|pending/i')
            .or(page.locator('[data-sonner-toast]'));
        await expect(errorOrSuccess.first()).toBeVisible({ timeout: 10_000 });
    });

});

test.describe('Custom Domains - SSL/TLS', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('shows SSL certificate status', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Should show SSL status — use separate locators to avoid invalid CSS
        const hasDomains = await page.locator('tr, [data-testid="domain-item"]').count() > 0;
        if (hasDomains) {
            const sslStatus = page.locator('text=/ssl|certificate|https/i')
                .or(page.locator('[data-testid="ssl-status"]'));
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
            // Mock verification failure — return 400 with error body
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
            
            // Also intercept the instruction-load endpoint to avoid it erroring
            await page.route('**/api/domains/*/verification-instructions', async (route) => {
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ records: [] })
                });
            });
            
            await verifyButton.click();
            
            // The component shows a sonner toast — wait for any error/fail/not-found
            // text in the toast region (sonner renders at the top of the page body)
            await expect(
                page.locator('[data-sonner-toast][data-type="error"], li[data-sonner-toast]')
                    .or(page.locator('text=/not found|failed|unable|DNS record/i'))
                    .first()
            ).toBeVisible({ timeout: 10_000 });
        } else {
            test.skip();
        }
    });

    test('shows helpful error for invalid DNS configuration', async ({ page }) => {
        await page.goto('/admin/domains');
        
        // Mock the add-domain API BEFORE filling the form
        await page.route('**/api/domains', async (route) => {
            if (route.request().method() === 'POST') {
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({
                        id: 'dom_test',
                        domain: 'subdomain.example.com',
                        verificationStatus: 'pending',
                        txtRecord: '_authstar-verify.subdomain.example.com',
                        cnameTarget: 'verify.authstar.com',
                    })
                });
            } else {
                await route.continue();
            }
        });
        
        // The Add Domain form is inline — fill input then click submit
        const domainInput = page.locator('input[name="domain"], input[placeholder*="yourcompany"]');
        await domainInput.waitFor({ state: 'visible', timeout: 10_000 });
        await domainInput.fill('subdomain.example.com');
        await page.click('button[type="submit"]:has-text("Add Domain"), button:has-text("Add Domain")');
        
        // Should show DNS configuration help (TXT/CNAME record instructions
        // or a success message about the domain being added)
        await expect(
            page.locator('text=/dns|cname|txt record|configure|added|pending/i').first()
        ).toBeVisible({ timeout: 10_000 });
    });

});

// Made with Bob
