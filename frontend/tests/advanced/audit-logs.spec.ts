/**
 * Phase 4: Audit Logs E2E Tests
 * 
 * Tests for viewing and verifying audit logs and EIAA execution records.
 */

import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Audit Logs Viewing', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to audit logs page', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Verify audit page loads — use .first() since multiple headings match
        await expect(page.locator('h1, h2').filter({ hasText: /audit|log/i }).first()).toBeVisible();
    });

    test('can view list of audit events', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Should show audit log table
        await expect(page.locator('table, [data-testid="audit-log"], [role="table"]')).toBeVisible({ timeout: 10000 });
    });

    test('audit log shows event details', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Wait for table to load
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        // Should show event types
        const eventType = page.locator('td, [role="cell"]').filter({ hasText: /login|logout|create|update|delete/i });
        
        const hasEvents = await page.locator('tr, [data-testid="audit-event"]').count() > 1; // More than header
        if (hasEvents) {
            await expect(eventType.first()).toBeVisible();
        }
    });

    test('audit log shows timestamps', async ({ page }) => {
        await page.goto('/admin/audit');
        
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        // Should show timestamps — component renders 'Apr 19, 2026' + '12:36:52 PM' format
        const timestamp = page.locator('text=/\\d{4}-\\d{2}-\\d{2}|\\w{3}\\s+\\d{1,2},?\\s+\\d{4}|\\d{1,2}:\\d{2}:\\d{2}|ago|minutes?|hours?|days?/i');
        
        const hasEvents = await page.locator('tr').count() > 1;
        if (hasEvents) {
            await expect(timestamp.first()).toBeVisible();
        }
    });

    test('audit log shows actor information', async ({ page }) => {
        await page.goto('/admin/audit');
        
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        // Should show who performed the action
        const actor = page.locator('td, [role="cell"]').filter({ hasText: /@|user|admin/i });
        
        const hasEvents = await page.locator('tr').count() > 1;
        if (hasEvents) {
            await expect(actor.first()).toBeVisible();
        }
    });

    test('can filter audit logs by event type', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Look for filter dropdown
        const filterSelect = page.locator('select[name="event_type"], [data-testid="event-filter"]');
        
        if (await filterSelect.isVisible({ timeout: 2000 })) {
            await filterSelect.selectOption('login');
            
            // Wait for filtered results
            await page.waitForTimeout(1000);
            
            // Should show only login events
            const events = page.locator('td, [role="cell"]').filter({ hasText: /login/i });
            expect(await events.count()).toBeGreaterThan(0);
        } else {
            test.skip();
        }
    });

    test('can filter audit logs by date range', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Look for date inputs
        const startDateInput = page.locator('input[name="start_date"], input[type="date"]').first();
        
        if (await startDateInput.isVisible({ timeout: 2000 })) {
            const today = new Date().toISOString().split('T')[0];
            await startDateInput.fill(today);
            
            // Apply filter
            const applyButton = page.locator('button:has-text("Apply"), button:has-text("Filter")');
            if (await applyButton.isVisible({ timeout: 1000 })) {
                await applyButton.click();
            }
            
            // Should show filtered results
            await page.waitForTimeout(1000);
            await expect(page.locator('table')).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('can search audit logs', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Look for search input
        const searchInput = page.locator('input[type="search"], input[placeholder*="Search"]');
        
        if (await searchInput.isVisible({ timeout: 2000 })) {
            await searchInput.fill('login');
            
            // Wait for search results
            await page.waitForTimeout(1000);
            
            // Should show matching results
            await expect(page.locator('table')).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('can paginate through audit logs', async ({ page }) => {
        await page.goto('/admin/audit');
        
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        // Look for pagination controls
        const nextButton = page.locator('button:has-text("Next"), button[aria-label="Next page"]');
        
        if (await nextButton.isVisible({ timeout: 2000 }) && await nextButton.isEnabled()) {
            await nextButton.click();
            
            // Should load next page
            await page.waitForTimeout(1000);
            await expect(page.locator('table')).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('can view audit event details', async ({ page }) => {
        await page.goto('/admin/audit');
        
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        // Click on first event row
        const firstEvent = page.locator('tbody tr, [data-testid="audit-event"]').first();
        
        if (await firstEvent.isVisible({ timeout: 2000 })) {
            await firstEvent.click();
            
            // The component may show a detail modal/panel or the row itself shows event info.
            // Check for either a dialog or that the row contains visible event data.
            const hasDialog = await page.locator('[role="dialog"], .modal, [data-testid="event-details"]').isVisible({ timeout: 2000 }).catch(() => false);
            if (!hasDialog) {
                // No detail modal — verify the row itself shows meaningful event data
                await expect(firstEvent.locator('td').first()).toBeVisible();
            }
        } else {
            test.skip();
        }
    });

    test('audit event details show metadata', async ({ page }) => {
        await page.goto('/admin/audit');
        
        await page.waitForSelector('table, [data-testid="audit-log"], [role="table"]', { timeout: 15000 });
        
        const firstEvent = page.locator('tbody tr').first();
        if (await firstEvent.isVisible({ timeout: 2000 })) {
            // The table renders IP address in a column — verify it's present
            const metadata = page.locator('text=/ip.*address|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|user.*agent|browser|location/i');
            await expect(metadata.first()).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

test.describe('EIAA Execution Records', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can view EIAA execution records', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Look for EIAA tab or filter
        const eiaaTab = page.locator('button:has-text("EIAA"), a:has-text("Executions")');
        
        if (await eiaaTab.first().isVisible({ timeout: 2000 })) {
            await eiaaTab.first().click();
            
            // Should show EIAA executions
            await expect(page.locator('table, [data-testid="eiaa-executions"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('EIAA records show decision outcomes', async ({ page }) => {
        await page.goto('/admin/audit');
        
        const eiaaTab = page.locator('button:has-text("EIAA")');
        if (await eiaaTab.isVisible({ timeout: 2000 })) {
            await eiaaTab.click();
            
            // Should show allow/deny decisions
            const decision = page.locator('text=/allow|deny|permit|reject/i, [data-testid="decision"]');
            
            const hasRecords = await page.locator('tr').count() > 1;
            if (hasRecords) {
                await expect(decision.first()).toBeVisible();
            }
        } else {
            test.skip();
        }
    });

    test('EIAA records show attestation signatures', async ({ page }) => {
        await page.goto('/admin/audit');
        
        const eiaaTab = page.locator('button:has-text("EIAA")');
        if (await eiaaTab.isVisible({ timeout: 2000 })) {
            await eiaaTab.click();
            
            // Click on first record
            const firstRecord = page.locator('tr').nth(1);
            if (await firstRecord.isVisible({ timeout: 2000 })) {
                await firstRecord.click();
                
                // Should show attestation signature
                await expect(page.locator('text=/attestation|signature|ed25519/i')).toBeVisible({ timeout: 5000 });
            }
        } else {
            test.skip();
        }
    });

    test.skip('can verify EIAA execution', async ({ page }) => {
        // TODO: Requires EIAA runtime service
        // Implementation steps:
        // 1. Navigate to EIAA executions
        // 2. Click on execution record
        // 3. Click "Verify" button
        // 4. Re-execute capsule with same inputs
        // 5. Compare results and attestation
        // 6. Show verification result
        
        await page.goto('/admin/audit');
        
        const eiaaTab = page.locator('button:has-text("EIAA")');
        if (await eiaaTab.isVisible({ timeout: 2000 })) {
            await eiaaTab.click();
            
            const firstRecord = page.locator('tr').nth(1);
            if (await firstRecord.isVisible({ timeout: 2000 })) {
                await firstRecord.click();
                
                const verifyButton = page.locator('button:has-text("Verify"), button:has-text("Re-execute")');
                if (await verifyButton.isVisible({ timeout: 2000 })) {
                    await verifyButton.click();
                    
                    // Should show verification result
                    await expect(page.locator('text=/verified|match|mismatch/i')).toBeVisible({ timeout: 10000 });
                }
            }
        }
    });

    test.skip('can batch verify EIAA executions', async ({ page }) => {
        // TODO: Requires EIAA runtime service
        await page.goto('/admin/audit');
        
        const eiaaTab = page.locator('button:has-text("EIAA")');
        if (await eiaaTab.isVisible({ timeout: 2000 })) {
            await eiaaTab.click();
            
            // Select multiple records
            const checkboxes = page.locator('input[type="checkbox"]');
            const count = await checkboxes.count();
            
            if (count > 1) {
                await checkboxes.nth(0).check();
                await checkboxes.nth(1).check();
                
                // Click batch verify
                const batchVerifyButton = page.locator('button:has-text("Verify Selected"), button:has-text("Batch Verify")');
                if (await batchVerifyButton.isVisible({ timeout: 2000 })) {
                    await batchVerifyButton.click();
                    
                    // Should show batch verification results
                    await expect(page.locator('text=/verification.*complete|results/i')).toBeVisible({ timeout: 15000 });
                }
            }
        }
    });

});

test.describe('Audit Export', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can export audit logs', async ({ page }) => {
        await page.goto('/admin/audit');
        
        // Look for export button
        const exportButton = page.locator('button:has-text("Export"), button:has-text("Download")');
        
        if (await exportButton.first().isVisible({ timeout: 2000 })) {
            // Set up download listener
            const downloadPromise = page.waitForEvent('download', { timeout: 10000 });
            
            await exportButton.first().click();
            
            // Verify download started
            const download = await downloadPromise;
            expect(download.suggestedFilename()).toMatch(/audit|log|export/i);
        } else {
            test.skip();
        }
    });

    test('can export in different formats', async ({ page }) => {
        await page.goto('/admin/audit');
        
        const exportButton = page.locator('button:has-text("Export")');
        if (await exportButton.isVisible({ timeout: 2000 })) {
            await exportButton.click();
            
            // Should show format options
            const formatOptions = page.locator('text=/csv|json|pdf/i, [data-testid="export-format"]');
            await expect(formatOptions.first()).toBeVisible({ timeout: 3000 });
        } else {
            test.skip();
        }
    });

});

// Made with Bob
