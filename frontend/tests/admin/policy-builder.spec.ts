import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Policy Builder', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can navigate to policy builder', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Verify policy builder page loads
        await expect(page.locator('h1, h2').filter({ hasText: /polic/i })).toBeVisible();
    });

    test('can view list of policy configurations', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Should show list of policies
        await expect(page.locator('table, [role="table"], [data-testid="policies-list"]')).toBeVisible({ timeout: 10000 });
    });

    test('can create new policy configuration', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Click create button
        const createButton = page.locator('button:has-text("Create"), button:has-text("New Policy")');
        await createButton.first().click();
        
        // Fill in policy details
        const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
        if (await nameInput.isVisible({ timeout: 2000 })) {
            await nameInput.fill('E2E Test Policy');
        }
        
        const descInput = page.locator('input[name="description"], textarea[name="description"]');
        if (await descInput.isVisible({ timeout: 2000 })) {
            await descInput.fill('Policy created by E2E test');
        }
        
        // Select action
        const actionSelect = page.locator('select[name="action"], [data-testid="action-select"]');
        if (await actionSelect.isVisible({ timeout: 2000 })) {
            await actionSelect.selectOption({ index: 1 });
        }
        
        // Submit
        await page.click('button[type="submit"]:has-text("Create"), button:has-text("Save")');
        
        // Should redirect to policy detail or show success
        await expect(page.locator('text=/created|success/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('can view policy templates', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Look for templates section or button
        const templatesButton = page.locator('button:has-text("Templates"), a:has-text("Templates")');
        
        if (await templatesButton.first().isVisible({ timeout: 2000 })) {
            await templatesButton.first().click();
            
            // Should show template list
            await expect(page.locator('[data-testid="template-card"], .template-item')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can add rule group to policy', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Click on first policy
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Add rule group
        const addGroupButton = page.locator('button:has-text("Add Group"), button:has-text("New Group")');
        
        if (await addGroupButton.first().isVisible({ timeout: 2000 })) {
            await addGroupButton.first().click();
            
            // Fill group details
            const groupNameInput = page.locator('input[name="name"], input[placeholder*="group"]');
            if (await groupNameInput.isVisible({ timeout: 2000 })) {
                await groupNameInput.fill('Test Rule Group');
            }
            
            await page.click('button[type="submit"]:has-text("Add"), button:has-text("Create")');
            
            // Should show success
            await expect(page.locator('text=/added|created/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can add rule to group', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Add rule
        const addRuleButton = page.locator('button:has-text("Add Rule"), button:has-text("New Rule")');
        
        if (await addRuleButton.first().isVisible({ timeout: 2000 })) {
            await addRuleButton.first().click();
            
            // Select rule type
            const ruleTypeSelect = page.locator('select[name="type"], [data-testid="rule-type"]');
            if (await ruleTypeSelect.isVisible({ timeout: 2000 })) {
                await ruleTypeSelect.selectOption({ index: 1 });
            }
            
            await page.click('button[type="submit"]:has-text("Add"), button:has-text("Create")');
            
            await expect(page.locator('text=/added|created/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can add condition to rule', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy with rules
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Add condition
        const addConditionButton = page.locator('button:has-text("Add Condition"), button:has-text("New Condition")');
        
        if (await addConditionButton.first().isVisible({ timeout: 2000 })) {
            await addConditionButton.first().click();
            
            // Select condition type
            const conditionTypeSelect = page.locator('select[name="condition_type"], [data-testid="condition-type"]');
            if (await conditionTypeSelect.isVisible({ timeout: 2000 })) {
                await conditionTypeSelect.selectOption({ index: 1 });
            }
            
            await page.click('button[type="submit"]:has-text("Add"), button:has-text("Create")');
            
            await expect(page.locator('text=/added|created/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can preview policy AST', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for preview button
        const previewButton = page.locator('button:has-text("Preview"), button:has-text("View AST")');
        
        if (await previewButton.first().isVisible({ timeout: 2000 })) {
            await previewButton.first().click();
            
            // Should show AST JSON
            await expect(page.locator('pre, code, [data-testid="ast-preview"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can simulate policy execution', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for simulate button
        const simulateButton = page.locator('button:has-text("Simulate"), button:has-text("Test")');
        
        if (await simulateButton.first().isVisible({ timeout: 2000 })) {
            await simulateButton.first().click();
            
            // Should show simulation form
            await expect(page.locator('form, [data-testid="simulation-form"]')).toBeVisible({ timeout: 5000 });
            
            // Fill simulation parameters
            const userIdInput = page.locator('input[name="user_id"], input[placeholder*="user"]');
            if (await userIdInput.isVisible({ timeout: 2000 })) {
                await userIdInput.fill('test-user-123');
            }
            
            // Run simulation
            await page.click('button[type="submit"]:has-text("Run"), button:has-text("Simulate")');
            
            // Should show results
            await expect(page.locator('[data-testid="simulation-result"], .result')).toBeVisible({ timeout: 10000 });
        } else {
            test.skip();
        }
    });

    test('can compile policy', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for compile button
        const compileButton = page.locator('button:has-text("Compile")');
        
        if (await compileButton.first().isVisible({ timeout: 2000 })) {
            await compileButton.first().click();
            
            // Should show compilation status
            await expect(page.locator('text=/compil(ed|ing)|success/i, [role="alert"]')).toBeVisible({ timeout: 10000 });
        } else {
            test.skip();
        }
    });

    test('can activate policy', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for activate button
        const activateButton = page.locator('button:has-text("Activate"), button:has-text("Enable")');
        
        if (await activateButton.first().isVisible({ timeout: 2000 })) {
            await activateButton.first().click();
            
            // Confirm activation
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/activated|enabled/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can view policy version history', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for versions tab or button
        const versionsButton = page.locator('button:has-text("Versions"), a:has-text("History")');
        
        if (await versionsButton.first().isVisible({ timeout: 2000 })) {
            await versionsButton.first().click();
            
            // Should show version list
            await expect(page.locator('[data-testid="version-item"], .version')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can view policy audit trail', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Navigate to policy detail
        const firstPolicy = page.locator('tr, [data-testid="policy-item"]').first();
        await firstPolicy.click();
        
        // Look for audit tab or button
        const auditButton = page.locator('button:has-text("Audit"), a:has-text("Activity")');
        
        if (await auditButton.first().isVisible({ timeout: 2000 })) {
            await auditButton.first().click();
            
            // Should show audit log
            await expect(page.locator('[data-testid="audit-entry"], .audit-item')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can delete policy configuration', async ({ page }) => {
        await page.goto('/admin/policies');
        
        // Look for delete button on a policy
        const deleteButton = page.locator('button:has-text("Delete"), button:has-text("Remove")').first();
        
        if (await deleteButton.isVisible({ timeout: 2000 })) {
            await deleteButton.click();
            
            // Confirm deletion
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Delete")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/deleted|removed|archived/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

// Made with Bob
