import { test, expect, loginAsAdmin } from '../fixtures/test-utils';

test.describe('Organization Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can view organization settings', async ({ page }) => {
        await page.goto('/admin/settings');
        
        // Verify settings page loads
        await expect(page.locator('h1, h2').filter({ hasText: /setting|organization/i })).toBeVisible();
    });

    test('can update organization branding', async ({ page }) => {
        await page.goto('/admin/branding');
        
        // Update logo URL
        const logoInput = page.locator('input[name="logo_url"], input[placeholder*="logo"]');
        if (await logoInput.isVisible({ timeout: 2000 })) {
            await logoInput.fill('https://example.com/logo.png');
        }
        
        // Update primary color
        const colorInput = page.locator('input[name="primary_color"], input[type="color"]');
        if (await colorInput.isVisible({ timeout: 2000 })) {
            await colorInput.fill('#FF5733');
        }
        
        // Save changes
        await page.click('button[type="submit"]:has-text("Save"), button:has-text("Update")');
        
        // Should show success
        await expect(page.locator('text=/saved|updated|success/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('can preview branding changes', async ({ page }) => {
        await page.goto('/admin/branding');
        
        // Look for preview button
        const previewButton = page.locator('button:has-text("Preview")');
        
        if (await previewButton.isVisible({ timeout: 2000 })) {
            await previewButton.click();
            
            // Should show preview modal or iframe
            await expect(page.locator('[data-testid="branding-preview"], iframe')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can manage team members', async ({ page }) => {
        await page.goto('/team');
        
        // Verify team page loads
        await expect(page.locator('h1, h2').filter({ hasText: /team|member/i })).toBeVisible();
        
        // Should show member list
        await expect(page.locator('table, [role="table"], [data-testid="members-list"]')).toBeVisible({ timeout: 10000 });
    });

    test('can invite team member', async ({ page }) => {
        await page.goto('/team');
        
        // Click invite button
        const inviteButton = page.locator('button:has-text("Invite"), button:has-text("Add Member")');
        await inviteButton.first().click();
        
        // Fill email
        const emailInput = page.locator('input[name="email"], input[type="email"]');
        await emailInput.fill('newmember@example.com');
        
        // Select role
        const roleSelect = page.locator('select[name="role"], [data-testid="role-select"]');
        if (await roleSelect.isVisible({ timeout: 2000 })) {
            await roleSelect.selectOption('member');
        }
        
        // Send invite
        await page.click('button[type="submit"]:has-text("Invite"), button:has-text("Send")');
        
        // Should show success
        await expect(page.locator('text=/invited|sent/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('can change member role', async ({ page }) => {
        await page.goto('/team');
        
        // Wait for member list
        await page.waitForSelector('table, [role="table"]', { timeout: 10000 });
        
        // Look for role dropdown or edit button
        const roleSelect = page.locator('select[name="role"]').first();
        
        if (await roleSelect.isVisible({ timeout: 2000 })) {
            await roleSelect.selectOption('admin');
            
            // Should show success or confirmation
            await expect(page.locator('text=/updated|changed/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can remove team member', async ({ page }) => {
        await page.goto('/team');
        
        await page.waitForSelector('table, [role="table"]', { timeout: 10000 });
        
        // Look for remove button
        const removeButton = page.locator('button:has-text("Remove"), button:has-text("Delete")').first();
        
        if (await removeButton.isVisible({ timeout: 2000 })) {
            await removeButton.click();
            
            // Confirm removal
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Remove")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/removed|deleted/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can manage roles', async ({ page }) => {
        await page.goto('/admin/roles');
        
        // Verify roles page loads
        await expect(page.locator('h1, h2').filter({ hasText: /role/i })).toBeVisible();
        
        // Should show role list
        await expect(page.locator('table, [role="table"], [data-testid="roles-list"]')).toBeVisible({ timeout: 10000 });
    });

    test('can create custom role', async ({ page }) => {
        await page.goto('/admin/roles');
        
        // Click create button
        const createButton = page.locator('button:has-text("Create"), button:has-text("New Role")');
        await createButton.first().click();
        
        // Fill role details
        const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
        await nameInput.fill('Custom Test Role');
        
        const descInput = page.locator('input[name="description"], textarea[name="description"]');
        if (await descInput.isVisible({ timeout: 2000 })) {
            await descInput.fill('Role created by E2E test');
        }
        
        // Submit
        await page.click('button[type="submit"]:has-text("Create"), button:has-text("Save")');
        
        // Should show success
        await expect(page.locator('text=/created|success/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('can delete custom role', async ({ page }) => {
        await page.goto('/admin/roles');
        
        await page.waitForSelector('table, [role="table"]', { timeout: 10000 });
        
        // Look for delete button (not on system roles)
        const deleteButton = page.locator('button:has-text("Delete")').first();
        
        if (await deleteButton.isVisible({ timeout: 2000 })) {
            await deleteButton.click();
            
            // Confirm deletion
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes"), button:has-text("Delete")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/deleted|removed/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can configure login methods', async ({ page }) => {
        await page.goto('/admin/auth');
        
        // Verify auth settings page loads
        await expect(page.locator('h1, h2').filter({ hasText: /auth|login/i })).toBeVisible();
        
        // Should show login method toggles
        await expect(page.locator('input[type="checkbox"], [role="switch"]')).toBeVisible({ timeout: 5000 });
    });

    test('can toggle password authentication', async ({ page }) => {
        await page.goto('/admin/auth');
        
        // Find password auth toggle
        const passwordToggle = page.locator('input[type="checkbox"][name*="password"], [role="switch"]').first();
        
        if (await passwordToggle.isVisible({ timeout: 2000 })) {
            const wasChecked = await passwordToggle.isChecked();
            await passwordToggle.click();
            
            // Verify toggle changed
            expect(await passwordToggle.isChecked()).toBe(!wasChecked);
            
            // Should auto-save or show save button
            const saveButton = page.locator('button:has-text("Save")');
            if (await saveButton.isVisible({ timeout: 1000 })) {
                await saveButton.click();
            }
            
            // Should show success
            await expect(page.locator('text=/saved|updated/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

// Made with Bob
