import { test, expect, loginAsUser, clearSession } from '../fixtures/test-utils';

test.describe('User Profile Management', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
        await loginAsUser(page);
    });

    test('can view user profile', async ({ page }) => {
        // Navigate to profile page
        await page.goto('/profile');
        
        // Verify profile page loads
        await expect(page.locator('h1, h2').filter({ hasText: /profile/i })).toBeVisible();
        
        // Verify user information is displayed
        await expect(page.locator('input[name="email"], input[type="email"]')).toBeVisible();
    });

    test('can update profile information', async ({ page }) => {
        await page.goto('/profile');
        
        // Wait for profile form to load
        await page.waitForSelector('input[name="first_name"], input[placeholder*="First"]', { timeout: 10000 });
        
        // Update first name
        const firstNameInput = page.locator('input[name="first_name"], input[placeholder*="First"]').first();
        await firstNameInput.fill('UpdatedFirst');
        
        // Update last name
        const lastNameInput = page.locator('input[name="last_name"], input[placeholder*="Last"]').first();
        await lastNameInput.fill('UpdatedLast');
        
        // Submit form
        await page.click('button[type="submit"]:has-text("Save"), button:has-text("Update")');
        
        // Verify success message or updated data
        await expect(page.locator('text=/updated|success/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('can change password', async ({ page }) => {
        await page.goto('/profile');
        
        // Look for password change section or button
        const changePasswordButton = page.locator('button:has-text("Change Password"), a:has-text("Change Password")');
        
        if (await changePasswordButton.isVisible()) {
            await changePasswordButton.click();
            
            // Fill password change form
            await page.fill('input[name="current_password"], input[placeholder*="Current"]', 'password');
            await page.fill('input[name="new_password"], input[placeholder*="New"]', 'NewPassword123!');
            await page.fill('input[name="confirm_password"], input[placeholder*="Confirm"]', 'NewPassword123!');
            
            // Submit
            await page.click('button[type="submit"]:has-text("Change"), button:has-text("Update")');
            
            // Verify success
            await expect(page.locator('text=/password.*changed|success/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('password change validates complexity', async ({ page }) => {
        await page.goto('/profile');
        
        const changePasswordButton = page.locator('button:has-text("Change Password"), a:has-text("Change Password")');
        
        if (await changePasswordButton.isVisible()) {
            await changePasswordButton.click();
            
            // Try weak password
            await page.fill('input[name="current_password"], input[placeholder*="Current"]', 'password');
            await page.fill('input[name="new_password"], input[placeholder*="New"]', 'weak');
            await page.fill('input[name="confirm_password"], input[placeholder*="Confirm"]', 'weak');
            
            await page.click('button[type="submit"]:has-text("Change"), button:has-text("Update")');
            
            // Should show validation error
            await expect(page.locator('text=/password.*requirements|too weak|invalid/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('password change requires correct current password', async ({ page }) => {
        await page.goto('/profile');
        
        const changePasswordButton = page.locator('button:has-text("Change Password"), a:has-text("Change Password")');
        
        if (await changePasswordButton.isVisible()) {
            await changePasswordButton.click();
            
            // Use wrong current password
            await page.fill('input[name="current_password"], input[placeholder*="Current"]', 'wrongpassword');
            await page.fill('input[name="new_password"], input[placeholder*="New"]', 'NewPassword123!');
            await page.fill('input[name="confirm_password"], input[placeholder*="Confirm"]', 'NewPassword123!');
            
            await page.click('button[type="submit"]:has-text("Change"), button:has-text("Update")');
            
            // Should show error
            await expect(page.locator('text=/incorrect|invalid.*password/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

});

// Made with Bob
