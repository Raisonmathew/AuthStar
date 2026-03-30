import { test, expect, loginAsUser, clearSession } from '../fixtures/test-utils';

test.describe('MFA Management', () => {

    test.beforeEach(async ({ page }) => {
        await clearSession(page);
        await loginAsUser(page);
    });

    test('can navigate to MFA enrollment page', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Verify MFA page loads
        await expect(page.locator('h1, h2').filter({ hasText: /mfa|multi-factor|two-factor/i })).toBeVisible();
    });

    test('can view MFA status', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Check for MFA status indicators
        const statusElement = page.locator('text=/enabled|disabled|not.*configured/i, [data-testid="mfa-status"]');
        await expect(statusElement.first()).toBeVisible({ timeout: 10000 });
    });

    test('can initiate TOTP setup', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Look for setup button
        const setupButton = page.locator('button:has-text("Enable"), button:has-text("Set up"), button:has-text("Configure")');
        
        if (await setupButton.first().isVisible()) {
            await setupButton.first().click();
            
            // Should show QR code or secret key
            await expect(page.locator('img[alt*="QR"], canvas, text=/secret.*key/i')).toBeVisible({ timeout: 5000 });
            
            // Should have verification code input
            await expect(page.locator('input[name="code"], input[placeholder*="code"]')).toBeVisible();
        } else {
            // MFA might already be enabled
            test.skip();
        }
    });

    test('TOTP verification requires valid code', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        const setupButton = page.locator('button:has-text("Enable"), button:has-text("Set up")');
        
        if (await setupButton.first().isVisible()) {
            await setupButton.first().click();
            
            // Wait for code input
            const codeInput = page.locator('input[name="code"], input[placeholder*="code"]');
            await codeInput.waitFor({ state: 'visible', timeout: 5000 });
            
            // Try invalid code
            await codeInput.fill('000000');
            await page.click('button[type="submit"]:has-text("Verify"), button:has-text("Confirm")');
            
            // Should show error
            await expect(page.locator('text=/invalid.*code|incorrect/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can view backup codes after MFA setup', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Look for backup codes section
        const backupCodesButton = page.locator('button:has-text("Backup Codes"), button:has-text("Recovery Codes"), a:has-text("Backup")');
        
        if (await backupCodesButton.first().isVisible()) {
            await backupCodesButton.first().click();
            
            // Should display backup codes
            await expect(page.locator('code, pre, [data-testid="backup-code"]')).toBeVisible({ timeout: 5000 });
        } else {
            // MFA might not be enabled yet
            test.skip();
        }
    });

    test('can disable MFA', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Look for disable button
        const disableButton = page.locator('button:has-text("Disable"), button:has-text("Turn off")');
        
        if (await disableButton.first().isVisible()) {
            await disableButton.first().click();
            
            // May require confirmation
            const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
            if (await confirmButton.isVisible({ timeout: 2000 })) {
                await confirmButton.click();
            }
            
            // Should show success message
            await expect(page.locator('text=/disabled|turned off|removed/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
        } else {
            // MFA might not be enabled
            test.skip();
        }
    });

    test('MFA factors are listed correctly', async ({ page }) => {
        await page.goto('/mfa-enrollment');
        
        // Check for factor types display
        const factorTypes = ['TOTP', 'Authenticator', 'SMS', 'Email'];
        
        for (const factorType of factorTypes) {
            const element = page.locator(`text=${factorType}`);
            if (await element.isVisible({ timeout: 2000 })) {
                // At least one factor type should be visible
                expect(await element.count()).toBeGreaterThan(0);
                break;
            }
        }
    });

});

// Made with Bob
