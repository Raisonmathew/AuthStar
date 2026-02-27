import { test, expect } from '@playwright/test';

test.describe('StepUpModal Structured Requirements', () => {

    test.beforeEach(async ({ page }) => {
        // Mock the user profile endpoint to simulate a logged-in state
        await page.route('**/api/v1/users/me', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ id: 'user-1', email: 'user@example.com', role: 'user' }),
            });
        });

        // Set the token in localStorage
        await page.addInitScript(() => {
            window.localStorage.setItem('admin_token', 'mock-token');
            window.sessionStorage.setItem('jwt', 'mock-token');
        });

        // Navigate to dashboard
        await page.goto('/dashboard');
    });

    test('displays assurance requirement message', async ({ page }) => {
        // Mock the factors endpoint first so the modal can load
        await page.route('**/api/v1/user/factors', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([
                    { id: '1', factor_type: 'totp', status: 'active' },
                    { id: '2', factor_type: 'passkey', status: 'active' }
                ])
            });
        });

        // Trigger the StepUpRequiredEvent manually with a requirement
        await page.evaluate(() => {
            const detail = {
                originalRequestConfig: {},
                requirement: {
                    required_assurance: 'Substantial'
                }
            };
            window.dispatchEvent(new CustomEvent('auth:step-up-required', { detail }));
        });

        // Verify modal appears
        await expect(page.locator('text=Security Verification Required')).toBeVisible();

        // Verify specific message
        await expect(page.locator('text=This action requires Substantial assurance.')).toBeVisible();
    });

    test('displays phishing-resistant message and filters factors', async ({ page }) => {
        // Mock factors: one TOTP (not phishing resistant), one Passkey (phishing resistant)
        await page.route('**/api/v1/user/factors', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([
                    { id: '1', factor_type: 'totp', status: 'active' },
                    { id: '2', factor_type: 'passkey', status: 'active' }
                ])
            });
        });

        // Trigger event with phishing resistant requirement
        await page.evaluate(() => {
            const detail = {
                originalRequestConfig: {},
                requirement: {
                    require_phishing_resistant: true
                }
            };
            window.dispatchEvent(new CustomEvent('auth:step-up-required', { detail }));
        });

        // Verify modal appears
        await expect(page.locator('text=Security Verification Required')).toBeVisible();

        // Verify specific message
        await expect(page.locator('text=This action requires a phishing-resistant authentication method')).toBeVisible();

        // Verify factor filtering
        // We expect only PASSKEY to be in the dropdown
        const select = page.locator('select');
        await expect(select).toBeVisible();

        const options = await select.locator('option').allTextContents();
        // Should contain PASSKEY
        expect(options).toContain('PASSKEY');
        // Should NOT contain TOTP
        expect(options).not.toContain('TOTP');
    });

    test('handles missing requirement gracefully', async ({ page }) => {
        // Mock factors
        await page.route('**/api/v1/user/factors', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([
                    { id: '1', factor_type: 'totp', status: 'active' }
                ])
            });
        });

        // Trigger generic event without requirement
        await page.evaluate(() => {
            const detail = {
                originalRequestConfig: {}
            };
            window.dispatchEvent(new CustomEvent('auth:step-up-required', { detail }));
        });

        // Verify default message
        await expect(page.locator('text=This action requires additional authentication. Please verify your identity to continue.')).toBeVisible();
    });
});
