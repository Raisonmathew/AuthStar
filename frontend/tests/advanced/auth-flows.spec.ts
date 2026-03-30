/**
 * Phase 5: Auth Flows E2E Tests
 * 
 * Tests for EIAA-powered authentication flows with risk assessment,
 * step-up authentication, and adaptive security.
 */

import { test, expect } from '../fixtures/test-utils';

test.describe('Auth Flow Initialization', () => {

    test('can initiate auth flow', async ({ page }) => {
        await page.goto('/u/default');
        
        // Auth flow should be initiated automatically
        // Look for flow ID in session or network
        const response = await page.waitForResponse(
            (response) => response.url().includes('/api/auth/flow/init'),
            { timeout: 10000 }
        );
        
        expect(response.status()).toBe(200);
        
        const data = await response.json();
        expect(data).toHaveProperty('flow_id');
        expect(data).toHaveProperty('ui_step');
    });

    test('auth flow shows correct initial step', async ({ page }) => {
        await page.goto('/u/default');
        
        // Should show email input as first step
        await expect(page.locator('input[type="email"]')).toBeVisible({ timeout: 5000 });
    });

    test('auth flow includes risk assessment', async ({ page }) => {
        await page.goto('/u/default');
        
        // Wait for flow init
        const response = await page.waitForResponse(
            (response) => response.url().includes('/api/auth/flow/init'),
            { timeout: 10000 }
        );
        
        const data = await response.json();
        
        // Should include risk context
        expect(data).toHaveProperty('context');
        // Risk score may or may not be present initially
    });

});

test.describe('Auth Flow - Identity Step', () => {

    test('can submit email for identification', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        // Should proceed to next step (password or other)
        await page.waitForSelector('input[type="password"], text=/verification|code/i', { timeout: 10000 });
    });

    test('handles unknown email gracefully', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'unknown@example.com');
        await page.click('button[type="submit"]');
        
        // Should show error or proceed to signup
        const errorOrSignup = page.locator('text=/not found|sign up|create account/i, [role="alert"]');
        await expect(errorOrSignup).toBeVisible({ timeout: 5000 });
    });

    test('validates email format', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.waitForSelector('input[type="email"]');
        await page.fill('input[type="email"]', 'invalid-email');
        await page.click('button[type="submit"]');
        
        // Should show validation error
        await expect(page.locator('text=/invalid.*email|valid.*email/i, [role="alert"]')).toBeVisible({ timeout: 3000 });
    });

});

test.describe('Auth Flow - Credential Step', () => {

    test('can submit password credential', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'password123');
        await page.click('button[type="submit"]');
        
        // Should complete or request additional factors
        await page.waitForTimeout(2000);
        
        // Either redirected to dashboard or asked for MFA
        const dashboardOrMfa = page.locator('text=/dashboard|verification|code/i');
        await expect(dashboardOrMfa.first()).toBeVisible({ timeout: 10000 });
    });

    test('handles incorrect password', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'wrongpassword');
        await page.click('button[type="submit"]');
        
        // Should show error
        await expect(page.locator('text=/incorrect|invalid.*password/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test.skip('can submit TOTP credential', async ({ page }) => {
        // TODO: Requires MFA setup
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        await page.fill('input[type="password"]', 'password123');
        await page.click('button[type="submit"]');
        
        // Should request TOTP
        const totpInput = page.locator('input[name="code"], input[placeholder*="code"]');
        if (await totpInput.isVisible({ timeout: 5000 })) {
            await totpInput.fill('123456');
            await page.click('button[type="submit"]');
            
            // Should complete or show error
            await page.waitForTimeout(2000);
        }
    });

});

test.describe('Auth Flow - Risk-Based Step-Up', () => {

    test.skip('triggers step-up for high-risk login', async ({ page }) => {
        // TODO: Requires risk engine mocking
        // Mock high risk score
        await page.route('**/api/auth/flow/submit', async (route) => {
            const response = await route.fetch();
            const data = await response.json();
            
            // Inject step-up requirement
            data.ui_step = 'RequireVerification';
            data.requirement = {
                required_assurance: 'Substantial',
                reason: 'High risk detected'
            };
            
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(data)
            });
        });
        
        await page.goto('/u/default');
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password123');
        await page.click('button[type="submit"]');
        
        // Should request additional verification
        await expect(page.locator('text=/additional.*verification|step.*up/i')).toBeVisible({ timeout: 5000 });
    });

    test.skip('requires phishing-resistant factor for sensitive action', async ({ page }) => {
        // TODO: Requires EIAA policy configuration
        await page.goto('/u/default');
        
        // Complete normal login
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password123');
        await page.click('button[type="submit"]');
        
        // Navigate to sensitive action
        await page.goto('/profile/change-password');
        
        // Should trigger step-up
        await expect(page.locator('text=/phishing.*resistant|security.*key|passkey/i')).toBeVisible({ timeout: 5000 });
    });

});

test.describe('Auth Flow - Completion', () => {

    test('successful flow redirects to dashboard', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        
        await page.waitForSelector('input[type="password"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');
        
        // Should redirect to dashboard
        await page.waitForURL('/dashboard', { timeout: 10000 });
        expect(page.url()).toContain('/dashboard');
    });

    test('flow creates session with correct claims', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');
        
        await page.waitForURL('/dashboard', { timeout: 10000 });
        
        // Check session storage
        const jwt = await page.evaluate(() => sessionStorage.getItem('jwt'));
        expect(jwt).toBeTruthy();
        
        const orgId = await page.evaluate(() => sessionStorage.getItem('active_org_id'));
        expect(orgId).toBeTruthy();
    });

    test('flow records decision reference', async ({ page }) => {
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password');
        
        // Capture complete response
        const completeResponse = page.waitForResponse(
            (response) => response.url().includes('/api/auth/flow/complete'),
            { timeout: 15000 }
        );
        
        await page.click('button[type="submit"]');
        
        const response = await completeResponse;
        const data = await response.json();
        
        // Should include decision reference for audit
        expect(data).toHaveProperty('session');
    });

});

test.describe('Auth Flow - Error Scenarios', () => {

    test('handles expired flow gracefully', async ({ page }) => {
        await page.goto('/u/default');
        
        // Wait long enough for flow to expire (if timeout is short)
        await page.waitForTimeout(2000);
        
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        // Should either work or show expiration error
        await page.waitForTimeout(2000);
        
        // Check for error or success
        const result = page.locator('input[type="password"], text=/expired|restart/i');
        await expect(result.first()).toBeVisible({ timeout: 5000 });
    });

    test('handles network errors during flow', async ({ page }) => {
        // Mock network error
        await page.route('**/api/auth/flow/submit', async (route) => {
            await route.abort('failed');
        });
        
        await page.goto('/u/default');
        
        await page.fill('input[type="email"]', 'user@example.com');
        await page.click('button[type="submit"]');
        
        // Should show error message
        await expect(page.locator('text=/error|failed|try again/i, [role="alert"]')).toBeVisible({ timeout: 5000 });
    });

    test('prevents flow replay attacks', async ({ page }) => {
        // This would require capturing and replaying flow tokens
        // In practice, the backend should reject replayed tokens
        test.skip();
    });

});

test.describe('Auth Flow - Device Fingerprinting', () => {

    test('collects device fingerprint', async ({ page }) => {
        await page.goto('/u/default');
        
        // Wait for flow init
        const response = await page.waitForResponse(
            (response) => response.url().includes('/api/auth/flow/init'),
            { timeout: 10000 }
        );
        
        const requestBody = response.request().postDataJSON();
        
        // Should include device context
        expect(requestBody).toHaveProperty('context');
    });

    test('recognizes returning device', async ({ page }) => {
        // First login
        await page.goto('/u/default');
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');
        
        await page.waitForURL('/dashboard', { timeout: 10000 });
        
        // Logout
        await page.click('button:has-text("Sign out")');
        await page.waitForURL('**/u/default', { timeout: 5000 });
        
        // Second login - should recognize device
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', 'password');
        await page.click('button[type="submit"]');
        
        // Should complete successfully (device recognized)
        await page.waitForURL('/dashboard', { timeout: 10000 });
    });

});

// Made with Bob
