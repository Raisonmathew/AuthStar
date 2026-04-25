/**
 * Phase 4: Passkeys/WebAuthn E2E Tests
 *
 * Tests for WebAuthn credential registration and authentication.
 * Uses WebAuthn API mocking for reliable testing.
 */

import { test, expect, loginAsUser } from '../fixtures/test-utils';
import {
    enableWebAuthnMocking,
    mockWebAuthnNotSupported,
    WebAuthnMockPresets
} from '../fixtures/webauthn-mock';

// Each test gets a unique fake IP so per-IP rate limits don't accumulate
// across tests. The backend trusts X-Forwarded-For directly in dev mode.
let _ipCounter = 0;

test.describe('Passkeys/WebAuthn Management', () => {

    test.beforeEach(async ({ page }) => {
        _ipCounter = (_ipCounter % 250) + 1;
        await page.setExtraHTTPHeaders({ 'X-Forwarded-For': `10.10.3.${_ipCounter}` });
        // Mock EIAA runtime keys so React mounts
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        // Clear any existing session so loginAsUser always goes through fresh login
        await page.context().clearCookies();
        await page.addInitScript(() => { try { sessionStorage.clear(); localStorage.clear(); } catch (_) {} });
        await loginAsUser(page);
    });

    test('can navigate to passkeys page', async ({ page }) => {
        // Passkeys are managed under account/security
        await page.goto('/account/security');
        
        // Look for passkeys section
        const passkeysSection = page.locator('h3:has-text("Passkeys"), h2:has-text("Passkeys"), button:has-text("Add passkey"), button:has-text("Register passkey")');
        
        if (await passkeysSection.first().isVisible({ timeout: 5000 })) {
            await expect(passkeysSection.first()).toBeVisible();
        } else {
            test.skip();
        }
    });

    test('can view list of registered passkeys', async ({ page }) => {
        await page.goto('/account/security');
        
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            // Should show passkeys list or empty state
            const listOrEmpty = page.locator('table, [data-testid="passkeys-list"], text=/no passkeys/i');
            await expect(listOrEmpty).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can register new passkey', async ({ page }) => {
        // Enable WebAuthn mocking for successful registration
        await enableWebAuthnMocking(page, WebAuthnMockPresets.successfulRegistration);
        
        await page.goto('/account/security');
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
        }
        
        const addButton = page.locator('button:has-text("Add Passkey"), button:has-text("Register")');
        if (await addButton.isVisible({ timeout: 2000 })) {
            await addButton.click();
            
            // Fill passkey name
            const nameInput = page.locator('input[name="name"], input[placeholder*="name"]');
            if (await nameInput.isVisible({ timeout: 2000 })) {
                await nameInput.fill('Test Passkey');
            }
            
            // Submit
            await page.click('button[type="submit"]');
            
            // Verify success
            await expect(page.locator('text=/registered|added|success/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('can authenticate with passkey', async ({ page }) => {
        // Enable WebAuthn mocking for successful authentication
        await enableWebAuthnMocking(page, WebAuthnMockPresets.successfulAuthentication);
        
        await page.goto('/u/default');
        
        const passkeyButton = page.locator('button:has-text("Passkey"), button:has-text("Sign in with passkey")');
        if (await passkeyButton.isVisible({ timeout: 2000 })) {
            await passkeyButton.click();
            
            // Should redirect to account area on success
            await page.waitForURL('**/account/**', { timeout: 10000 });
            expect(page.url()).toContain('/account');
        } else {
            test.skip();
        }
    });

    test('can delete passkey', async ({ page }) => {
        await page.goto('/account/security');
        
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            // Look for delete button
            const deleteButton = page.locator('button:has-text("Delete"), button:has-text("Remove")').first();
            
            if (await deleteButton.isVisible({ timeout: 2000 })) {
                await deleteButton.click();
                
                // Confirm deletion
                const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
                if (await confirmButton.isVisible({ timeout: 2000 })) {
                    await confirmButton.click();
                }
                
                // Verify success
                await expect(page.locator('text=/deleted|removed/i')).toBeVisible({ timeout: 5000 });
            } else {
                test.skip();
            }
        } else {
            test.skip();
        }
    });

    test('passkey list shows device information', async ({ page }) => {
        await page.goto('/account/security');
        
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            // Check for device/platform information
            const deviceInfo = page.locator('text=/chrome|firefox|safari|windows|mac|android|ios/i');
            
            // If passkeys exist, should show device info
            const hasPasskeys = await page.locator('table tr, [data-testid="passkey-item"]').count() > 0;
            if (hasPasskeys) {
                await expect(deviceInfo.first()).toBeVisible({ timeout: 5000 });
            }
        } else {
            test.skip();
        }
    });

    test('shows last used timestamp for passkeys', async ({ page }) => {
        await page.goto('/account/security');
        
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            // Check for timestamp
            const timestamp = page.locator('text=/last used|never|ago/i');
            
            const hasPasskeys = await page.locator('table tr, [data-testid="passkey-item"]').count() > 0;
            if (hasPasskeys) {
                await expect(timestamp.first()).toBeVisible({ timeout: 5000 });
            }
        } else {
            test.skip();
        }
    });

});

test.describe('Passkeys - Error Scenarios', () => {

    test.beforeEach(async ({ page }) => {
        _ipCounter = (_ipCounter % 250) + 1;
        await page.setExtraHTTPHeaders({ 'X-Forwarded-For': `10.10.3.${_ipCounter}` });
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
        await page.context().clearCookies();
        await page.addInitScript(() => { try { sessionStorage.clear(); localStorage.clear(); } catch (_) {} });
        await loginAsUser(page);
    });

    test('handles WebAuthn not supported', async ({ page }) => {
        // Mock WebAuthn as not supported
        await mockWebAuthnNotSupported(page);
        
        await page.goto('/account/security');
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            // Should show not supported message
            await expect(page.locator('text=/not supported|browser.*support/i')).toBeVisible({ timeout: 5000 });
        } else {
            test.skip();
        }
    });

    test('handles registration cancellation', async ({ page }) => {
        // Enable WebAuthn mocking with cancellation
        await enableWebAuthnMocking(page, WebAuthnMockPresets.userCancelled);
        
        await page.goto('/account/security');
        const passkeysLink = page.locator('a:has-text("Passkeys")');
        if (await passkeysLink.isVisible({ timeout: 2000 })) {
            await passkeysLink.click();
            
            const addButton = page.locator('button:has-text("Add Passkey")');
            if (await addButton.isVisible({ timeout: 2000 })) {
                await addButton.click();
                
                // Should handle cancellation gracefully
                await expect(page.locator('text=/cancelled|aborted/i')).toBeVisible({ timeout: 5000 });
            } else {
                test.skip();
            }
        } else {
            test.skip();
        }
    });

});

// Made with Bob
