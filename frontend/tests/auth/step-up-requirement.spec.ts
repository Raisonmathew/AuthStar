import { test, expect } from '../fixtures/test-utils';

test.describe('StepUpModal Structured Requirements', () => {

    test.beforeEach(async ({ page }) => {
        // Install a toggleable capture-phase suppressor so background AAL
        // events fired by dashboard API calls do NOT open the modal during
        // navigation, while test-dispatched events still reach React's handler.
        // The flag `window.__suppressStepUp` starts true (suppress) and is
        // flipped to false once the page is stable and we want tests to work.
        await page.addInitScript(() => {
            (window as any).__suppressStepUp = true;
            window.addEventListener('auth:step-up-required', (e) => {
                if ((window as any).__suppressStepUp) {
                    e.stopImmediatePropagation();
                }
            }, true);
        });

        // Mock EIAA runtime keys so React mounts even when gRPC runtime is down
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );

        // Mock the admin whoami gate — an AAL1 session gets 403 from the capsule,
        // causing AdminLayout to navigate to /account/profile. Return a minimal
        // 200 so the admin shell stays rendered for these modal tests.
        await page.route('**/api/admin/v1/whoami', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '{"id":"user_admin","email":"admin@example.com","role":"admin"}' })
        );

        // The chromium project provides admin storageState — navigate to a real admin page
        await page.goto('/admin/dashboard');
        await page.waitForURL('**/admin/dashboard', { timeout: 30_000 });

        // Wait for React app to fully mount (AppLoadingGuard cleared,
        // <StepUpModal /> has its event listener registered).
        await page.locator('aside, [role="navigation"], nav').first().waitFor({ state: 'visible', timeout: 15_000 });
        await page.waitForFunction(
            () => sessionStorage.getItem('active_org_id'),
            { timeout: 15_000 },
        );

        // Page is stable — allow test-dispatched events to reach the modal.
        await page.evaluate(() => { (window as any).__suppressStepUp = false; });
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
        await expect(page.locator('text=This action requires a phishing-resistant authentication method (e.g. Passkey).')).toBeVisible();

        // Verify factor filtering:
        // With require_phishing_resistant=true, TOTP is filtered out leaving only 1 passkey.
        // When only 1 factor remains, no dropdown is shown — the passkey UI is shown directly.
        const select = page.locator('select');
        await expect(select).not.toBeVisible();

        // Should show the passkey action button directly
        await expect(page.locator('button:has-text("Use Passkey")')).toBeVisible();
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
