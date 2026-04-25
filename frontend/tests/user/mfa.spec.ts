import { test, expect } from '../fixtures/test-utils';

// MFA enrollment lives at /account/security (the Security Settings page),
// not /mfa-enrollment. The page renders three sections: Authenticator App
// (TOTP), Backup Codes, and Passkeys.
//
// Project user-journey uses the AAL3-upgraded admin storageState so step-up
// modals don't block these reads.

test.describe('MFA Management', () => {

    test.beforeEach(async ({ page }) => {
        // EIAA runtime keys mock so React mounts even if the capsule
        // runtime gRPC service is down.
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
    });

    test('can navigate to MFA enrollment page', async ({ page }) => {
        await page.goto('/account/security');

        await expect(
            page.locator('h1:has-text("Security Settings")')
        ).toBeVisible({ timeout: 15_000 });
    });

    test('can view MFA status', async ({ page }) => {
        await page.goto('/account/security');

        // The page renders all three factor sections regardless of enrolment.
        await expect(page.locator('h3:has-text("Authenticator App")')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Backup Codes")')).toBeVisible();
        await expect(page.locator('h3:has-text("Passkeys")')).toBeVisible();
    });

    test('can initiate TOTP setup', async ({ page }) => {
        await page.goto('/account/security');
        await expect(page.locator('h1:has-text("Security Settings")')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Authenticator App")')).toBeVisible({ timeout: 15_000 });

        // The TOTP section exposes either an Enable button (not enrolled)
        // or a Disable button (already enrolled). If already enrolled we
        // skip — re-running enrolment requires disabling + re-verifying
        // which is out of scope for this smoke test.
        const enableButton = page.getByRole('button', { name: /enable|set up|configure/i }).first();
        if (!(await enableButton.isVisible({ timeout: 3_000 }).catch(() => false))) {
            test.skip(true, 'TOTP appears to be already enrolled');
            return;
        }

        await enableButton.click();

        // After clicking Enable the page should show either a QR code,
        // a manual entry key, or a 6-digit code input.
        const setupVisible = await Promise.race([
            page.locator('img[alt*="QR" i]').first().waitFor({ state: 'visible', timeout: 8_000 }).then(() => true).catch(() => false),
            page.locator('input[maxlength="6"], input[placeholder*="code" i]').first().waitFor({ state: 'visible', timeout: 8_000 }).then(() => true).catch(() => false),
            page.locator('text=/manual.*entry|secret.*key/i').first().waitFor({ state: 'visible', timeout: 8_000 }).then(() => true).catch(() => false),
        ]);
        expect(setupVisible).toBe(true);
    });

    test('TOTP verification requires valid code', async ({ page }) => {
        await page.goto('/account/security');
        await expect(page.locator('h1:has-text("Security Settings")')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Authenticator App")')).toBeVisible({ timeout: 15_000 });

        const enableButton = page.getByRole('button', { name: /enable|set up|configure/i }).first();
        if (!(await enableButton.isVisible({ timeout: 3_000 }).catch(() => false))) {
            test.skip(true, 'TOTP appears to be already enrolled');
            return;
        }
        await enableButton.click();

        const codeInput = page.locator('input[placeholder*="code" i], input[maxlength="6"]').first();
        if (!(await codeInput.isVisible({ timeout: 8_000 }).catch(() => false))) {
            test.skip(true, 'Code input did not appear — backend may not have completed setup');
            return;
        }

        await codeInput.fill('000000');
        await page.getByRole('button', { name: /verify|confirm|enable/i }).first().click();

        // Backend returns an error toast (sonner) for invalid TOTP codes.
        await expect(page.locator('text=/invalid|incorrect|try again/i').first())
            .toBeVisible({ timeout: 10_000 });
    });

    test('backup codes section is visible', async ({ page }) => {
        await page.goto('/account/security');
        await expect(page.locator('h1:has-text("Security Settings")')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Backup Codes")')).toBeVisible({ timeout: 15_000 });
    });

    test('can view passkeys section', async ({ page }) => {
        await page.goto('/account/security');
        await expect(page.locator('h1:has-text("Security Settings")')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Passkeys")')).toBeVisible({ timeout: 15_000 });
    });

    test('MFA factors are listed', async ({ page }) => {
        await page.goto('/account/security');

        // All three factor sections must render so users can see what's
        // available, regardless of current enrolment state.
        const sections = ['Authenticator App', 'Backup Codes', 'Passkeys'];
        for (const section of sections) {
            await expect(page.locator(`h3:has-text("${section}")`)).toBeVisible({ timeout: 15_000 });
        }
    });

});
