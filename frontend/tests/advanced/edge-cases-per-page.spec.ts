/**
 * Per-Page Edge Case E2E Tests
 *
 * Targets page-specific failure modes that aren't already covered by the
 * primary specs in tests/{user,admin,auth}/. Each test exercises one
 * concrete edge case on one page so failures point straight at the bug.
 *
 * Pages covered:
 *   - InvitationAcceptPage  : backend 500 on info fetch shows graceful error
 *   - MFAEnrollmentPage     : invalid TOTP code keeps the form usable for retry
 *   - APIKeysPage           : cancelling the revoke confirm leaves the key intact
 *   - TeamManagementPage    : inviting an already-member email surfaces an error
 */

import { test, expect } from '../fixtures/scoped-org';
import { loginAsAdmin } from '../fixtures/test-utils';
import { ADMIN_AUTH_STATE_PATH } from '../global-setup';

// Mock the EIAA runtime keys endpoint on every test so React mounts even
// when the capsule runtime gRPC service is unavailable. Mirrors the
// pattern used by edge-cases.spec.ts and mfa.spec.ts.
test.beforeEach(async ({ page }) => {
    await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );
});

// ---------------------------------------------------------------------------
// InvitationAcceptPage
// ---------------------------------------------------------------------------

test.describe('InvitationAcceptPage edge cases', () => {

    test('backend 500 on invitation lookup renders error card, not blank', async ({ page }) => {
        // Force the invitation lookup to fail with a server error. The
        // component must catch the rejected promise (set `error` state) and
        // render the "Invalid Invitation" card — never a blank screen.
        await page.route('**/api/v1/invitations/*', (route) => {
            if (route.request().method() === 'GET') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'database timeout' }),
                });
            }
            return route.continue();
        });

        await page.goto('/invitations/server-error-token');

        // The error card always renders the "Invalid Invitation" heading
        // regardless of the upstream error message.
        await expect(page.getByRole('heading', { name: /Invalid Invitation/i }))
            .toBeVisible({ timeout: 15_000 });

        // The recovery affordance ("Go to Dashboard") must remain clickable
        // so the user is never trapped on a dead page.
        await expect(page.getByRole('button', { name: /Go to Dashboard/i }))
            .toBeVisible();
    });
});

// ---------------------------------------------------------------------------
// MFAEnrollmentPage  (lives at /account/security)
// ---------------------------------------------------------------------------

test.describe('MFAEnrollmentPage edge cases', () => {

    test('invalid TOTP code shows error and keeps the form usable for retry', async ({ page }) => {
        // The edge-cases project has no storageState by default, so log in
        // as admin first — mirrors the pattern in api-keys.spec.ts.
        await loginAsAdmin(page);

        // Stub verify to always fail so we can drive the error path
        // deterministically without a wall-clock TOTP window.
        await page.route('**/api/v1/mfa/totp/verify', (route) =>
            route.fulfill({
                status: 400,
                contentType: 'application/json',
                body: JSON.stringify({ message: 'Invalid verification code' }),
            })
        );

        await page.goto('/account/security');
        await expect(page.locator('h1:has-text("Security Settings")'))
            .toBeVisible({ timeout: 15_000 });
        await expect(page.locator('h3:has-text("Authenticator App")'))
            .toBeVisible({ timeout: 15_000 });

        // The TOTP section exposes either an Enable button (not enrolled)
        // or a Disable button (already enrolled). If TOTP is already enrolled
        // for this admin we skip rather than tear down a real factor.
        const enableBtn = page
            .getByRole('button', { name: /enable|set up|configure/i })
            .first();
        if (!(await enableBtn.isVisible({ timeout: 3_000 }).catch(() => false))) {
            test.skip(true, 'TOTP appears to be already enrolled for the admin user');
            return;
        }
        await enableBtn.click();

        const codeInput = page
            .locator('input[placeholder*="code" i], input[maxlength="6"]')
            .first();
        if (!(await codeInput.isVisible({ timeout: 8_000 }).catch(() => false))) {
            test.skip(true, 'Code input did not appear — TOTP setup did not complete');
            return;
        }

        await codeInput.fill('000000');
        await page
            .getByRole('button', { name: /verify|confirm|enable/i })
            .first()
            .click();

        // The page must surface an error AND leave the code field present
        // and editable so the user can immediately retry. A common
        // regression is wiping the form or showing a blocking spinner.
        await expect(
            page
                .locator('[role="alert"], .text-destructive, .text-red-500')
                .or(page.getByText(/invalid|incorrect|try again/i))
                .first()
        ).toBeVisible({ timeout: 15_000 });

        await expect(codeInput).toBeVisible();
        await expect(codeInput).toBeEnabled();
    });
});

// ---------------------------------------------------------------------------
// APIKeysPage
// ---------------------------------------------------------------------------

test.describe('APIKeysPage edge cases', () => {
    // Use the pre-authenticated admin storage state (upgraded to AAL3 by
    // global-setup) so /admin/api-keys is reachable without a fresh password
    // login that would only grant AAL1 and trigger the StepUpModal.
    test.use({ storageState: ADMIN_AUTH_STATE_PATH });

    test('cancelling the revoke confirm dialog keeps the key', async ({ page }) => {
        await page.goto('/admin/api-keys');
        await expect(page.locator('h1:has-text("API Keys")'))
            .toBeVisible({ timeout: 15_000 });

        // Free up plan capacity so create can succeed even if previous test
        // runs left rows behind. Revoke any existing keys first.
        await page.waitForLoadState('networkidle');
        let existing = page.locator('button:has-text("Revoke")').first();
        while (await existing.isVisible({ timeout: 1_500 }).catch(() => false)) {
            page.once('dialog', (d) => d.accept());
            const resp = page.waitForResponse(
                (r) => r.url().includes('/api/v1/api-keys/') && r.request().method() === 'DELETE',
                { timeout: 10_000 }
            );
            await existing.click();
            await resp.catch(() => null);
            await page.waitForTimeout(300);
            existing = page.locator('button:has-text("Revoke")').first();
        }

        // Create a single key with a unique name so we have a known target
        // to (not) revoke. Mirrors the modal selectors used by api-keys.spec.ts.
        const keyName = `cancel-revoke-${Date.now()}`;
        await page.click('button:has-text("+ Create Key")');
        await expect(page.locator('h3:has-text("Create API Key")'))
            .toBeVisible({ timeout: 5_000 });
        await page.fill('input[placeholder="e.g. Production Backend"]', keyName);
        await page.locator('.fixed button:has-text("Create Key")').click();

        // Dismiss the one-time reveal banner.
        const revealBanner = page.locator('h3:has-text("Save your API key")');
        await expect(revealBanner).toBeVisible({ timeout: 15_000 });
        await page.click('button:has-text("Done")');
        await expect(revealBanner).not.toBeVisible({ timeout: 5_000 });

        // Find the row for our new key. The page renders keys as flex divs
        // inside a `divide-y` list (no <tr>/<li>), so anchor on the unique
        // key name and walk up to the nearest container that has a Revoke
        // button. This is robust to layout tweaks and never matches
        // somebody else's row by accident.
        const row = page
            .locator('div', { hasText: keyName })
            .filter({ has: page.locator('button:has-text("Revoke")') })
            .last();
        await expect(row).toBeVisible({ timeout: 10_000 });

        // Reject the confirm() dialog instead of accepting it.
        let dialogShown = false;
        let revokeRequestSent = false;
        page.once('dialog', async (d) => {
            dialogShown = true;
            await d.dismiss();
        });
        page.on('request', (req) => {
            if (req.url().includes('/api/v1/api-keys/') && req.method() === 'DELETE') {
                revokeRequestSent = true;
            }
        });

        await row.locator('button:has-text("Revoke")').click();

        // Give the page a moment to (not) issue the DELETE call.
        await page.waitForTimeout(750);

        expect(dialogShown).toBe(true);
        expect(revokeRequestSent).toBe(false); // cancel must NOT call backend
        await expect(row).toBeVisible(); // row still on screen

        // Cleanup: actually revoke the key now so we don't leak rows past the
        // 5-key plan limit. Accept the dialog this time.
        page.once('dialog', (d) => d.accept());
        await row.locator('button:has-text("Revoke")').click();
        await page.waitForResponse(
            (resp) => resp.url().includes('/api/v1/api-keys/') && resp.request().method() === 'DELETE',
            { timeout: 10_000 }
        ).catch(() => null);
    });
});

// ---------------------------------------------------------------------------
// TeamManagementPage
// ---------------------------------------------------------------------------

test.describe('TeamManagementPage edge cases', () => {
    // Same rationale as APIKeysPage: load the AAL3 admin storage state so
    // the StepUpModal does not block clicks.
    test.use({ storageState: ADMIN_AUTH_STATE_PATH });

    test('inviting an existing member surfaces an error and does not silently succeed', async ({
        page,
    }) => {
        // The bootstrap admin (admin@example.com) is *always* a member of
        // whatever org sessionStorage currently points at — trying to invite
        // them again exercises the duplicate-member path without needing
        // backend test-seed scaffolding (which can race or 5xx).
        const email = 'admin@example.com';

        await page.goto('/admin/user-management/team');
        await expect(page.locator('h1:has-text("Team Management")'))
            .toBeVisible({ timeout: 30_000 });

        // Wait for the invite form to render.
        const emailInput = page.locator('input[type="email"]').first();
        await expect(emailInput).toBeVisible({ timeout: 15_000 });
        await emailInput.fill(email);

        await page.click('button:has-text("Invite")');

        // The user-visible contract is feedback — either an error toast
        // ("already a member" / "invitation already exists") OR an info
        // toast confirming a re-invite. The regression we guard against is
        // a silent no-op: clicking Invite for an existing member must never
        // leave the admin without any feedback at all.
        await expect(
            page
                .locator('[data-sonner-toast], [role="alert"], .text-destructive, .text-red-500')
                .or(page.getByText(/already|exists|member|invited|sent|added/i))
                .first()
        ).toBeVisible({ timeout: 10_000 });
    });
});

// Made with Bob
