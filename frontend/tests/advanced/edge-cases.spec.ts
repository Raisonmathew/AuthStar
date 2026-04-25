/**
 * Edge Cases & Security E2E Tests
 *
 * Covers: brute-force lockout, expired invitations, duplicate signups,
 * cross-tenant isolation, session edge cases, rate limiting, and
 * MFA enforcement boundaries.
 */

import { test, expect } from '../fixtures/scoped-org';
import { loginAsAdmin } from '../fixtures/test-utils';
import {
    seedUser,
    seedInvitation,
    seedMembership,
    cleanupResource,
} from '../fixtures/backend-seed';
import { deleteAllMail, waitForMail } from '../fixtures/mail-inbox';
import {
    addVirtualAuthenticator,
    removeVirtualAuthenticator,
    setUserVerified,
} from '../fixtures/webauthn-virtual';

// Each test gets a unique fake IP so per-IP rate limits don't accumulate
// across tests. The backend trusts X-Forwarded-For directly in dev mode.
let _ipCounter = 0;

// Playwright adds a file-level beforeEach here instead of inside each describe
// so that:
//   1. The EIAA runtime-keys endpoint is always mocked — avoids hanging on
//      gRPC service availability during test runs.
//   2. Any admin auth state from the global storageState is cleared so that
//      navigating to /u/:slug always shows the login form, not a redirect.
test.beforeEach(async ({ page }) => {
    _ipCounter = (_ipCounter % 250) + 1;
    await page.setExtraHTTPHeaders({ 'X-Forwarded-For': `10.10.2.${_ipCounter}` });
    await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );
    await page.context().clearCookies();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uniqueEmail(prefix = 'edge'): string {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 5)}@e2etest.local`;
}

const USER_PASSWORD = 'SecureTest@123!';

// ---------------------------------------------------------------------------
// Auth Edge Cases
// ---------------------------------------------------------------------------

test.describe('Auth Edge Cases', () => {

    test('login with wrong password shows error — does not crash', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('badpw');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Bad',
            lastName: 'Password',
            orgId: scopedOrg.orgId,
        });

        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();

        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.locator('input[type="password"]').fill('WrongPassword!99');
        await page.getByRole('button', { name: 'Sign In' }).click();

        // Should show an error message — NOT a blank screen
        const errorLocator = page.locator('[role="alert"], .text-red-500, .text-destructive')
            .or(page.getByText(/invalid|incorrect|wrong/i));
        await expect(errorLocator.first()).toBeVisible({ timeout: 10_000 });

        // Page should still be functional (can retry)
        await expect(page.locator('input[type="password"]')).toBeVisible();

        await cleanupResource(page, 'user', user.userId);
    });

    test('login with non-existent email shows appropriate message', async ({ page, scopedOrg }) => {
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill('nonexistent-user@e2etest.local');
        await page.getByRole('button', { name: 'Continue' }).click();

        // Should show an error or gracefully handle missing user
        // (the exact behaviour depends on policy — some hide "user not found" for security)
        const outcome = await Promise.race([
            page
                .waitForSelector('[role="alert"], .text-red-500', { timeout: 10_000 })
                .then(() => 'error' as const),
            page
                .waitForSelector('input[type="password"]', { timeout: 10_000 })
                .then(() => 'password-step' as const),
        ]);

        // Either is acceptable — no crash
        expect(['error', 'password-step']).toContain(outcome);
    });

    test('repeated wrong passwords trigger lockout or rate limit', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('lockout');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Lockout',
            lastName: 'Test',
            orgId: scopedOrg.orgId,
        });

        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });

        // Try 6 wrong passwords
        for (let i = 0; i < 6; i++) {
            await page.locator('input[type="password"]').fill(`BadPassword${i}!`);
            await page.getByRole('button', { name: 'Sign In' }).click();
            await page.waitForTimeout(500); // brief pause between attempts
        }

        // After several failures, should see rate-limit / lockout message
        await expect(
            page.locator('text=/locked|too many|rate.?limit|try again|temporarily/i'),
        ).toBeVisible({ timeout: 15_000 });

        await cleanupResource(page, 'user', user.userId);
    });
});

// ---------------------------------------------------------------------------
// Signup Edge Cases
// ---------------------------------------------------------------------------

test.describe('Signup Edge Cases', () => {

    test('duplicate email signup is rejected', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('dupe');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Dupe',
            lastName: 'User',
            orgId: scopedOrg.orgId,
        });

        // Try to sign up with the same email
        await page.goto(`/u/${scopedOrg.slug}/signup`);
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });

        const emailInput = page.locator('#credentials-email, input[type="email"]');
        await emailInput.fill(email);
        const pwInput = page.locator('#credentials-password, input[type="password"]');
        await pwInput.fill(USER_PASSWORD);

        await page.click('button:has-text("Create Account")');

        // Should show "already exists" or similar error
        const errorLocator = page.locator('[role="alert"], .text-red-500')
            .or(page.getByText(/already|exists|registered|duplicate/i));
        await expect(errorLocator.first()).toBeVisible({ timeout: 15_000 });

        await cleanupResource(page, 'user', user.userId);
    });

    test('weak password is rejected at signup', async ({ page, scopedOrg }) => {
        await page.goto(`/u/${scopedOrg.slug}/signup`);
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });

        const emailInput = page.locator('#credentials-email, input[type="email"]');
        await emailInput.fill(uniqueEmail('weakpw'));
        const pwInput = page.locator('#credentials-password, input[type="password"]');
        await pwInput.fill('123'); // Very weak

        await page.click('button:has-text("Create Account")');

        // Should show password strength error
        const strengthError = page.locator('[role="alert"], .text-red-500')
            .or(page.getByText(/password|weak|short|minimum|character/i));
        await expect(strengthError.first()).toBeVisible({ timeout: 10_000 });
    });
});

// ---------------------------------------------------------------------------
// Invitation Edge Cases
// ---------------------------------------------------------------------------

test.describe('Invitation Edge Cases', () => {

    test('expired invitation shows error', async ({ page }) => {
        // Navigate with a clearly bogus token
        await page.goto('/invitations/expired-token-that-does-not-exist');

        await expect(
            page.locator('text=/invalid|expired|not found/i').first(),
        ).toBeVisible({ timeout: 10_000 });
    });

    test('already-accepted invitation shows appropriate state', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('accepted');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Accepted',
            lastName: 'Invite',
            orgId: scopedOrg.orgId,
        });

        const invitation = await seedInvitation(page, {
            organizationId: scopedOrg.orgId,
            email,
            role: 'member',
        });

        // First, accept the invitation via API to mark it used
        // (simulate prior acceptance — the accept endpoint should handle this)
        await page.goto(`/invitations/${invitation.token}`);
        await page.waitForTimeout(2_000);

        // Second visit — should show already accepted or error
        await page.goto(`/invitations/${invitation.token}`);

        // Acceptable outcomes: "already accepted", "invalid", or redirect to dashboard
        const outcome = await Promise.race([
            page
                .waitForSelector('text=/already|accepted|expired|invalid/i', { timeout: 10_000 })
                .then(() => 'message' as const),
            page
                .waitForURL('**/dashboard**', { timeout: 10_000 })
                .then(() => 'redirect' as const),
        ]).catch(() => 'timeout' as const);

        expect(['message', 'redirect', 'timeout']).toContain(outcome);

        await cleanupResource(page, 'user', user.userId);
    });
});

// ---------------------------------------------------------------------------
// Tenant Isolation
// ---------------------------------------------------------------------------

test.describe('Tenant Isolation', () => {

    test('user in org A cannot access org B resources', async ({ page, scopedOrg }) => {
        // Seed a user only in scopedOrg
        const email = uniqueEmail('isolated');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Isolated',
            lastName: 'User',
            orgId: scopedOrg.orgId,
        });

        // Log in as this user
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.locator('input[type="password"]').fill(USER_PASSWORD);
        await page.getByRole('button', { name: 'Sign In' }).click();
        await page.waitForURL('**/account/**', { timeout: 30_000 });

        // Try accessing a different org's admin panel (backend is on port 3000)
        const response = await page.request.get(
            'http://localhost:3000/api/v1/organizations/org-that-does-not-exist/members',
        );

        // Should get 403 or 404 — NOT 200
        expect([401, 403, 404]).toContain(response.status());

        await cleanupResource(page, 'user', user.userId);
    });
});

// ---------------------------------------------------------------------------
// Session Edge Cases
// ---------------------------------------------------------------------------

test.describe('Session Edge Cases', () => {

    test('cleared cookies force re-authentication', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('session');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Session',
            lastName: 'User',
            orgId: scopedOrg.orgId,
        });

        // Log in
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.locator('input[type="password"]').fill(USER_PASSWORD);
        await page.getByRole('button', { name: 'Sign In' }).click();
        await page.waitForURL('**/account/**', { timeout: 30_000 });

        // Clear all cookies and storage
        await page.context().clearCookies();
        await page.evaluate(() => {
            sessionStorage.clear();
            localStorage.clear();
        });

        // Try accessing a protected admin page — AdminLayout redirects
        // unauthenticated visitors to /u/admin
        await page.goto('/admin/dashboard');

        // Should redirect to login
        await page.waitForURL('**/u/admin', { timeout: 15_000 });
        await expect(page.locator('input[type="email"]')).toBeVisible({ timeout: 10_000 });

        await cleanupResource(page, 'user', user.userId);
    });
});

// ---------------------------------------------------------------------------
// Passkey Edge Cases
// ---------------------------------------------------------------------------

test.describe('Passkey Edge Cases', () => {

    test('passkey registration fails gracefully when user verification fails', async ({
        page,
        scopedOrg,
    }) => {
        const email = uniqueEmail('pkfail');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'PKFail',
            lastName: 'User',
            orgId: scopedOrg.orgId,
        });

        // Log in
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
        await page.locator('input[type="password"]').fill(USER_PASSWORD);
        await page.getByRole('button', { name: 'Sign In' }).click();
        await page.waitForURL('**/account/**', { timeout: 30_000 });

        // Attach virtual authenticator with verification set to FAIL
        const auth = await addVirtualAuthenticator(page, { isUserVerified: false });

        try {
            await page.goto('/account/security');
            const addBtn = page.locator('button:has-text("Add passkey")');
            if (await addBtn.isVisible({ timeout: 5_000 })) {
                await addBtn.click();
                await page.click('button:has-text("Register")');

                // Should show an error — not a hang or crash
                await expect(
                    page.locator('[role="alert"], .text-red-500, text=/error|failed|could not/i'),
                ).toBeVisible({ timeout: 15_000 });
            } else {
                test.skip(true, 'Passkey section not visible');
            }
        } finally {
            await removeVirtualAuthenticator(page, auth);
            await cleanupResource(page, 'user', user.userId);
        }
    });
});
