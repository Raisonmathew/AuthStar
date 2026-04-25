/**
 * Per-Page Edge Case E2E Tests — Public / unauthenticated pages
 *
 * Covers:
 *   - AuthFlowPage (login intent)         — identify call 500
 *   - AuthFlowPage (signup intent)        — sign-up call 409 (email taken)
 *   - AuthFlowPage (resetpassword intent) — identify call 500
 *   - OAuthConsentPage                    — visited without query params
 *
 * The contract under test is "graceful degradation": a backend failure
 * must not blank the screen, must surface user-visible feedback, and
 * must leave the form usable for retry.
 *
 * These tests run under the edge-cases project, which has no
 * storageState — every test is a fresh, anonymous browser context.
 */

import { test, expect } from '../fixtures/scoped-org';

// Mock the EIAA runtime keys endpoint on every test so React mounts even
// when the capsule runtime gRPC service is unavailable.
test.beforeEach(async ({ page }) => {
    await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );
});

const ERROR_BOUNDARY = 'h1:has-text("Something went wrong")';

function feedbackLocator(page: import('@playwright/test').Page) {
    // Canonical containers only — destructive-styled buttons share the
    // .text-red-* / .text-destructive classes and cause strict-mode
    // violations when both a toast and a button match.
    return page.locator('[data-sonner-toast], [role="alert"]').first();
}

// AuthFlowPage uses inline error panels (`bg-red-50 border-red-200 text-red-700`)
// for identify/init failures rather than Sonner toasts, so we accept any of:
//   - sonner toast
//   - role="alert" (FieldError component)
//   - the inline error panel
//   - the "System Error" catch-all heading
function authFlowErrorLocator(page: import('@playwright/test').Page) {
    return page
        .locator(
            '[data-sonner-toast], [role="alert"], .bg-red-50, h3:has-text("System Error")'
        )
        .first();
}

// ---------------------------------------------------------------------------
// AuthFlowPage — login intent
// ---------------------------------------------------------------------------

test.describe('AuthFlowPage (login) edge cases', () => {

    test('identify call 500 surfaces error and keeps email step usable', async ({ page }) => {
        // Let the flow init succeed normally (real backend), but force the
        // identify call (after the user types their email) to fail. The
        // page must show an error and leave the email input editable.
        await page.route(/\/api\/v1\/auth-flow\/[^/]+\/identify/, (route) => {
            if (route.request().method() === 'POST') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'identify failed' }),
                });
            }
            return route.continue();
        });

        await page.goto('/u/default');
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        const email = page.locator('input[type="email"]');
        await email.fill('edge.case@example.com');
        await page.click('button[type="submit"]');

        // Some user-visible failure indicator must appear.
        await expect(authFlowErrorLocator(page)).toBeVisible({ timeout: 15_000 });

        // Email step must remain usable for retry — the input is still
        // present, enabled, and we are still on the same /u/* route.
        await expect(email).toBeVisible();
        await expect(email).toBeEnabled();
        expect(page.url()).toContain('/u/');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// AuthFlowPage — signup intent
// ---------------------------------------------------------------------------

test.describe('AuthFlowPage (signup) edge cases', () => {

    test('sign-up 409 (email taken) surfaces error and keeps form usable', async ({ page }) => {
        await page.route('**/api/v1/sign-up', (route) => {
            if (route.request().method() === 'POST') {
                return route.fulfill({
                    status: 409,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'Email already registered' }),
                });
            }
            return route.continue();
        });
        // Whatever path the signup flow uses to validate the email at the
        // server, also fail it with 409 so we cover both code paths.
        await page.route(/\/api\/v1\/auth-flow\/[^/]+\/identify/, (route) => {
            if (route.request().method() === 'POST') {
                return route.fulfill({
                    status: 409,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'Email already registered' }),
                });
            }
            return route.continue();
        });

        await page.goto('/u/default/signup');

        // Some orgs disable self-registration. If the email step never
        // appears within a generous timeout the page is showing a
        // "signup disabled" or org-error state — still a graceful UX, just
        // not the path this test exercises. Skip rather than fail.
        const email = page.locator('input[type="email"]');
        if (!(await email.first().isVisible({ timeout: 15_000 }).catch(() => false))) {
            await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
            test.skip(true, 'Signup email step did not render — signup may be disabled for the default org');
            return;
        }
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        await email.fill('admin@example.com');
        await page.click('button[type="submit"]');

        await expect(authFlowErrorLocator(page)).toBeVisible({ timeout: 15_000 });
        await expect(email).toBeVisible();
        await expect(email).toBeEnabled();
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// AuthFlowPage — reset-password intent
// ---------------------------------------------------------------------------

test.describe('AuthFlowPage (resetpassword) edge cases', () => {

    test('identify 500 on reset-password keeps form usable', async ({ page }) => {
        await page.route(/\/api\/v1\/auth-flow\/[^/]+\/identify/, (route) => {
            if (route.request().method() === 'POST') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'identify failed' }),
                });
            }
            return route.continue();
        });

        await page.goto('/u/default/reset-password');
        await page.waitForSelector('input[type="email"]', { timeout: 15_000 });
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        const email = page.locator('input[type="email"]');
        await email.fill('edge.reset@example.com');
        await page.click('button[type="submit"]');

        await expect(authFlowErrorLocator(page)).toBeVisible({ timeout: 15_000 });
        await expect(email).toBeVisible();
        await expect(email).toBeEnabled();
        expect(page.url()).toContain('/u/');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// OAuthConsentPage
// ---------------------------------------------------------------------------

test.describe('OAuthConsentPage edge cases', () => {

    test('visiting /oauth/consent without oauth_flow_id renders the error card', async ({ page }) => {
        // The page short-circuits to its error state when the required
        // query param is missing — no backend call needed. We're
        // protecting against a regression that would render a blank page
        // or crash the ErrorBoundary on an obviously broken URL.
        await page.goto('/oauth/consent');

        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.getByRole('heading', { name: /Authorization Error/i }))
            .toBeVisible({ timeout: 15_000 });

        // The page must surface the specific reason so support can
        // diagnose. The component sets "Missing OAuth flow ID".
        await expect(page.getByText(/Missing OAuth flow ID/i))
            .toBeVisible({ timeout: 5_000 });
    });

    test('GET /api/oauth/consent 500 with valid id renders the error card', async ({ page }) => {
        await page.route('**/api/oauth/consent*', (route) => {
            if (route.request().method() === 'GET') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'down' }),
                });
            }
            return route.continue();
        });

        await page.goto('/oauth/consent?oauth_flow_id=edge-fixture-flow-id');

        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.getByRole('heading', { name: /Authorization Error/i }))
            .toBeVisible({ timeout: 15_000 });
    });
});

// Made with Bob
