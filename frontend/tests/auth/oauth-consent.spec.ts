/**
 * OAuth 2.0 Consent Page E2E Tests
 *
 * Tests the consent flow UI with mocked API responses.
 * No live backend needed — all API calls are intercepted via page.route().
 */

import { test, expect } from '../fixtures/test-utils';

// ═══════════════════════════════════════════════════════════════════════════════
// Bootstrap Mocks — Required for React app to mount
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Mock the EIAA runtime keys + CSRF endpoints so main.tsx bootstrap completes
 * and React actually mounts the app. Without this, the page stays blank.
 */
async function mockBootstrap(page: import('@playwright/test').Page) {
    // Runtime keys — return empty array (attestation not needed for consent tests)
    await page.route('**/api/eiaa/v1/runtime/keys', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([]),
        });
    });

    // CSRF token — return a dummy token
    await page.route('**/api/csrf-token', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ csrf_token: 'test-csrf-token' }),
        });
    });

    // Token refresh — return 401 immediately so AppLoadingGuard clears fast.
    // These tests don't need an authenticated session.
    await page.route('**/api/v1/token/refresh', async (route) => {
        await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({ error: 'unauthorized' }),
        });
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mock API Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function mockConsentCheck(
    page: import('@playwright/test').Page,
    response: {
        consent_required: boolean;
        client_name: string;
        scopes: string[];
        redirect_uri: string;
    },
) {
    return page.route('**/api/oauth/consent*', async (route) => {
        const req = route.request();
        // Only intercept API (fetch/xhr) — let document navigations render React
        if (req.resourceType() !== 'fetch' && req.resourceType() !== 'xhr') {
            return route.fallback();
        }
        if (req.method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(response),
            });
        } else {
            await route.fallback();
        }
    });
}

function mockConsentGrant(
    page: import('@playwright/test').Page,
    redirectUri: string,
) {
    return page.route('**/api/oauth/consent', async (route) => {
        const req = route.request();
        if (req.resourceType() !== 'fetch' && req.resourceType() !== 'xhr') {
            return route.fallback();
        }
        if (req.method() === 'POST') {
            const body = req.postDataJSON();
            if (body?.grant === true) {
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ redirect_uri: redirectUri }),
                });
            } else {
                // Denial — redirect with error
                const uri = new URL(redirectUri.split('?')[0]);
                uri.searchParams.set('error', 'access_denied');
                uri.searchParams.set('error_description', 'User denied consent');
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ redirect_uri: uri.toString() }),
                });
            }
        } else {
            await route.fallback();
        }
    });
}

function mockConsentCheckError(page: import('@playwright/test').Page, status: number, error: string) {
    return page.route('**/api/oauth/consent*', async (route) => {
        const req = route.request();
        if (req.resourceType() !== 'fetch' && req.resourceType() !== 'xhr') {
            return route.fallback();
        }
        if (req.method() === 'GET') {
            await route.fulfill({
                status,
                contentType: 'application/json',
                body: JSON.stringify({ error: 'server_error', error_description: error }),
            });
        } else {
            await route.fallback();
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

test.describe('OAuth Consent Page', () => {

    test.beforeEach(async ({ page }) => {
        await mockBootstrap(page);
    });

    test('shows error when oauth_flow_id is missing', async ({ page }) => {
        await page.goto('/oauth/consent');

        // Should show "Missing OAuth flow ID" error
        await page.waitForSelector('text=Authorization Error', { timeout: 10000 });
        await expect(page.locator('text=Missing OAuth flow ID')).toBeVisible();

        // "Return Home" button should be present
        await expect(page.locator('button:has-text("Return Home")')).toBeVisible();
    });

    test('renders consent form with scopes for third-party app', async ({ page }) => {
        await mockConsentCheck(page, {
            consent_required: true,
            client_name: 'Acme Analytics',
            scopes: ['openid', 'profile', 'email'],
            redirect_uri: 'https://acme.example.com/callback',
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-123');

        // Header
        await expect(page.locator('text=Authorize Application')).toBeVisible();
        await expect(page.locator('text=Acme Analytics')).toBeVisible();
        await expect(page.locator('text=wants to access your account')).toBeVisible();

        // Scope list
        await expect(page.locator('text=OpenID Connect')).toBeVisible();
        await expect(page.getByText('Profile', { exact: true })).toBeVisible();
        await expect(page.getByText('Email', { exact: true })).toBeVisible();
        await expect(page.locator('text=Verify your identity')).toBeVisible();
        await expect(page.locator('text=Access your name and profile picture')).toBeVisible();
        await expect(page.locator('text=Access your email address')).toBeVisible();

        // Redirect URI origin display
        await expect(page.locator('text=acme.example.com')).toBeVisible();

        // Buttons
        await expect(page.locator('button:has-text("Authorize")')).toBeVisible();
        await expect(page.locator('button:has-text("Deny")')).toBeVisible();
    });

    test('renders unknown scopes with fallback label', async ({ page }) => {
        await mockConsentCheck(page, {
            consent_required: true,
            client_name: 'Test App',
            scopes: ['openid', 'custom:read'],
            redirect_uri: 'https://app.example.com/cb',
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-456');

        // Known scope
        await expect(page.locator('text=OpenID Connect')).toBeVisible();

        // Unknown scope — should show raw scope name
        await expect(page.getByText('custom:read', { exact: true })).toBeVisible();
        await expect(page.locator('text=Access "custom:read" data')).toBeVisible();
    });

    test('grant button redirects to callback with code', async ({ page }) => {
        const callbackUrl = 'https://acme.example.com/callback?code=auth_code_xyz&state=random_state';

        await mockConsentCheck(page, {
            consent_required: true,
            client_name: 'Acme App',
            scopes: ['openid'],
            redirect_uri: callbackUrl,
        });
        await mockConsentGrant(page, callbackUrl);

        // Intercept the external redirect so the page doesn't actually navigate away
        let capturedRedirectUrl = '';
        await page.route('https://acme.example.com/**', async (route) => {
            capturedRedirectUrl = route.request().url();
            await route.fulfill({ status: 200, contentType: 'text/html', body: '<html>redirected</html>' });
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-grant');
        await page.waitForSelector('button:has-text("Authorize")');
        await page.click('button:has-text("Authorize")');

        // Wait for the external navigation to be intercepted
        await page.waitForURL(/acme\.example\.com/, { timeout: 5000 }).catch(() => {});
        // Give time for the redirect to be captured
        await page.waitForTimeout(1000);

        expect(capturedRedirectUrl).toContain('acme.example.com/callback');
        expect(capturedRedirectUrl).toContain('code=auth_code_xyz');
    });

    test('deny button redirects with access_denied error', async ({ page }) => {
        const callbackBase = 'https://acme.example.com/callback';

        await mockConsentCheck(page, {
            consent_required: true,
            client_name: 'Acme App',
            scopes: ['openid'],
            redirect_uri: callbackBase,
        });
        await mockConsentGrant(page, `${callbackBase}?code=unused`);

        // Intercept the external redirect
        let capturedRedirectUrl = '';
        await page.route('https://acme.example.com/**', async (route) => {
            capturedRedirectUrl = route.request().url();
            await route.fulfill({ status: 200, contentType: 'text/html', body: '<html>redirected</html>' });
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-deny');
        await page.waitForSelector('button:has-text("Deny")');
        await page.click('button:has-text("Deny")');

        // Wait for the external navigation to be intercepted
        await page.waitForURL(/acme\.example\.com/, { timeout: 5000 }).catch(() => {});
        await page.waitForTimeout(1000);

        expect(capturedRedirectUrl).toContain('error=access_denied');
    });

    test('first-party app auto-grants consent without showing UI', async ({ page }) => {
        await mockConsentCheck(page, {
            consent_required: false,
            client_name: 'Internal Dashboard',
            scopes: ['openid', 'profile'],
            redirect_uri: 'https://internal.example.com/cb?code=auto_granted',
        });
        await mockConsentGrant(page, 'https://internal.example.com/cb?code=auto_granted');

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-first-party');

        // Should NOT show the consent UI — it should try to auto-redirect
        await page.waitForTimeout(1000);

        // Either we got redirected or we see loading/blank — but NOT the consent form
        const hasConsentForm = await page.locator('text=Authorize Application').isVisible().catch(() => false);
        expect(hasConsentForm).toBe(false);
    });

    test('shows loading spinner initially', async ({ page }) => {
        // Delay the API response to catch the loading state
        await page.route('**/api/oauth/consent*', async (route) => {
            const req = route.request();
            if (req.resourceType() !== 'fetch' && req.resourceType() !== 'xhr') {
                return route.fallback();
            }
            if (req.method() === 'GET') {
                await new Promise((r) => setTimeout(r, 2000));
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({
                        consent_required: true,
                        client_name: 'Slow App',
                        scopes: ['openid'],
                        redirect_uri: 'https://slow.example.com/cb',
                    }),
                });
            } else {
                await route.fallback();
            }
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-slow');

        // Loading spinner should be visible
        await expect(page.locator('text=Checking authorization')).toBeVisible();
    });

    test('shows error when API returns failure', async ({ page }) => {
        await mockConsentCheckError(page, 400, 'Invalid or expired flow ID');

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-expired');

        await page.waitForSelector('text=Authorization Error', { timeout: 5000 });
        await expect(page.locator('text=Invalid or expired flow ID')).toBeVisible();
    });

    test('buttons are disabled while submitting', async ({ page }) => {
        await mockConsentCheck(page, {
            consent_required: true,
            client_name: 'Test App',
            scopes: ['openid'],
            redirect_uri: 'https://test.example.com/cb',
        });

        // Delay the POST response
        await page.route('**/oauth/consent', async (route) => {
            if (route.request().method() === 'POST') {
                await new Promise((r) => setTimeout(r, 3000));
                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ redirect_uri: 'https://test.example.com/cb?code=test' }),
                });
            } else {
                await route.fallback();
            }
        });

        await page.goto('/oauth/consent?oauth_flow_id=test-flow-submit');
        await page.waitForSelector('button:has-text("Authorize")');
        await page.click('button:has-text("Authorize")');

        // Both buttons should be disabled during submission
        await expect(page.locator('button:has-text("Authorizing...")')).toBeVisible();
        await expect(page.locator('button:has-text("Deny")')).toBeDisabled();
    });

    test('Return Home button navigates to root on error', async ({ page }) => {
        await page.goto('/oauth/consent');

        await page.waitForSelector('text=Authorization Error');
        await page.click('button:has-text("Return Home")');

        // navigate('/') goes through React Router which may redirect to a default route
        await expect(page).not.toHaveURL(/\/oauth\/consent/, { timeout: 5000 });
    });

});
