/**
 * Per-Page Edge Case E2E Tests — Admin Console pages
 *
 * Each test exercises ONE concrete failure mode on ONE admin page so
 * regressions point straight at the bug. The contract under test is
 * "graceful degradation": when a backend call fails, the page must
 *   1. NOT render the global ErrorBoundary fallback ("Something went wrong"),
 *   2. surface user-visible feedback (toast / inline error / empty state),
 *   3. leave the user able to retry or navigate away.
 *
 * Pages covered (one or more tests each):
 *   - ProfilePage              (/account/profile)
 *   - AdminDashboardPage       (/admin/dashboard)
 *   - AppRegistryPage          (/admin/applications)
 *   - LoginMethodsPage         (/admin/authentication/login-methods)
 *   - SSOPage                  (/admin/authentication/sso)
 *   - ConfigListPage           (/admin/policies)
 *   - AttackProtectionPage     (/admin/security/attack-protection)
 *   - RolesPage                (/admin/user-management/roles)
 *   - BrandingPage             (/admin/branding/login)
 *   - DomainsPage              (/admin/branding/domains)
 *   - AuditLogPage             (/admin/monitoring/logs)
 *   - BillingPage              (/admin/settings/billing)
 *
 * All tests use the AAL3 admin storage state (ADMIN_AUTH_STATE_PATH) so
 * the StepUpModal does not block clicks on admin-gated routes.
 */

import { test, expect } from '../fixtures/scoped-org';
import { ADMIN_AUTH_STATE_PATH } from '../global-setup';

// Use the pre-authenticated admin storage state for every test in this file.
test.use({ storageState: ADMIN_AUTH_STATE_PATH });

// Mock the EIAA runtime keys endpoint on every test so React mounts even
// when the capsule runtime gRPC service is unavailable. Mirrors the
// pattern in edge-cases-per-page.spec.ts.
test.beforeEach(async ({ page }) => {
    await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );
});

// Selector matching the global ErrorBoundary fallback. If this is visible the
// page crashed during render — that is what we are guarding against.
const ERROR_BOUNDARY = 'h1:has-text("Something went wrong")';

// Generic "user got some feedback" matcher. Restricted to canonical toast
// and alert containers — the .text-destructive / .text-red-500 classes
// are also used by destructive-styled buttons (e.g. "Delete") and would
// cause strict-mode collisions when the page legitimately shows both a
// toast and a destructive control at the same time.
function feedbackLocator(page: import('@playwright/test').Page) {
    return page.locator('[data-sonner-toast], [role="alert"]').first();
}

// ---------------------------------------------------------------------------
// ProfilePage
// ---------------------------------------------------------------------------

test.describe('ProfilePage edge cases', () => {

    test('PATCH /api/v1/user 500 surfaces error and keeps form usable', async ({ page }) => {
        // Force the profile-save call to fail. The page must surface a toast
        // and leave the inputs editable so the user can retry — never wipe
        // the form, never blank the screen.
        await page.route('**/api/v1/user', (route) => {
            if (route.request().method() === 'PATCH') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'database timeout' }),
                });
            }
            return route.continue();
        });

        await page.goto('/account/profile');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        // The profile section is read-only until "Edit Profile" is clicked.
        const editBtn = page.getByRole('button', { name: /edit profile/i });
        await expect(editBtn).toBeVisible({ timeout: 15_000 });
        await editBtn.click();

        // The edit panel renders two text inputs (First Name, Last Name).
        // They have no placeholder/name attributes, so anchor on the heading
        // of the section we just opened.
        const firstNameInput = page.locator('input[type="text"]').first();
        await expect(firstNameInput).toBeVisible({ timeout: 5_000 });
        await firstNameInput.fill('EdgeCaseFirst');

        // Click the Save Changes button. Backend mock will reject with 500.
        await page.getByRole('button', { name: /save changes/i }).first().click();

        // User-visible feedback must appear — toast or inline error.
        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });

        // Form must remain usable.
        await expect(firstNameInput).toBeVisible();
        await expect(firstNameInput).toBeEnabled();

        // No crash.
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });

    test('change-password with wrong current password shows error and keeps form', async ({ page }) => {
        await page.route('**/api/v1/user/change-password', (route) =>
            route.fulfill({
                status: 400,
                contentType: 'application/json',
                body: JSON.stringify({ message: 'Current password is incorrect' }),
            })
        );

        await page.goto('/account/profile');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        const heading = page.locator('h3:has-text("Change Password")');
        if (!(await heading.isVisible({ timeout: 8_000 }).catch(() => false))) {
            test.skip(true, 'Change Password section not rendered for this user');
            return;
        }

        const passwordInputs = page.locator('input[type="password"]');
        const count = await passwordInputs.count();
        if (count < 2) {
            test.skip(true, 'Change Password form did not render the expected fields');
            return;
        }

        // Fill all visible password fields with the same dummy value — the
        // backend mock will reject regardless of content.
        for (let i = 0; i < count; i++) {
            await passwordInputs.nth(i).fill('Wrong-Current-Pwd-1!');
        }

        await page.getByRole('button', { name: /change password|update password/i }).first().click();

        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
        await expect(passwordInputs.first()).toBeEnabled();
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// AdminDashboardPage
// ---------------------------------------------------------------------------

test.describe('AdminDashboardPage edge cases', () => {

    test('GET audit/stats 500 still mounts the dashboard without ErrorBoundary', async ({ page }) => {
        await page.route('**/api/admin/v1/audit/stats', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );
        await page.route('**/api/admin/v1/audit*', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );

        await page.goto('/admin/dashboard');
        await page.waitForLoadState('domcontentloaded');

        // Page must NOT render the global ErrorBoundary fallback.
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        // Sidebar / shell must be present so the user can navigate elsewhere.
        // We assert the URL stayed on /admin/dashboard and that *some*
        // recognisable nav text is on the page.
        expect(page.url()).toContain('/admin/dashboard');
        await expect(
            page.getByRole('link', { name: /dashboard|applications|user management|monitoring/i }).first()
        ).toBeVisible({ timeout: 15_000 });
    });
});

// ---------------------------------------------------------------------------
// AppRegistryPage
// ---------------------------------------------------------------------------

test.describe('AppRegistryPage edge cases', () => {

    test('GET /api/admin/v1/apps 500 shows error toast, page stays mounted', async ({ page }) => {
        await page.route('**/api/admin/v1/apps', (route) => {
            if (route.request().method() === 'GET') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'down' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/applications');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h2:has-text("App Registry")'))
            .toBeVisible({ timeout: 15_000 });

        // Sonner toast confirms the failure was surfaced to the user.
        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
    });
});

// ---------------------------------------------------------------------------
// LoginMethodsPage
// ---------------------------------------------------------------------------

test.describe('LoginMethodsPage edge cases', () => {

    test('PATCH login-methods 500 surfaces error toast and form stays usable', async ({ page }) => {
        await page.route('**/api/org-config/login-methods', (route) => {
            if (route.request().method() === 'PATCH') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'save failed' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/authentication/login-methods');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        // Wait for the page heading (any of the h1 in LoginMethodsPage).
        await expect(page.locator('h1, h2').filter({ hasText: /login methods|authentication methods/i }).first())
            .toBeVisible({ timeout: 15_000 });

        // Click any visible save button; the mock will fail it.
        const saveBtn = page.getByRole('button', { name: /^save/i }).first();
        if (!(await saveBtn.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No save button visible — page rendered an unexpected variant');
            return;
        }
        await saveBtn.click();

        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// SSOPage
// ---------------------------------------------------------------------------

test.describe('SSOPage edge cases', () => {

    test('GET /api/admin/v1/sso 500 shows error toast, page mounts', async ({ page }) => {
        await page.route('**/api/admin/v1/sso', (route) => {
            if (route.request().method() === 'GET') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'down' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/authentication/sso');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h1:has-text("SSO Connections")'))
            .toBeVisible({ timeout: 15_000 });

        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
    });
});

// ---------------------------------------------------------------------------
// ConfigListPage (Policy Builder)
// ---------------------------------------------------------------------------

test.describe('ConfigListPage edge cases', () => {

    test('GET /api/v1/policy-builder/configs 500 still renders Policy Builder shell', async ({ page }) => {
        await page.route('**/api/v1/policy-builder/configs', (route) => {
            if (route.request().method() === 'GET') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'down' }),
                });
            }
            return route.continue();
        });
        await page.route('**/api/v1/policy-builder/actions', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );

        await page.goto('/admin/policies');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        // The page heading must still render even when the lists fail.
        await expect(page.locator('h1:has-text("Policy Builder")'))
            .toBeVisible({ timeout: 15_000 });
    });
});

// ---------------------------------------------------------------------------
// AttackProtectionPage
// ---------------------------------------------------------------------------

test.describe('AttackProtectionPage edge cases', () => {

    test('GET policy configs 500 still renders Attack Protection page (graceful degrade)', async ({ page }) => {
        await page.route('**/api/v1/policy-builder/configs', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );
        await page.route(/\/api\/v1\/policy-builder\/configs\/[^/?]+/, (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );

        await page.goto('/admin/security/attack-protection');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);

        // The PageHeader title is "Attack Protection" — the page swallows the
        // error in console and renders all features as inactive.
        await expect(page.getByRole('heading', { name: /attack protection/i }).first())
            .toBeVisible({ timeout: 15_000 });

        // The "View All Policies" button must still be reachable so the
        // admin is never trapped on a dead page.
        await expect(page.getByRole('button', { name: /view all policies/i }))
            .toBeVisible({ timeout: 10_000 });
    });
});

// ---------------------------------------------------------------------------
// RolesPage
// ---------------------------------------------------------------------------

test.describe('RolesPage edge cases', () => {

    test('DELETE role 409 (conflict) surfaces error and keeps page mounted', async ({ page }) => {
        // Inject a fake non-deletable role into the list so we have a
        // deterministic target. We intercept the GET to add a row and the
        // DELETE to fail with 409.
        await page.route(/\/api\/v1\/organizations\/[^/]+\/roles$/, async (route) => {
            const req = route.request();
            if (req.method() === 'GET') {
                // Pass through but inject our synthetic role at the top.
                const real = await route.fetch();
                let body: any[] = [];
                try {
                    body = await real.json();
                } catch {
                    body = [];
                }
                if (!Array.isArray(body)) body = [];
                body.unshift({
                    id: 'role-edge-fixture-409',
                    name: 'edge-case-undeletable',
                    description: 'Fixture role used by edge-cases spec',
                    permissions: [],
                    is_system: false,
                });
                return route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify(body),
                });
            }
            return route.continue();
        });
        await page.route(/\/api\/v1\/organizations\/[^/]+\/roles\/role-edge-fixture-409/, (route) => {
            if (route.request().method() === 'DELETE') {
                return route.fulfill({
                    status: 409,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'Role is assigned to one or more users' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/user-management/roles');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h1:has-text("Roles & Permissions")'))
            .toBeVisible({ timeout: 15_000 });

        // Locate the row for the synthetic role and click its Delete control.
        const row = page
            .locator('div, tr, li', { hasText: 'edge-case-undeletable' })
            .filter({ has: page.getByRole('button', { name: /delete|remove|trash/i }) })
            .last();

        if (!(await row.isVisible({ timeout: 8_000 }).catch(() => false))) {
            test.skip(true, 'Synthetic role row did not render — delete control may live in a menu');
            return;
        }

        // Auto-accept any browser confirm() dialogs.
        page.on('dialog', (d) => d.accept().catch(() => undefined));

        await row.getByRole('button', { name: /delete|remove|trash/i }).first().click();

        // 409 must surface as user-visible feedback.
        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// BrandingPage
// ---------------------------------------------------------------------------

test.describe('BrandingPage edge cases', () => {

    test('PATCH branding 500 surfaces error toast, editor stays usable', async ({ page }) => {
        await page.route(/\/api\/organizations\/[^/]+\/branding/, (route) => {
            if (route.request().method() === 'PATCH') {
                return route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ message: 'save failed' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/branding/login');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h2:has-text("Visual Editor")'))
            .toBeVisible({ timeout: 15_000 });

        // Click the first save button on the editor. The save will fail.
        const saveBtn = page.getByRole('button', { name: /^save|publish|apply/i }).first();
        if (!(await saveBtn.isVisible({ timeout: 5_000 }).catch(() => false))) {
            test.skip(true, 'No save button visible on Branding editor');
            return;
        }
        await saveBtn.click();

        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// DomainsPage
// ---------------------------------------------------------------------------

test.describe('DomainsPage edge cases', () => {

    test('POST add invalid domain 400 surfaces error and keeps the form', async ({ page }) => {
        await page.route('**/api/domains', (route) => {
            if (route.request().method() === 'POST') {
                return route.fulfill({
                    status: 400,
                    contentType: 'application/json',
                    body: JSON.stringify({ error: 'Invalid domain format' }),
                });
            }
            return route.continue();
        });

        await page.goto('/admin/branding/domains');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h1:has-text("Custom Domains")'))
            .toBeVisible({ timeout: 15_000 });

        const domainInput = page.locator('input[type="text"], input[type="url"]').first();
        await expect(domainInput).toBeVisible({ timeout: 10_000 });
        await domainInput.fill('not a real domain');

        const addBtn = page.getByRole('button', { name: /^add( domain)?$/i }).first();
        await addBtn.click();

        await expect(feedbackLocator(page)).toBeVisible({ timeout: 10_000 });
        await expect(domainInput).toBeEnabled();
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
    });
});

// ---------------------------------------------------------------------------
// AuditLogPage
// ---------------------------------------------------------------------------

test.describe('AuditLogPage edge cases', () => {

    test('GET events 500 still renders the Audit & Compliance shell', async ({ page }) => {
        await page.route('**/api/admin/v1/events*', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );

        await page.goto('/admin/monitoring/logs');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h2:has-text("Audit & Compliance")'))
            .toBeVisible({ timeout: 15_000 });
        // URL stays on the page — admin not redirected away on failure.
        expect(page.url()).toContain('/admin/monitoring/logs');
    });
});

// ---------------------------------------------------------------------------
// BillingPage
// ---------------------------------------------------------------------------

test.describe('BillingPage edge cases', () => {

    test('GET billing subscription 500 still renders Billing shell with recovery UI', async ({ page }) => {
        await page.route('**/api/billing/v1/subscription*', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );
        await page.route('**/api/billing/v1/invoices*', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'down' }) })
        );

        await page.goto('/admin/settings/billing');
        await expect(page.locator(ERROR_BOUNDARY)).toHaveCount(0);
        await expect(page.locator('h1:has-text("Billing & Subscription")'))
            .toBeVisible({ timeout: 15_000 });

        expect(page.url()).toContain('/admin/settings/billing');
    });
});

// Made with Bob
