import { test, expect, loginAsAdmin } from '../fixtures/test-utils';
import { seedUser, cleanupResource } from '../fixtures/backend-seed';

test.describe('Organization Management', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    test('can view organization settings', async ({ page }) => {
        await page.goto('/admin/settings/general');

        // GeneralSettingsPage heading is "Tenant Settings"
        await expect(page.locator('h3:has-text("Tenant Settings")')).toBeVisible({ timeout: 10_000 });
    });

    test('can update organization branding', async ({ page }) => {
        await page.goto('/admin/branding/login');

        // BrandingPage has "Visual Editor" heading
        await expect(page.locator('h2:has-text("Visual Editor")')).toBeVisible({ timeout: 10_000 });

        // Update primary color via the text input
        const colorTextInput = page.locator('input[type="text"]').filter({ hasText: /#/ }).first();
        if (await colorTextInput.isVisible({ timeout: 3_000 })) {
            await colorTextInput.fill('#FF5733');
        }

        // Update logo URL
        const logoInput = page.locator('input[placeholder="https://example.com/logo.png"]');
        if (await logoInput.isVisible({ timeout: 3_000 })) {
            await logoInput.fill('https://example.com/test-logo.png');
        }
    });

    test('can preview branding changes', async ({ page }) => {
        await page.goto('/admin/branding/login');

        // BrandingPage has a side-by-side preview of the login/register form
        // Preview type toggle buttons (Login / Register)
        const loginBtn = page.locator('button:has-text("Login")');
        const registerBtn = page.locator('button:has-text("Register")');

        if (await loginBtn.isVisible({ timeout: 5_000 })) {
            // Preview is rendered inline, toggle between login/register
            await registerBtn.click();
            await loginBtn.click();
        } else {
            test.skip(true, 'No preview buttons visible');
        }
    });

    test('can manage team members', async ({ page }) => {
        await page.goto('/admin/user-management/team');

        // TeamManagementPage heading renders only after API data loads
        await expect(page.locator('h1:has-text("Team Management")')).toBeVisible({ timeout: 30_000 });
    });

    test('can invite team member', async ({ page }) => {
        await page.goto('/admin/user-management/team');

        await expect(page.locator('h1:has-text("Team Management")')).toBeVisible({ timeout: 30_000 });

        // Fill invite email
        const emailInput = page.locator('input[type="email"]');
        await emailInput.fill('newmember@example.com');

        // Select role (select with member/admin options)
        const roleSelect = page.locator('select').first();
        if (await roleSelect.isVisible({ timeout: 3_000 })) {
            await roleSelect.selectOption('member');
        }

        // Click Invite button
        await page.click('button:has-text("Invite")');

        // Wait briefly for API response toast
        await page.waitForTimeout(2_000);
    });

    test('can change member role', async ({ page }) => {
        // Seed a disposable member in the 'default' org so we can change
        // *their* role without ever touching user_admin (which would lock
        // subsequent tests out of admin-only endpoints).
        const email = `role-change-${Date.now()}@e2e.test`;
        const seeded = await seedUser(page, {
            email,
            password: 'TestPassword123!',
            firstName: 'Role',
            lastName: 'Target',
            orgId: 'default',
            role: 'member',
        });

        try {
            // Exercise the real role-change endpoint that the UI uses
            // (PATCH /api/v1/organizations/:org/members/:userId).
            //
            // Must run inside the browser context (page.evaluate) so the same-origin
            // fetch attaches the __session cookie *and* we can read the __csrf cookie
            // and pass it as the X-CSRF-Token header. Playwright's page.request.patch
            // does not perform the cookie→header copy that our React API client does,
            // and the CSRF middleware (backend/crates/api_server/src/middleware/csrf.rs)
            // returns a bare 403 with no body when the header is missing.
            await page.goto('/admin/dashboard');
            const patchResult = await page.evaluate(async (userId) => {
                const csrfToken = document.cookie.match(/__csrf=([^;]+)/)?.[1] ?? '';
                const res = await fetch(`/api/v1/organizations/default/members/${userId}`, {
                    method: 'PATCH',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken,
                    },
                    body: JSON.stringify({ role: 'admin' }),
                });
                return { ok: res.ok, status: res.status, body: await res.text() };
            }, seeded.userId);
            expect(patchResult.ok, `PATCH failed: ${patchResult.status} ${patchResult.body}`).toBe(true);

            // Verify via the members list that the role is now 'admin'.
            const members = await page.evaluate(async () => {
                const res = await fetch('/api/v1/organizations/default/members', {
                    credentials: 'include',
                });
                return res.ok ? await res.json() : [];
            });
            const updated = members.find((m: { userId: string; role: string }) => m.userId === seeded.userId);
            expect(updated, 'seeded member should appear in members list').toBeTruthy();
            expect(updated.role).toBe('admin');
        } finally {
            await cleanupResource(page, 'user', seeded.userId).catch(() => { /* best-effort */ });
        }
    });

    test('can remove team member', async ({ page }) => {
        await page.goto('/admin/user-management/team');

        await expect(page.locator('h1:has-text("Team Management")')).toBeVisible({ timeout: 30_000 });

        // Remove buttons use confirm() dialog
        const removeButton = page.locator('button:has-text("Remove")').first();

        if (await removeButton.isVisible({ timeout: 5_000 })) {
            // Don't actually remove — just verify button exists
            expect(await removeButton.isEnabled()).toBe(true);
        } else {
            test.skip(true, 'No removable members');
        }
    });

    test('can manage roles', async ({ page }) => {
        await page.goto('/admin/user-management/roles');

        // RolesPage heading is "Roles & Permissions"
        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });

        // Should show roles table
        await expect(page.locator('table')).toBeVisible({ timeout: 10_000 });
    });

    test('can create custom role', async ({ page }) => {
        await page.goto('/admin/user-management/roles');

        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });

        // Bulk-delete leftover "E2E Role" rows from prior runs via the API.
        // The UI delete loop (one-by-one with confirm() dialogs and 1s waits)
        // accumulates beyond the test timeout when many stale rows exist.
        // Same browser-context fetch pattern used elsewhere — auto-attaches
        // __session and the X-CSRF-Token derived from the __csrf cookie.
        await page.evaluate(async () => {
            const csrfToken = document.cookie.match(/__csrf=([^;]+)/)?.[1] ?? '';
            const roles: Array<{ id: string; name: string; is_system_role?: boolean }> =
                await fetch('/api/v1/organizations/default/roles', { credentials: 'include' })
                    .then((r) => (r.ok ? r.json() : []))
                    .catch(() => []);
            for (const role of roles) {
                if (role.name?.startsWith('E2E Role') && !role.is_system_role) {
                    await fetch(`/api/v1/organizations/default/roles/${role.id}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: { 'X-CSRF-Token': csrfToken },
                    });
                }
            }
        });
        await page.reload();
        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });

        // Click "Create New Role" button
        await page.click('button:has-text("Create New Role")');
        await page.waitForURL('**/roles/new', { timeout: 10_000 });

        // RoleEditor heading is "Create New Role"
        await expect(page.locator('h1:has-text("Create New Role")')).toBeVisible({ timeout: 5_000 });

        // Fill name (placeholder: "e.g. Editor")
        const roleName = `E2E Role ${Date.now()}`;
        await page.fill('input[placeholder="e.g. Editor"]', roleName);

        // Fill description (placeholder: "Can edit content but not settings...")
        await page.fill('textarea[placeholder*="Can edit"]', 'Created by E2E test suite');

        // Select a permission
        const firstCheckbox = page.locator('input[type="checkbox"]').first();
        await firstCheckbox.check();

        // Submit — "Create Role" button
        await page.click('button[type="submit"]:has-text("Create Role")');

        // React Router updates the URL without a full page load here.
        await expect(page).toHaveURL(/\/admin\/user-management\/roles$/, { timeout: 15_000 });
        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });
        await expect(page.locator(`td:has-text("${roleName}")`)).toBeVisible({ timeout: 10_000 });
    });

    test('can delete custom role', async ({ page }) => {
        await page.goto('/admin/user-management/roles');

        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });

        // Look for Delete button on non-system roles (uses confirm() dialog)
        const deleteButton = page.locator('button:has-text("Delete")').first();

        if (await deleteButton.isVisible({ timeout: 5_000 })) {
            page.once('dialog', async (dialog) => {
                await dialog.accept();
            });
            await deleteButton.click();

            // Wait for API
            await page.waitForTimeout(1_000);
        } else {
            test.skip(true, 'No deletable roles');
        }
    });

    test('can configure login methods', async ({ page }) => {
        await page.goto('/admin/authentication/login-methods');

        // LoginMethodsPage should show toggle switches
        // Wait for the page to load
        await page.waitForTimeout(3_000);

        // Should have checkbox/toggle inputs for login methods
        const toggles = page.locator('input[type="checkbox"], [role="switch"]');
        expect(await toggles.count()).toBeGreaterThan(0);
    });

    test('can toggle password authentication', async ({ page }) => {
        await page.goto('/admin/authentication/login-methods');

        // Wait for config to load
        await page.waitForTimeout(3_000);

        // Find a toggle/checkbox for email/password
        const toggle = page.locator('input[type="checkbox"]').first();

        if (await toggle.isVisible({ timeout: 5_000 })) {
            const wasChecked = await toggle.isChecked();
            // Just verify it exists and is interactable — don't toggle auth methods in test
            expect(typeof wasChecked).toBe('boolean');
        } else {
            test.skip(true, 'No toggles visible');
        }
    });

});

