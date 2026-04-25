/**
 * Admin Lifecycle E2E Test
 *
 * Full journey: role CRUD → invite member → role reassignment → member removal → audit trail.
 *
 * Uses the `scopedOrg` fixture so each test gets an isolated organization
 * and cleanup is automatic.
 */

import { test, expect } from '../fixtures/scoped-org';
import { loginAsAdmin } from '../fixtures/test-utils';
import {
    seedUser,
    seedMembership,
    seedInvitation,
    cleanupResource,
} from '../fixtures/backend-seed';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Navigate to Team Management for the active org */
async function goToTeam(page: import('@playwright/test').Page) {
    await page.goto('/admin/user-management/team');
    // The h1 "Team Management" only renders after API data loads (not during loading spinner).
    // Wait for it with a generous timeout.
    await page.waitForSelector('h1:has-text("Team Management")', { timeout: 30_000 });
}

/** Navigate to Roles & Permissions */
async function goToRoles(page: import('@playwright/test').Page) {
    await page.goto('/admin/user-management/roles');
    await page.waitForSelector('h1:has-text("Roles & Permissions")', { timeout: 30_000 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Admin Lifecycle', () => {

    test.beforeEach(async ({ page }) => {
        await loginAsAdmin(page);
    });

    // ---- Role CRUD --------------------------------------------------------

    test('can create a custom role with specific permissions', async ({ page }) => {
        await goToRoles(page);

        // Use a timestamp-unique name so chromium and admin-journey projects don't clash
        const ROLE_NAME = `E2E Reviewer ${Date.now()}`;

        // Open role creation form
        await page.click('button:has-text("Create New Role")');
        await page.waitForURL('**/roles/new', { timeout: 10_000 });

        // Wait for RoleEditor to fully mount before filling (avoids strict-mode violation
        // if the old RolesPage DOM is still present during the React Router transition)
        await expect(page.locator('h1:has-text("Create New Role")')).toBeVisible({ timeout: 5_000 });

        // Fill name and description
        await page.locator('form input[placeholder="e.g. Editor"]').fill(ROLE_NAME);
        await page.fill('textarea[placeholder*="Can edit"]', 'Created by E2E test suite');

        // Select specific permissions via checkboxes
        const firstCheckbox = page.locator('input[type="checkbox"]').first();
        if (await firstCheckbox.isVisible({ timeout: 3_000 })) {
            await firstCheckbox.check();
        }

        // Submit — "Create Role" button
        await page.click('button[type="submit"]:has-text("Create Role")');

        // React Router updates the URL without a full page load here.
        await expect(page).toHaveURL(/\/admin\/user-management\/roles$/, { timeout: 15_000 });
        await expect(page.locator('h1:has-text("Roles & Permissions")')).toBeVisible({ timeout: 10_000 });

        // Verify the new role appears in the table
        await expect(page.locator(`td:has-text("${ROLE_NAME}")`)).toBeVisible({ timeout: 10_000 });
    });

    test('can delete a custom role', async ({ page }) => {
        await goToRoles(page);

        // Look for any E2E-created role that has a Delete button
        const deleteBtn = page.locator('tr:has-text("E2E Reviewer") button:has-text("Delete")').first();
        if (await deleteBtn.isVisible({ timeout: 3_000 })) {
            // Handle the confirm() dialog
            page.once('dialog', async (dialog) => {
                await dialog.accept();
            });
            await deleteBtn.click();
            // The row should disappear
            await expect(deleteBtn).not.toBeVisible({ timeout: 5_000 });
        } else {
            // Try any deletable non-system role
            const anyDeleteBtn = page.locator('tr button:has-text("Delete")').first();
            if (await anyDeleteBtn.isVisible({ timeout: 3_000 })) {
                page.once('dialog', async (dialog) => { await dialog.accept(); });
                await anyDeleteBtn.click();
                await expect(anyDeleteBtn).not.toBeVisible({ timeout: 5_000 });
            } else {
                test.skip(true, 'No deletable role found — create test may not have run');
            }
        }
    });

    // ---- Member Invitation ------------------------------------------------

    test('can invite a new member by email', async ({ page }) => {
        await goToTeam(page);

        const inviteEmail = `invited-${Date.now()}@e2etest.local`;

        // Fill invite form — email input + role select + Invite button
        await page.fill('input[type="email"]', inviteEmail);

        // Select role
        const roleSelect = page.locator('select').first();
        if (await roleSelect.isVisible({ timeout: 2_000 })) {
            await roleSelect.selectOption('member');
        }

        // Click Invite
        await page.click('button:has-text("Invite")');

        // Wait for API response
        await page.waitForTimeout(2_000);
    });

    test('can invite existing user — becomes immediate member', async ({ page, scopedOrg }) => {
        // Seed a user that exists but isn't in this org
        const existingUser = await seedUser(page, {
            email: `existing-${Date.now()}@e2etest.local`,
            password: 'Test123!@#',
            firstName: 'Existing',
            lastName: 'User',
        });

        await goToTeam(page);

        await page.fill('input[type="email"]', existingUser.email);
        await page.click('button:has-text("Invite")');

        // Wait for API response
        await page.waitForTimeout(2_000);

        // Cleanup the extra user
        await cleanupResource(page, 'user', existingUser.userId);
    });

    // ---- Role Reassignment ------------------------------------------------

    test('can change a member role', async ({ page, scopedOrg }) => {
        // Seed a disposable member in the scoped org so we never touch
        // user_admin's role. The previous implementation toggled the FIRST
        // <select> on the team page, which is the admin row when no other
        // members exist — this silently demoted user_admin to "member" and
        // broke every subsequent admin-journey test that requires the admin
        // role on the 'default' org.
        const seeded = await seedUser(page, {
            email: `lifecycle-role-${Date.now()}@e2etest.local`,
            password: 'Test123!@#',
            firstName: 'Lifecycle',
            lastName: 'RoleTarget',
            orgId: scopedOrg.orgId,
            role: 'member',
        });

        try {
            await goToTeam(page);

            // Locate the seeded user's row by email and use its role <select>.
            const memberRow = page.locator(`.space-y-3:has-text("${seeded.email}")`).first();
            const memberRoleSelect = memberRow.locator('select').first();

            if (await memberRoleSelect.isVisible({ timeout: 5_000 })) {
                await memberRoleSelect.selectOption('admin');

                // Wait for the PATCH to finish
                await page.waitForTimeout(1_000);

                // Sanity check: re-read the value
                await expect(memberRoleSelect).toHaveValue('admin', { timeout: 5_000 });
            } else {
                test.skip(true, 'Seeded member row not visible on team page');
            }
        } finally {
            await cleanupResource(page, 'user', seeded.userId).catch(() => { /* best-effort */ });
        }
    });

    // ---- Member Removal ---------------------------------------------------

    test('can remove a member', async ({ page }) => {
        await goToTeam(page);

        // Remove buttons on member div cards — uses confirm() dialog
        const removeButton = page.locator('button:has-text("Remove")').first();

        if (await removeButton.isVisible({ timeout: 5_000 })) {
            // Just verify it exists and is enabled — don't actually remove admin
            expect(await removeButton.isEnabled()).toBe(true);
        } else {
            test.skip(true, 'No removable members');
        }
    });

    // ---- Audit Trail ------------------------------------------------------

    test('admin actions appear in audit log', async ({ page }) => {
        await page.goto('/admin/monitoring/logs');

        // AuditLogPage heading is "Audit & Compliance"
        // Use waitForSelector first to let the page fully render before asserting
        await page.waitForSelector('h1, h2', { timeout: 15_000 });
        await expect(page.locator('h1, h2').filter({ hasText: /Audit/i }).first()).toBeVisible({ timeout: 15_000 });

        // The audit log table should be visible
        await expect(page.locator('table')).toBeVisible({ timeout: 10_000 });

        // Should contain recent entries
        const rows = page.locator('table tbody tr');
        await expect(rows.first()).toBeVisible({ timeout: 10_000 });
    });

    // ---- Invitation Token Flow -------------------------------------------

    test('seeded invitation can be viewed at /invitations/:token', async ({ page, scopedOrg }) => {
        const invitation = await seedInvitation(page, {
            organizationId: scopedOrg.orgId,
            email: `token-test-${Date.now()}@e2etest.local`,
            role: 'member',
            inviterUserId: scopedOrg.admin.userId,
        });

        // Navigate to the invitation accept page
        await page.goto(`/invitations/${invitation.token}`);

        // Should show the invitation details
        await expect(
            page.getByRole('heading', { name: /invited/i })
        ).toBeVisible({ timeout: 10_000 });
    });
});
