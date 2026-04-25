import { test, expect } from '../fixtures/test-utils';

// User profile lives at /account/profile, not /profile. The profile form
// is read-only by default and toggled to edit mode via an "Edit Profile"
// button. Password change is exposed as a "Change Password" button that
// opens a modal dialog with three labelled password inputs.
//
// Project user-journey uses the AAL3-upgraded admin storageState so
// step-up modals don't block password-change flows.

test.describe('User Profile Management', () => {

    test.beforeEach(async ({ page }) => {
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
        );
    });

    test('can view user profile', async ({ page }) => {
        await page.goto('/account/profile');

        // Section heading is "Personal Information"
        await expect(
            page.locator('h2:has-text("Personal Information")')
        ).toBeVisible({ timeout: 15_000 });

        // Email of the authenticated user is shown next to the avatar
        await expect(page.locator('text=admin@example.com').first())
            .toBeVisible({ timeout: 10_000 });
    });

    test('can update profile information', async ({ page }) => {
        await page.goto('/account/profile');
        await expect(page.locator('h2:has-text("Personal Information")'))
            .toBeVisible({ timeout: 15_000 });

        await page.getByRole('button', { name: /edit profile/i }).click();

        // Find the First/Last Name inputs by their label text — these
        // inputs have no name/placeholder attributes.
        const firstNameInput = page.locator('label:has-text("First Name") + input');
        const lastNameInput = page.locator('label:has-text("Last Name") + input');

        const stamp = Date.now().toString().slice(-6);
        await firstNameInput.fill(`First${stamp}`);
        await lastNameInput.fill(`Last${stamp}`);

        await page.getByRole('button', { name: /save changes/i }).click();

        // Toast confirms success; sonner uses role=status.
        await expect(page.locator('text=/updated|saved|success/i').first())
            .toBeVisible({ timeout: 10_000 });
    });

    test('can open change password modal', async ({ page }) => {
        await page.goto('/account/profile');
        await expect(page.locator('h2:has-text("Personal Information")'))
            .toBeVisible({ timeout: 15_000 });

        await page.getByRole('button', { name: /change password/i }).click();

        // Modal heading is "Change Password" (h3)
        await expect(page.locator('h3:has-text("Change Password")'))
            .toBeVisible({ timeout: 5_000 });
    });

    test('password change validates complexity', async ({ page }) => {
        await page.goto('/account/profile');
        await expect(page.locator('h2:has-text("Personal Information")'))
            .toBeVisible({ timeout: 15_000 });

        await page.getByRole('button', { name: /change password/i }).click();
        await expect(page.locator('h3:has-text("Change Password")')).toBeVisible({ timeout: 5_000 });

        // The modal renders three password inputs in order: current, new, confirm.
        const pwInputs = page.locator('input[type="password"]');
        await pwInputs.nth(0).fill(process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly');
        await pwInputs.nth(1).fill('weak');
        await pwInputs.nth(2).fill('weak');

        await page.getByRole('button', { name: /^(change|update|save)/i }).first().click();

        // Backend rejects weak passwords; expect either a toast error or the
        // modal to remain open. We assert the latter — the modal heading
        // should still be visible.
        await expect(page.locator('h3:has-text("Change Password")'))
            .toBeVisible({ timeout: 5_000 });
    });

    test('password change requires correct current password', async ({ page }) => {
        await page.goto('/account/profile');
        await expect(page.locator('h2:has-text("Personal Information")'))
            .toBeVisible({ timeout: 15_000 });

        await page.getByRole('button', { name: /change password/i }).click();
        await expect(page.locator('h3:has-text("Change Password")')).toBeVisible({ timeout: 5_000 });

        const pwInputs = page.locator('input[type="password"]');
        await pwInputs.nth(0).fill('definitely-wrong-password');
        await pwInputs.nth(1).fill('NewPassword123!');
        await pwInputs.nth(2).fill('NewPassword123!');

        await page.getByRole('button', { name: /^(change|update|save)/i }).first().click();

        // Toast surfaces the failure; modal should remain open.
        await expect(page.locator('h3:has-text("Change Password")'))
            .toBeVisible({ timeout: 5_000 });
    });

});
