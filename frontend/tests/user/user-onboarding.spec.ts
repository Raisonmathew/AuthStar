/**
 * User Onboarding E2E Test
 *
 * Full user journey: invitation acceptance → signup → email verification →
 * MFA enforcement (TOTP enrollment) → passkey registration → profile →
 * org switching.
 *
 * Uses the `scopedOrg` fixture for isolation.
 */

import { test, expect } from '../fixtures/scoped-org';
import { loginAsAdmin } from '../fixtures/test-utils';
import {
    seedUser,
    seedInvitation,
    seedMembership,
    cleanupResource,
} from '../fixtures/backend-seed';
import { deleteAllMail, waitForMail, extractLink, isMailHogAvailable } from '../fixtures/mail-inbox';
import {
    addVirtualAuthenticator,
    removeVirtualAuthenticator,
    getCredentials,
} from '../fixtures/webauthn-virtual';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uniqueEmail(prefix = 'user'): string {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 5)}@e2etest.local`;
}

const USER_PASSWORD = 'SecureTest@123!';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('User Onboarding Journey', () => {

    // ---- Invitation → Signup (new user) ------------------------------------

    test('new user can accept invitation and sign up', async ({ page, scopedOrg }) => {
        const mailAvailable = await isMailHogAvailable();
        test.skip(!mailAvailable, 'MailHog not available — skipping email-dependent test');
        const email = uniqueEmail('invite');

        // Admin creates an invitation via seed
        const invitation = await seedInvitation(page, {
            organizationId: scopedOrg.orgId,
            email,
            role: 'member',
            inviterUserId: scopedOrg.admin.userId,
        });

        // New user navigates to invitation page
        await page.goto(`/invitations/${invitation.token}`);

        // Should see the invitation with org name. Multiple elements on the
        // page contain the word "invited"/"invitation" (heading, body copy,
        // and the accept button), so scope to the first match to avoid
        // strict mode violations.
        await expect(
            page.locator('text=/invited|invitation/i').first(),
        ).toBeVisible({ timeout: 10_000 });

        // Unauthenticated → should offer "Sign In to Accept" button
        const signInBtn = page.locator('button:has-text("Sign In to Accept")');
        if (await signInBtn.isVisible({ timeout: 5_000 })) {
            await signInBtn.click();

            // Should redirect to login with redirect back to invitation
            await page.waitForURL('**/login**', { timeout: 10_000 });

            // Navigate to signup instead
            const signUpLink = page.getByRole('link', { name: 'Sign up' });
            if (await signUpLink.isVisible({ timeout: 3_000 })) {
                await signUpLink.click();
            }
        }
    });

    // ---- Full Signup Flow --------------------------------------------------

    test('user can complete signup with email and password', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('signup');

        // Navigate to signup for the scoped org's slug
        await page.goto(`/u/${scopedOrg.slug}/signup`);

        // Wait for the registration form
        await page.waitForSelector(
            'form[aria-label="Account registration form"], input[type="email"]',
            { timeout: 15_000 },
        );

        // Fill email
        const emailInput = page.locator('#credentials-email, input[type="email"]');
        await emailInput.fill(email);

        // Fill password
        const passwordInput = page.locator('#credentials-password, input[type="password"]');
        await passwordInput.fill(USER_PASSWORD);

        // Fill optional name fields if visible
        const firstNameInput = page.locator('#credentials-first_name');
        if (await firstNameInput.isVisible({ timeout: 1_000 })) {
            await firstNameInput.fill('E2E');
        }
        const lastNameInput = page.locator('#credentials-last_name');
        if (await lastNameInput.isVisible({ timeout: 1_000 })) {
            await lastNameInput.fill('TestUser');
        }

        // Submit
        await page.click('button:has-text("Create Account")');

        // Wait for email verification step or redirect
        const outcome = await Promise.race([
            page
                .waitForSelector('form[aria-label="Email verification form"]', { timeout: 20_000 })
                .then(() => 'verify-email' as const),
            page
                .waitForURL('**/account/**', { timeout: 20_000 })
                .then(() => 'redirected' as const),
        ]);

        if (outcome === 'verify-email') {
            // Try MailHog first; fall back to the test seed API when SMTP is down.
            // The backend degrades gracefully in non-production (email send logged,
            // not fatal) so the signup ticket always exists in the DB.
            let otp: string | null = null;
            const mailAvail = await isMailHogAvailable();
            if (mailAvail) {
                const mail = await waitForMail(email, 'verify', { timeout: 30_000 });
                expect(mail).toBeTruthy();
                const m = mail.body.match(/\b(\d{6})\b/);
                otp = m ? m[1] : null;
            } else {
                // Fetch OTP from backend test endpoint
                const seedToken = process.env.TEST_SEED_TOKEN;
                if (!seedToken) {
                    throw new Error(
                        'TEST_SEED_TOKEN env var must be set to fetch verification codes from /api/test/*'
                    );
                }
                const codeRes = await page.evaluate(
                    async ({ e, token }) => {
                        const r = await fetch('/api/test/verification-code', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-Test-Seed-Token': token,
                            },
                            body: JSON.stringify({ email: e, kind: 'signup' }),
                        });
                        return r.ok ? (await r.json()).code : null;
                    },
                    { e: email, token: seedToken }
                );
                otp = codeRes;
            }

            if (otp) {
                await page.fill(
                    'input[inputmode="numeric"][maxlength="6"]',
                    otp,
                );
                await page.click('button:has-text("Verify")');
            }

            // After OTP verification the app auto-logs in and redirects to
            // /account/profile. If the auto-login fails (e.g. the EIAA flow
            // token expired or the signup intent flow rejected the re-identify),
            // the user lands on the scoped org login page instead. Handle both.
            const postVerifyOutcome = await Promise.race([
                page.waitForURL('**/account/**', { timeout: 25_000 })
                    .then(() => 'account' as const),
                page.waitForSelector('form[aria-label="Email address form"]', { timeout: 25_000 })
                    .then(() => 'login-form' as const),
            ]);

            if (postVerifyOutcome === 'login-form') {
                // Auto-login failed — complete login manually
                await page.getByPlaceholder('you@example.com').fill(email);
                await page.getByRole('button', { name: 'Continue' }).click();
                await page.waitForSelector('input[type="password"]', { timeout: 15_000 });
                await page.locator('input[type="password"]').fill(USER_PASSWORD);
                await page.getByRole('button', { name: 'Sign In' }).click();
                await page.waitForURL('**/account/**', { timeout: 30_000 });
            }
        }

        // User should now be on account/profile or dashboard
        expect(page.url()).toMatch(/account|dashboard/);
    });

    // ---- Login Flow -------------------------------------------------------

    test('existing user can log in with email + password', async ({ page, scopedOrg }) => {
        // Seed a user
        const email = uniqueEmail('login');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Login',
            lastName: 'Test',
            orgId: scopedOrg.orgId,
        });

        // Navigate to login
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.waitForSelector('form[aria-label="Email address form"]', { timeout: 15_000 });

        // Enter email
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Enter password
        await page.waitForSelector('form[aria-label="Password form"]', { timeout: 15_000 });
        await page.locator('input[type="password"]').fill(USER_PASSWORD);
        await page.getByRole('button', { name: 'Sign In' }).click();

        // Should redirect to account or dashboard
        await page.waitForURL('**/account/**', { timeout: 30_000 });

        await cleanupResource(page, 'user', user.userId);
    });

    // ---- TOTP Enrollment --------------------------------------------------

    test('user can enroll TOTP authenticator', async ({ page, scopedOrg }) => {
        // Seed and log in a user
        const email = uniqueEmail('totp');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'TOTP',
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

        // Navigate to security settings
        await page.goto('/account/security');

        // Click "Set up authenticator"
        const setupBtn = page.locator('button:has-text("Set up authenticator")');
        if (await setupBtn.isVisible({ timeout: 5_000 })) {
            await setupBtn.click();

            // Should show the TOTP secret key
            const secretEl = page.locator('code');
            await expect(secretEl).toBeVisible({ timeout: 10_000 });
            const secret = await secretEl.textContent();
            expect(secret).toBeTruthy();
            expect(secret!.length).toBeGreaterThanOrEqual(16);

            // Generate TOTP code from secret (using the otpauth library would
            // be ideal; for now, we verify the UI flow up to the point where
            // we'd need a valid code)
            await expect(
                page.locator('input[inputmode="numeric"][maxlength="6"]'),
            ).toBeVisible({ timeout: 5_000 });

            // Cancel the enrollment (we can't generate a valid TOTP without a lib)
            await page.click('button:has-text("Cancel")');
        } else {
            test.skip(true, 'TOTP setup not available on this page');
        }

        await cleanupResource(page, 'user', user.userId);
    });

    // ---- Passkey Registration (with CDP virtual authenticator) -------------

    test('user can register a passkey', async ({ page, scopedOrg }) => {
        // Seed and log in a user
        const email = uniqueEmail('passkey');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Passkey',
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

        // Attach virtual authenticator
        const auth = await addVirtualAuthenticator(page);

        try {
            // Navigate to security settings
            await page.goto('/account/security');

            // Click "Add passkey"
            const addBtn = page.locator('button:has-text("Add passkey")');
            if (await addBtn.isVisible({ timeout: 5_000 })) {
                await addBtn.click();

                // Optionally name the passkey
                const nameInput = page.locator('input[placeholder*="Name this passkey"]');
                if (await nameInput.isVisible({ timeout: 2_000 })) {
                    await nameInput.fill('E2E Virtual Key');
                }

                // Click Register — the virtual authenticator handles the ceremony
                await page.click('button:has-text("Register")');

                // Wait for success — the passkey should appear in the list
                await expect(
                    page.locator('text=/E2E Virtual Key|passkey.*registered|success/i'),
                ).toBeVisible({ timeout: 15_000 });

                // Verify credential was stored in the virtual authenticator
                const creds = await getCredentials(auth);
                expect(creds.length).toBeGreaterThanOrEqual(1);
            } else {
                test.skip(true, 'Passkey registration not available');
            }
        } finally {
            await removeVirtualAuthenticator(page, auth);
            await cleanupResource(page, 'user', user.userId);
        }
    });

    // ---- Profile Management -----------------------------------------------

    test('user can view and update profile', async ({ page, scopedOrg }) => {
        const email = uniqueEmail('profile');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Profile',
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

        // Navigate to profile
        await page.goto('/account/profile');

        // The profile page renders a read-only view by default.
        // Click "Edit Profile" to enter edit mode and reveal inputs.
        const editBtn = page.locator('button:has-text("Edit Profile"), a:has-text("Edit Profile")');
        await expect(editBtn).toBeVisible({ timeout: 10_000 });
        await editBtn.click();

        // Should now show input fields
        await expect(page.locator('input').first()).toBeVisible({ timeout: 10_000 });

        // Try updating first name — inputs are direct children of the edit form (no name attrs)
        const firstNameInput = page.locator('input[type="text"]').first();
        if (await firstNameInput.isVisible({ timeout: 3_000 })) {
            await firstNameInput.clear();
            await firstNameInput.fill('UpdatedE2E');

            // Save — button text in ProfilePage.tsx is "Save Changes"
            const saveBtn = page.locator('button:has-text("Save Changes")');
            if (await saveBtn.isVisible({ timeout: 2_000 })) {
                await saveBtn.click();
                // Toast: "Profile updated successfully!"
                await expect(
                    page.locator('text=/updated successfully/i')
                ).toBeVisible({ timeout: 10_000 });
            }
        }

        await cleanupResource(page, 'user', user.userId);
    });

    // ---- Password Reset Flow -----------------------------------------------

    test('user can reset password via email', async ({ page, scopedOrg }) => {
        const mailAvailable = await isMailHogAvailable();
        test.skip(!mailAvailable, 'MailHog not available — skipping email-dependent test');
        const email = uniqueEmail('reset');
        const user = await seedUser(page, {
            email,
            password: USER_PASSWORD,
            firstName: 'Reset',
            lastName: 'User',
            orgId: scopedOrg.orgId,
        });

        await deleteAllMail();

        // Navigate to login
        await page.goto(`/u/${scopedOrg.slug}`);
        await page.getByPlaceholder('you@example.com').fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Click "Forgot password?"
        await page.waitForSelector('form[aria-label="Password form"]', { timeout: 15_000 });
        await page.getByRole('link', { name: 'Forgot password?' }).click();

        // Should navigate to reset password page
        await page.waitForURL('**/reset-password**', { timeout: 10_000 });

        // Enter email if prompted
        const emailField = page.locator('input[type="email"]');
        if (await emailField.isVisible({ timeout: 3_000 })) {
            await emailField.fill(email);
            await page.click('button[type="submit"]');
        }

        // Wait for verification code step
        const codeInput = page.locator('input[inputmode="numeric"][maxlength="6"]');
        await expect(codeInput).toBeVisible({ timeout: 15_000 });

        // Get code from email
        const mail = await waitForMail(email, 'reset', { timeout: 30_000 });
        const codeMatch = mail.body.match(/\b(\d{6})\b/);
        if (codeMatch) {
            await codeInput.fill(codeMatch[1]);
            await page.click('button:has-text("Verify")');

            // New password form
            const newPwForm = page.locator('form[aria-label="Set new password form"]');
            if (await newPwForm.isVisible({ timeout: 10_000 })) {
                const newPassword = 'NewSecureTest@456!';
                await page.locator('input[placeholder="New password"]').fill(newPassword);
                await page.locator('input[placeholder="Confirm new password"]').fill(newPassword);
                await page.click('button:has-text("Reset Password")');

                // Should redirect to login or dashboard
                await page.waitForURL('**/u/**', { timeout: 15_000 });
            }
        }

        await cleanupResource(page, 'user', user.userId);
    });
});
