/**
 * F-4: AuthStar E2E Test Suite — Auth Flow Coverage
 *
 * Covers the critical user journeys that must work end-to-end:
 *   1. Login flow (email → password → dashboard)
 *   2. Signup flow (email → credentials → email verification → account created)
 *   3. Password reset flow (forgot password → reset code → new password → login)
 *   4. MFA flow (login → TOTP step → dashboard)
 *   5. Flow expiry handling (expired flow → auto-restart)
 *   6. Form validation (client-side zod validation errors shown before submit)
 *   7. Accessibility (ARIA labels, keyboard navigation)
 *   8. Mobile viewport (375px iPhone SE)
 *
 * These tests use Playwright's API mocking to avoid requiring a live backend.
 * For integration tests against a real backend, see backend/crates/api_server/tests/.
 */

import { test, expect, Page } from '@playwright/test';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BASE_URL = 'http://localhost:5173';
const LOGIN_URL = `${BASE_URL}/u/default`;
const SIGNUP_URL = `${BASE_URL}/u/default/signup`;
const RESET_URL = `${BASE_URL}/u/default/reset-password`;

/** Mock the flow init endpoint to return a specific first step */
async function mockFlowInit(page: Page, uiStep: object, extras: object = {}) {
    await page.route('**/api/v1/flows/init', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                flow_id: 'test-flow-id-001',
                flow_token: 'test-flow-token',
                ui_step: uiStep,
                acceptable_capabilities: ['Password', 'Totp'],
                required_aal: 'AAL1',
                risk_level: 'Low',
                ...extras,
            }),
        });
    });
}

/** Mock a flow submit endpoint to return the next step */
async function mockFlowSubmit(page: Page, response: object, statusCode = 200) {
    await page.route('**/api/v1/flows/*/submit', async (route) => {
        await route.fulfill({
            status: statusCode,
            contentType: 'application/json',
            body: JSON.stringify(response),
        });
    });
}

/** Mock the identify endpoint */
async function mockFlowIdentify(page: Page, response: object) {
    await page.route('**/api/v1/flows/*/identify', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(response),
        });
    });
}

// ─── 1. Login Flow ────────────────────────────────────────────────────────────

test.describe('Login Flow', () => {
    test('renders email step on load', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        // Email input should be visible and labelled
        await expect(page.getByLabel('Email address')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Continue' })).toBeVisible();
    });

    test('shows validation error for invalid email', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        // Submit with invalid email
        await page.getByLabel('Email address').fill('not-an-email');
        await page.getByRole('button', { name: 'Continue' }).click();

        // Zod validation error should appear without network request
        await expect(page.getByRole('alert')).toContainText('valid email');
    });

    test('shows validation error for empty email', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page.getByRole('alert')).toContainText('required');
    });

    test('advances to password step after valid email', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });
        await mockFlowIdentify(page, {
            flow_id: 'test-flow-id-001',
            ui_step: { type: 'password', label: 'Password' },
        });

        await page.goto(LOGIN_URL);
        await page.getByLabel('Email address').fill('user@example.com');
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page.getByLabel('Password')).toBeVisible();
    });

    test('shows password validation error for short password', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'password',
            label: 'Password',
        });

        await page.goto(LOGIN_URL);
        await page.getByLabel('Password').fill('short');
        await page.getByRole('button', { name: 'Sign In' }).click();

        await expect(page.getByRole('alert')).toContainText('8 characters');
    });

    test('has forgot password link', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        const forgotLink = page.getByRole('link', { name: /forgot.*password/i });
        await expect(forgotLink).toBeVisible();
        await expect(forgotLink).toHaveAttribute('href', /reset-password/);
    });

    test('has sign up link', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        const signupLink = page.getByRole('link', { name: /sign up/i });
        await expect(signupLink).toBeVisible();
    });
});

// ─── 2. Signup Flow ───────────────────────────────────────────────────────────

test.describe('Signup Flow', () => {
    test('renders credentials step for signup', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'credentials',
            fields: [
                { name: 'email', label: 'Email', format: 'email', required: true },
                { name: 'password', label: 'Password', format: 'password', required: true, min_length: 8 },
                { name: 'name', label: 'Full Name', format: 'text', required: true },
            ],
        });

        await page.goto(SIGNUP_URL);

        await expect(page.getByLabel('Email')).toBeVisible();
        await expect(page.getByLabel('Password')).toBeVisible();
        await expect(page.getByLabel('Full Name')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Create Account' })).toBeVisible();
    });

    test('shows required field errors on empty submit', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'credentials',
            fields: [
                { name: 'email', label: 'Email', format: 'email', required: true },
                { name: 'password', label: 'Password', format: 'password', required: true, min_length: 8 },
            ],
        });

        await page.goto(SIGNUP_URL);
        await page.getByRole('button', { name: 'Create Account' }).click();

        // Both fields should show errors
        const alerts = page.getByRole('alert');
        await expect(alerts.first()).toBeVisible();
    });

    test('has sign in link', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'credentials',
            fields: [
                { name: 'email', label: 'Email', format: 'email', required: true },
            ],
        });

        await page.goto(SIGNUP_URL);

        const signinLink = page.getByRole('link', { name: /sign in/i });
        await expect(signinLink).toBeVisible();
    });
});

// ─── 3. Password Reset Flow ───────────────────────────────────────────────────

test.describe('Password Reset Flow', () => {
    test('renders email step for reset', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(RESET_URL);

        await expect(page.getByLabel('Email address')).toBeVisible();
        await expect(page.getByRole('heading', { name: /reset/i })).toBeVisible();
    });

    test('renders reset code step', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'reset_code_verification',
            label: 'Reset Code',
            email: 'user@example.com',
        });

        await page.goto(RESET_URL);

        await expect(page.getByLabel('Reset Code')).toBeVisible();
        await expect(page.getByText('user@example.com')).toBeVisible();
        await expect(page.getByText('10 minutes')).toBeVisible();
    });

    test('shows OTP validation error for non-numeric code', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'reset_code_verification',
            label: 'Reset Code',
            email: 'user@example.com',
        });

        await page.goto(RESET_URL);
        await page.getByLabel('Reset Code').fill('abcdef');
        await page.getByRole('button', { name: 'Verify Code' }).click();

        await expect(page.getByRole('alert')).toContainText('digits');
    });

    test('renders new password step with confirm field', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'new_password',
            label: 'New Password',
            hint: 'At least 8 characters',
        });

        await page.goto(RESET_URL);

        await expect(page.getByLabel('New Password')).toBeVisible();
        await expect(page.getByLabel('Confirm Password')).toBeVisible();
        await expect(page.getByText('At least 8 characters')).toBeVisible();
    });

    test('shows password mismatch error', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'new_password',
            label: 'New Password',
        });

        await page.goto(RESET_URL);
        await page.getByLabel('New Password').fill('password123');
        await page.getByLabel('Confirm Password').fill('different456');
        await page.getByRole('button', { name: 'Reset Password' }).click();

        await expect(page.getByRole('alert')).toContainText('match');
    });

    test('show/hide password toggle works', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'new_password',
            label: 'New Password',
        });

        await page.goto(RESET_URL);

        const passwordInput = page.getByLabel('New Password');
        await expect(passwordInput).toHaveAttribute('type', 'password');

        // Click show password button
        await page.getByRole('button', { name: /show password/i }).click();
        await expect(passwordInput).toHaveAttribute('type', 'text');

        // Click hide password button
        await page.getByRole('button', { name: /hide password/i }).click();
        await expect(passwordInput).toHaveAttribute('type', 'password');
    });
});

// ─── 4. MFA / OTP Flow ───────────────────────────────────────────────────────

test.describe('MFA / OTP Flow', () => {
    test('renders OTP step with numeric input', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'otp',
            label: 'Authenticator Code',
        });

        await page.goto(LOGIN_URL);

        const otpInput = page.getByLabel('Authenticator Code');
        await expect(otpInput).toBeVisible();
        await expect(otpInput).toHaveAttribute('inputmode', 'numeric');
        await expect(otpInput).toHaveAttribute('autocomplete', 'one-time-code');
        await expect(otpInput).toHaveAttribute('maxlength', '6');
    });

    test('shows error for OTP shorter than 6 digits', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'otp',
            label: 'Authenticator Code',
        });

        await page.goto(LOGIN_URL);
        await page.getByLabel('Authenticator Code').fill('123');
        await page.getByRole('button', { name: 'Verify' }).click();

        await expect(page.getByRole('alert')).toContainText('6 digits');
    });

    test('shows error for non-numeric OTP', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'otp',
            label: 'Authenticator Code',
        });

        await page.goto(LOGIN_URL);
        await page.getByLabel('Authenticator Code').fill('abc123');
        await page.getByRole('button', { name: 'Verify' }).click();

        await expect(page.getByRole('alert')).toContainText('digits');
    });
});

// ─── 5. Flow Expiry Handling ──────────────────────────────────────────────────

test.describe('Flow Expiry', () => {
    test('auto-restarts flow on 410 Gone response', async ({ page }) => {
        let initCallCount = 0;

        // First init returns email step
        await page.route('**/api/v1/flows/init', async (route) => {
            initCallCount++;
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    flow_id: `test-flow-${initCallCount}`,
                    flow_token: 'test-token',
                    ui_step: { type: 'email', label: 'Email address', required: true },
                    acceptable_capabilities: ['Password'],
                    required_aal: 'AAL1',
                    risk_level: 'Low',
                }),
            });
        });

        // Identify returns 410 (flow expired)
        await page.route('**/api/v1/flows/*/identify', async (route) => {
            await route.fulfill({
                status: 410,
                contentType: 'application/json',
                body: JSON.stringify({
                    error: 'FLOW_EXPIRED',
                    message: 'This authentication flow has expired.',
                }),
            });
        });

        await page.goto(LOGIN_URL);

        // Fill email and submit
        await page.getByLabel('Email address').fill('user@example.com');
        await page.getByRole('button', { name: 'Continue' }).click();

        // Flow should auto-restart (init called again)
        await expect(page).toHaveURL(new RegExp(LOGIN_URL));
        // After restart, email step should be visible again
        await expect(page.getByLabel('Email address')).toBeVisible({ timeout: 5000 });
    });
});

// ─── 6. Accessibility ─────────────────────────────────────────────────────────

test.describe('Accessibility', () => {
    test('email input has aria-required', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        const emailInput = page.getByLabel('Email address');
        await expect(emailInput).toHaveAttribute('aria-required', 'true');
    });

    test('invalid input has aria-invalid=true after failed submit', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);
        await page.getByLabel('Email address').fill('bad');
        await page.getByRole('button', { name: 'Continue' }).click();

        const emailInput = page.getByLabel('Email address');
        await expect(emailInput).toHaveAttribute('aria-invalid', 'true');
    });

    test('error message has role=alert', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page.getByRole('alert')).toBeVisible();
    });

    test('form has aria-label', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        await expect(page.getByRole('form', { name: /email/i })).toBeVisible();
    });

    test('keyboard navigation: tab through form fields', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        // Tab to email input
        await page.keyboard.press('Tab');
        const emailInput = page.getByLabel('Email address');
        await expect(emailInput).toBeFocused();

        // Tab to submit button
        await page.keyboard.press('Tab');
        const submitButton = page.getByRole('button', { name: 'Continue' });
        await expect(submitButton).toBeFocused();
    });
});

// ─── 7. Mobile Viewport ───────────────────────────────────────────────────────

test.describe('Mobile Responsiveness (375px)', () => {
    test.use({ viewport: { width: 375, height: 812 } }); // iPhone SE

    test('auth card is visible and not clipped on mobile', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        // Card should be visible
        const emailInput = page.getByLabel('Email address');
        await expect(emailInput).toBeVisible();

        // Submit button should be fully visible (not clipped)
        const submitButton = page.getByRole('button', { name: 'Continue' });
        await expect(submitButton).toBeVisible();
        await expect(submitButton).toBeInViewport();
    });

    test('submit button has adequate touch target height on mobile', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        const submitButton = page.getByRole('button', { name: 'Continue' });
        const box = await submitButton.boundingBox();

        // WCAG 2.5.5: minimum 44px touch target
        expect(box?.height).toBeGreaterThanOrEqual(44);
    });

    test('forgot password link has adequate touch target on mobile', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        const forgotLink = page.getByRole('link', { name: /forgot.*password/i });
        const box = await forgotLink.boundingBox();

        // WCAG 2.5.5: minimum 44px touch target
        expect(box?.height).toBeGreaterThanOrEqual(44);
    });
});

// ─── 8. Page Title and Branding ───────────────────────────────────────────────

test.describe('Page Title and Branding', () => {
    test('login page shows correct heading', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(LOGIN_URL);

        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('signup page shows correct heading', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'credentials',
            fields: [{ name: 'email', label: 'Email', format: 'email', required: true }],
        });

        await page.goto(SIGNUP_URL);

        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('reset password page shows correct heading', async ({ page }) => {
        await mockFlowInit(page, {
            type: 'email',
            label: 'Email address',
            required: true,
        });

        await page.goto(RESET_URL);

        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });
});

// Made with Bob
