import { test as base, Page } from '@playwright/test';

// Extend base test with custom fixtures and automatic cleanup
export const test = base.extend<{
    authenticatedAdminPage: Page;
    authenticatedUserPage: Page;
}>({
    // Pre-authenticated admin page with automatic cleanup
    authenticatedAdminPage: async ({ page }, use) => {
        await loginAsAdmin(page);
        await use(page);
        // Cleanup after test
        await clearSession(page);
    },

    // Pre-authenticated user page with automatic cleanup
    authenticatedUserPage: async ({ page }, use) => {
        await loginAsUser(page);
        await use(page);
        // Cleanup after test
        await clearSession(page);
    },
});

// Credentials — must match IDAAS_BOOTSTRAP_PASSWORD in backend/.env
const ADMIN_EMAIL = 'admin@example.com';
const ADMIN_PASSWORD = process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly';

/**
 * Login as Admin.
 *
 * If the page context was seeded with a valid storageState (refresh cookie)
 * the app will auto-authenticate and redirect to /admin/dashboard without
 * showing the login form.  This function handles both paths:
 *   1. Already authenticated  → navigate to /u/admin → instant redirect
 *   2. Not authenticated      → fill email + password → redirect
 */
export async function loginAsAdmin(page: Page) {
    await page.goto('/u/admin');

    // Race: dashboard redirect (already authed) vs email form (needs login)
    const outcome = await Promise.race([
        page.waitForURL('**/admin/dashboard', { timeout: 10_000 })
            .then(() => 'authenticated' as const),
        page.waitForSelector('input[type="email"]', { timeout: 10_000 })
            .then(() => 'needs-login' as const),
    ]);

    if (outcome === 'authenticated') {
        return;
    }

    await page.fill('input[type="email"]', ADMIN_EMAIL);
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]', { timeout: 20_000 });
    await page.fill('input[type="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('**/admin/dashboard', { timeout: 30_000 });
}

// Helper: Login as User
export async function loginAsUser(page: Page) {
    await page.goto('/u/default');
    await page.waitForSelector('input[type="email"]', { timeout: 30_000 });
    await page.fill('input[type="email"]', 'admin@example.com');
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]', { timeout: 20_000 });
    await page.fill('input[type="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('**/dashboard', { timeout: 30_000 });
}

// Helper: Clear session (navigates to base URL first to ensure context exists)
export async function clearSession(page: Page) {
    await page.goto('/');
    await page.evaluate(() => {
        sessionStorage.clear();
        localStorage.clear();
    });
    
    // Clear cookies
    await page.context().clearCookies();
}

// Helper: Get session storage value
export async function getSessionStorageItem(page: Page, key: string): Promise<string | null> {
    return page.evaluate((k) => sessionStorage.getItem(k), key);
}

// Helper: Get local storage value
export async function getLocalStorageItem(page: Page, key: string): Promise<string | null> {
    return page.evaluate((k) => localStorage.getItem(k), key);
}

// Helper: Set session storage value
export async function setSessionStorageItem(page: Page, key: string, value: string): Promise<void> {
    await page.evaluate(({ k, v }) => sessionStorage.setItem(k, v), { k: key, v: value });
}

// Helper: Wait for API response
export async function waitForApiResponse(page: Page, urlPattern: string, timeout: number = 10000) {
    return await page.waitForResponse(
        (response) => response.url().includes(urlPattern),
        { timeout }
    );
}

// Helper: Cleanup test data created during test
export async function cleanupTestData(page: Page, dataType: 'api-keys' | 'policies' | 'members') {
    // This would call cleanup utilities or delete test data via UI
    console.log(`Cleaning up test data: ${dataType}`);
}

export { expect } from '@playwright/test';
