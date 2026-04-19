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

// Helper: Login as Admin
export async function loginAsAdmin(page: Page) {
    await page.goto('/u/admin');
    await page.waitForSelector('input[type="email"]', { timeout: 30000 });
    await page.fill('input[type="email"]', 'admin@example.com');
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]', { timeout: 60000 });
    await page.fill('input[type="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/admin/dashboard', { timeout: 30000 });
}

// Helper: Login as User
export async function loginAsUser(page: Page) {
    await page.goto('/u/default');
    await page.waitForSelector('input[type="email"]', { timeout: 30000 });
    await page.fill('input[type="email"]', 'admin@example.com');
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]', { timeout: 60000 });
    await page.fill('input[type="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard', { timeout: 30000 });
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
