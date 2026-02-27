import { test as base, Page } from '@playwright/test';

// Extend base test with custom fixtures
export const test = base.extend<{
    authenticatedAdminPage: Page;
    authenticatedUserPage: Page;
}>({
    // Pre-authenticated admin page
    authenticatedAdminPage: async ({ page }, use) => {
        await loginAsAdmin(page);
        await use(page);
    },

    // Pre-authenticated user page
    authenticatedUserPage: async ({ page }, use) => {
        await loginAsUser(page);
        await use(page);
    },
});

// Helper: Login as Admin
export async function loginAsAdmin(page: Page) {
    await page.goto('/u/admin');
    await page.waitForSelector('input[type="email"]');
    await page.fill('input[type="email"]', 'admin@example.com');
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]');
    await page.fill('input[type="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/admin/dashboard', { timeout: 10000 });
}

// Helper: Login as User
export async function loginAsUser(page: Page) {
    await page.goto('/u/default');
    await page.waitForSelector('input[type="email"]');
    await page.fill('input[type="email"]', 'admin@example.com');
    await page.click('button[type="submit"]');
    await page.waitForSelector('input[type="password"]');
    await page.fill('input[type="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard', { timeout: 10000 });
}

// Helper: Clear session (navigates to base URL first to ensure context exists)
export async function clearSession(page: Page) {
    await page.goto('/');
    await page.evaluate(() => {
        sessionStorage.clear();
        localStorage.clear();
    });
}

// Helper: Get session storage value
export async function getSessionStorageItem(page: Page, key: string): Promise<string | null> {
    return page.evaluate((k) => sessionStorage.getItem(k), key);
}

export { expect } from '@playwright/test';
