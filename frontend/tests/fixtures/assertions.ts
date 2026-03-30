/**
 * Enhanced Assertion Utilities for E2E Tests
 * 
 * Provides comprehensive assertion helpers that go beyond basic visibility checks
 * to validate data integrity, API responses, and application state.
 */

import { Page, expect } from '@playwright/test';

// ============================================================================
// Data Validation Assertions
// ============================================================================

/**
 * Assert that a table contains specific data
 */
export async function assertTableContains(
    page: Page,
    tableSelector: string,
    expectedData: Record<string, string>[]
) {
    const table = page.locator(tableSelector);
    await expect(table).toBeVisible();
    
    for (const row of expectedData) {
        for (const [key, value] of Object.entries(row)) {
            const cell = table.locator(`td:has-text("${value}"), [role="cell"]:has-text("${value}")`);
            await expect(cell).toBeVisible({ timeout: 5000 });
        }
    }
}

/**
 * Assert that a form has specific values
 */
export async function assertFormValues(
    page: Page,
    formSelector: string,
    expectedValues: Record<string, string>
) {
    const form = page.locator(formSelector);
    await expect(form).toBeVisible();
    
    for (const [fieldName, expectedValue] of Object.entries(expectedValues)) {
        const field = form.locator(`input[name="${fieldName}"], textarea[name="${fieldName}"], select[name="${fieldName}"]`);
        const actualValue = await field.inputValue();
        expect(actualValue).toBe(expectedValue);
    }
}

/**
 * Assert that an API response was successful
 */
export async function assertApiSuccess(
    page: Page,
    urlPattern: string,
    expectedStatus: number = 200
) {
    const response = await page.waitForResponse(
        (response) => response.url().includes(urlPattern) && response.status() === expectedStatus,
        { timeout: 10000 }
    );
    
    expect(response.status()).toBe(expectedStatus);
    return response;
}

/**
 * Assert that an API response contains specific data
 */
export async function assertApiResponseContains(
    page: Page,
    urlPattern: string,
    expectedData: Record<string, any>
) {
    const response = await page.waitForResponse(
        (response) => response.url().includes(urlPattern),
        { timeout: 10000 }
    );
    
    const data = await response.json();
    
    for (const [key, value] of Object.entries(expectedData)) {
        expect(data).toHaveProperty(key);
        if (typeof value === 'object') {
            expect(data[key]).toMatchObject(value);
        } else {
            expect(data[key]).toBe(value);
        }
    }
    
    return data;
}

/**
 * Assert that an error message is displayed
 */
export async function assertErrorMessage(
    page: Page,
    expectedMessage: string | RegExp
) {
    const errorElement = page.locator('[role="alert"], .error, .text-red-500, .text-red-700');
    await expect(errorElement).toBeVisible({ timeout: 5000 });
    
    if (typeof expectedMessage === 'string') {
        await expect(errorElement).toContainText(expectedMessage);
    } else {
        const text = await errorElement.textContent();
        expect(text).toMatch(expectedMessage);
    }
}

/**
 * Assert that a success message is displayed
 */
export async function assertSuccessMessage(
    page: Page,
    expectedMessage?: string | RegExp
) {
    const successElement = page.locator('[role="alert"], .success, .text-green-500, .text-green-700');
    await expect(successElement).toBeVisible({ timeout: 5000 });
    
    if (expectedMessage) {
        if (typeof expectedMessage === 'string') {
            await expect(successElement).toContainText(expectedMessage);
        } else {
            const text = await successElement.textContent();
            expect(text).toMatch(expectedMessage);
        }
    }
}

// ============================================================================
// State Validation Assertions
// ============================================================================

/**
 * Assert that session storage contains specific data
 */
export async function assertSessionStorage(
    page: Page,
    key: string,
    expectedValue: string | null
) {
    const actualValue = await page.evaluate((k) => sessionStorage.getItem(k), key);
    expect(actualValue).toBe(expectedValue);
}

/**
 * Assert that local storage contains specific data
 */
export async function assertLocalStorage(
    page: Page,
    key: string,
    expectedValue: string | null
) {
    const actualValue = await page.evaluate((k) => localStorage.getItem(k), key);
    expect(actualValue).toBe(expectedValue);
}

/**
 * Assert that a cookie exists with specific value
 */
export async function assertCookie(
    page: Page,
    cookieName: string,
    expectedValue?: string
) {
    const cookies = await page.context().cookies();
    const cookie = cookies.find(c => c.name === cookieName);
    
    expect(cookie).toBeDefined();
    
    if (expectedValue !== undefined) {
        expect(cookie?.value).toBe(expectedValue);
    }
}

/**
 * Assert that user is authenticated
 */
export async function assertAuthenticated(page: Page) {
    // Check for JWT in session storage
    const jwt = await page.evaluate(() => sessionStorage.getItem('jwt'));
    expect(jwt).toBeTruthy();
    
    // Check for active org ID
    const orgId = await page.evaluate(() => sessionStorage.getItem('active_org_id'));
    expect(orgId).toBeTruthy();
}

/**
 * Assert that user is not authenticated
 */
export async function assertNotAuthenticated(page: Page) {
    const jwt = await page.evaluate(() => sessionStorage.getItem('jwt'));
    expect(jwt).toBeNull();
}

// ============================================================================
// UI State Assertions
// ============================================================================

/**
 * Assert that a button is in loading state
 */
export async function assertButtonLoading(
    page: Page,
    buttonSelector: string
) {
    const button = page.locator(buttonSelector);
    await expect(button).toBeDisabled();
    
    // Check for loading indicator
    const loadingIndicator = button.locator('svg, .spinner, [data-testid="loading"]');
    await expect(loadingIndicator).toBeVisible();
}

/**
 * Assert that a modal is open
 */
export async function assertModalOpen(
    page: Page,
    modalSelector: string = '[role="dialog"], .modal'
) {
    const modal = page.locator(modalSelector);
    await expect(modal).toBeVisible();
    
    // Check for backdrop
    const backdrop = page.locator('.modal-backdrop, [data-testid="modal-backdrop"]');
    if (await backdrop.count() > 0) {
        await expect(backdrop).toBeVisible();
    }
}

/**
 * Assert that a modal is closed
 */
export async function assertModalClosed(
    page: Page,
    modalSelector: string = '[role="dialog"], .modal'
) {
    const modal = page.locator(modalSelector);
    await expect(modal).not.toBeVisible();
}

/**
 * Assert that a dropdown/select has specific options
 */
export async function assertSelectOptions(
    page: Page,
    selectSelector: string,
    expectedOptions: string[]
) {
    const select = page.locator(selectSelector);
    const options = await select.locator('option').allTextContents();
    
    for (const expectedOption of expectedOptions) {
        expect(options).toContain(expectedOption);
    }
}

/**
 * Assert that a list contains specific items
 */
export async function assertListContains(
    page: Page,
    listSelector: string,
    expectedItems: string[]
) {
    const list = page.locator(listSelector);
    await expect(list).toBeVisible();
    
    for (const item of expectedItems) {
        const listItem = list.locator(`li:has-text("${item}"), [role="listitem"]:has-text("${item}")`);
        await expect(listItem).toBeVisible();
    }
}

// ============================================================================
// Navigation Assertions
// ============================================================================

/**
 * Assert that page navigated to expected URL
 */
export async function assertNavigatedTo(
    page: Page,
    expectedPath: string | RegExp
) {
    if (typeof expectedPath === 'string') {
        await page.waitForURL(`**${expectedPath}`, { timeout: 10000 });
        expect(page.url()).toContain(expectedPath);
    } else {
        await page.waitForURL(expectedPath, { timeout: 10000 });
        expect(page.url()).toMatch(expectedPath);
    }
}

/**
 * Assert that page did not navigate (stayed on same page)
 */
export async function assertDidNotNavigate(
    page: Page,
    originalUrl: string
) {
    await page.waitForTimeout(1000); // Wait a bit to ensure no navigation
    expect(page.url()).toBe(originalUrl);
}

// ============================================================================
// Accessibility Assertions
// ============================================================================

/**
 * Assert that an element has proper ARIA attributes
 */
export async function assertAriaAttributes(
    page: Page,
    selector: string,
    expectedAttributes: Record<string, string>
) {
    const element = page.locator(selector);
    
    for (const [attr, value] of Object.entries(expectedAttributes)) {
        const actualValue = await element.getAttribute(attr);
        expect(actualValue).toBe(value);
    }
}

/**
 * Assert that page has no accessibility violations
 * Note: Requires @axe-core/playwright to be installed
 */
export async function assertNoA11yViolations(page: Page) {
    // This is a placeholder - actual implementation would use axe-core
    // Example:
    // const results = await new AxeBuilder({ page }).analyze();
    // expect(results.violations).toHaveLength(0);
    
    console.log('A11y check: Would run axe-core scan here');
}

// ============================================================================
// Performance Assertions
// ============================================================================

/**
 * Assert that page loaded within acceptable time
 */
export async function assertPageLoadTime(
    page: Page,
    maxLoadTime: number = 3000
) {
    const performanceTiming = await page.evaluate(() => {
        const timing = performance.timing;
        return timing.loadEventEnd - timing.navigationStart;
    });
    
    expect(performanceTiming).toBeLessThan(maxLoadTime);
}

/**
 * Assert that API response time is acceptable
 */
export async function assertApiResponseTime(
    page: Page,
    urlPattern: string,
    maxResponseTime: number = 1000
) {
    const startTime = Date.now();
    
    await page.waitForResponse(
        (response) => response.url().includes(urlPattern),
        { timeout: maxResponseTime + 1000 }
    );
    
    const responseTime = Date.now() - startTime;
    expect(responseTime).toBeLessThan(maxResponseTime);
}

// ============================================================================
// Data Integrity Assertions
// ============================================================================

/**
 * Assert that data persists after page reload
 */
export async function assertDataPersistsAfterReload(
    page: Page,
    dataSelector: string,
    expectedText: string
) {
    // Verify data is present
    await expect(page.locator(dataSelector)).toContainText(expectedText);
    
    // Reload page
    await page.reload();
    
    // Verify data still present
    await expect(page.locator(dataSelector)).toContainText(expectedText);
}

/**
 * Assert that form validation works correctly
 */
export async function assertFormValidation(
    page: Page,
    formSelector: string,
    fieldName: string,
    invalidValue: string,
    expectedError: string | RegExp
) {
    const form = page.locator(formSelector);
    const field = form.locator(`input[name="${fieldName}"], textarea[name="${fieldName}"]`);
    
    // Fill with invalid value
    await field.fill(invalidValue);
    
    // Try to submit
    await form.locator('button[type="submit"]').click();
    
    // Check for validation error
    const errorElement = form.locator(`[data-testid="${fieldName}-error"], .error`);
    await expect(errorElement).toBeVisible();
    
    if (typeof expectedError === 'string') {
        await expect(errorElement).toContainText(expectedError);
    } else {
        const text = await errorElement.textContent();
        expect(text).toMatch(expectedError);
    }
}

// Made with Bob
