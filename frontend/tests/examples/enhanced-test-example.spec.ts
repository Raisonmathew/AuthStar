/**
 * Enhanced E2E Test Example
 * 
 * This file demonstrates how to use the new test infrastructure:
 * - API mocking
 * - Test data fixtures
 * - Enhanced assertions
 * - Proper cleanup
 * - Error scenario testing
 */

import { test, expect } from '../fixtures/test-utils';
import { 
    mockUserProfile, 
    mockApiKeys, 
    mockApiError,
    enableCommonMocks 
} from '../fixtures/api-mocks';
import { 
    TEST_USERS, 
    TEST_API_KEYS,
    generateUniqueTestData,
    createTestDataViaUI,
    deleteTestDataViaUI
} from '../fixtures/test-data';
import {
    assertApiSuccess,
    assertSuccessMessage,
    assertErrorMessage,
    assertTableContains,
    assertAuthenticated,
    assertFormValidation
} from '../fixtures/assertions';

test.describe('Enhanced API Keys Management (Example)', () => {

    test.beforeEach(async ({ page }) => {
        // Enable API mocking for consistent test data
        await enableCommonMocks(page);
    });

    test('can create API key with proper data validation', async ({ page }) => {
        // Login
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        // Verify authentication
        await assertAuthenticated(page);
        
        // Navigate to API keys
        await page.goto('/api-keys');
        
        // Generate unique test data
        const testData = generateUniqueTestData('api-key');
        
        // Create API key via UI
        await createTestDataViaUI(page, 'api-key', {
            name: testData.name,
            description: 'Test API key created by enhanced E2E test'
        });
        
        // Assert API call was successful
        await assertApiSuccess(page, '/api/v1/api-keys', 201);
        
        // Assert success message displayed
        await assertSuccessMessage(page, /created|success/i);
        
        // Assert key is displayed (one-time only)
        const keyElement = page.locator('code, pre').filter({ hasText: /ask_/ });
        await expect(keyElement).toBeVisible();
        
        // Cleanup: Delete the created key
        await page.click('button:has-text("Close"), button:has-text("Done")');
        await deleteTestDataViaUI(page, 'api-key', testData.name);
    });

    test('validates required fields on API key creation', async ({ page }) => {
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        await page.click('button:has-text("Create")');
        
        // Try to submit without name
        await assertFormValidation(
            page,
            'form',
            'name',
            '', // empty value
            /required|name.*required/i
        );
    });

    test('handles API errors gracefully', async ({ page }) => {
        // Mock API error
        await mockApiError(page, '**/api/v1/api-keys', 500, 'Internal server error');
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        await page.click('button:has-text("Create")');
        
        const testData = generateUniqueTestData('api-key');
        await page.fill('input[name="name"]', testData.name);
        await page.click('button[type="submit"]');
        
        // Assert error message is displayed
        await assertErrorMessage(page, /error|failed/i);
    });

    test('displays existing API keys with proper data', async ({ page }) => {
        // Mock API keys list
        await mockApiKeys(page, [TEST_API_KEYS.active, TEST_API_KEYS.unused]);
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        
        // Assert table contains expected data
        await assertTableContains(page, 'table', [
            { name: TEST_API_KEYS.active.name, prefix: TEST_API_KEYS.active.prefix },
            { name: TEST_API_KEYS.unused.name, prefix: TEST_API_KEYS.unused.prefix },
        ]);
    });

    test('can revoke API key with confirmation', async ({ page }) => {
        await mockApiKeys(page, [TEST_API_KEYS.active]);
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        
        // Click revoke button
        await page.click('button:has-text("Revoke")');
        
        // Confirm in modal
        await page.click('button:has-text("Confirm")');
        
        // Assert API call was made
        await assertApiSuccess(page, '/api/v1/api-keys', 200);
        
        // Assert success message
        await assertSuccessMessage(page, /revoked|deleted/i);
    });

    test('prevents duplicate API key names', async ({ page }) => {
        // Mock existing key
        await mockApiKeys(page, [TEST_API_KEYS.active]);
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        await page.click('button:has-text("Create")');
        
        // Try to create key with existing name
        await page.fill('input[name="name"]', TEST_API_KEYS.active.name);
        await page.click('button[type="submit"]');
        
        // Should show error
        await assertErrorMessage(page, /already exists|duplicate/i);
    });

});

test.describe('Performance and Accessibility Tests (Example)', () => {

    test('API keys page loads within acceptable time', async ({ page }) => {
        await enableCommonMocks(page);
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        const startTime = Date.now();
        await page.goto('/api-keys');
        await page.waitForSelector('table, [data-testid="api-keys-list"]');
        const loadTime = Date.now() - startTime;
        
        // Assert page loaded within 3 seconds
        expect(loadTime).toBeLessThan(3000);
    });

    test('API keys page has proper ARIA labels', async ({ page }) => {
        await enableCommonMocks(page);
        
        await page.goto('/u/admin');
        await page.fill('input[type="email"]', TEST_USERS.admin.email);
        await page.click('button[type="submit"]');
        await page.fill('input[type="password"]', TEST_USERS.admin.password);
        await page.click('button[type="submit"]');
        
        await page.goto('/api-keys');
        
        // Check for proper ARIA attributes
        const createButton = page.locator('button:has-text("Create")');
        const ariaLabel = await createButton.getAttribute('aria-label');
        
        // Should have descriptive aria-label or text content
        expect(ariaLabel || await createButton.textContent()).toBeTruthy();
    });

});

// Made with Bob
