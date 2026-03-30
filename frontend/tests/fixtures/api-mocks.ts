import { Page, Route } from '@playwright/test';

/**
 * API Mocking Strategy for E2E Tests
 * 
 * This module provides utilities to mock backend API responses,
 * allowing tests to run independently of backend state.
 */

export interface MockConfig {
    enabled: boolean;
    mockData?: Record<string, any>;
}

/**
 * Mock user profile API response
 */
export async function mockUserProfile(page: Page, userData?: any) {
    await page.route('**/api/v1/user', async (route: Route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(userData || {
                id: 'test-user-123',
                email: 'test@example.com',
                first_name: 'Test',
                last_name: 'User',
                image_url: null,
                created_at: new Date().toISOString(),
            }),
        });
    });
}

/**
 * Mock MFA factors list
 */
export async function mockMfaFactors(page: Page, factors?: any[]) {
    await page.route('**/api/v1/user/factors', async (route: Route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(factors || [
                { id: '1', factor_type: 'totp', status: 'active', created_at: new Date().toISOString() },
            ]),
        });
    });
}

/**
 * Mock API keys list
 */
export async function mockApiKeys(page: Page, keys?: any[]) {
    await page.route('**/api/v1/api-keys', async (route: Route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(keys || [
                    {
                        id: 'key-1',
                        name: 'Test API Key',
                        prefix: 'ask_abc123',
                        created_at: new Date().toISOString(),
                        last_used_at: null,
                    },
                ]),
            });
        } else {
            // Let POST requests through for creation tests
            await route.continue();
        }
    });
}

/**
 * Mock policy configurations list
 */
export async function mockPolicyConfigs(page: Page, configs?: any[]) {
    await page.route('**/api/v1/policy-builder/configs', async (route: Route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(configs || [
                    {
                        id: 'config-1',
                        name: 'Test Policy',
                        description: 'Test policy configuration',
                        action: 'user:read',
                        state: 'draft',
                        created_at: new Date().toISOString(),
                    },
                ]),
            });
        } else {
            await route.continue();
        }
    });
}

/**
 * Mock organization details
 */
export async function mockOrganization(page: Page, orgData?: any) {
    await page.route('**/api/v1/organizations/*', async (route: Route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(orgData || {
                    id: 'org-123',
                    name: 'Test Organization',
                    slug: 'test-org',
                    branding: {
                        logo_url: 'https://example.com/logo.png',
                        primary_color: '#3B82F6',
                    },
                    created_at: new Date().toISOString(),
                }),
            });
        } else {
            await route.continue();
        }
    });
}

/**
 * Mock team members list
 */
export async function mockTeamMembers(page: Page, members?: any[]) {
    await page.route('**/api/v1/organizations/*/members', async (route: Route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(members || [
                    {
                        user_id: 'user-1',
                        email: 'member1@example.com',
                        first_name: 'Member',
                        last_name: 'One',
                        role: 'admin',
                        joined_at: new Date().toISOString(),
                    },
                    {
                        user_id: 'user-2',
                        email: 'member2@example.com',
                        first_name: 'Member',
                        last_name: 'Two',
                        role: 'member',
                        joined_at: new Date().toISOString(),
                    },
                ]),
            });
        } else {
            await route.continue();
        }
    });
}

/**
 * Mock subscription details
 */
export async function mockSubscription(page: Page, subData?: any) {
    await page.route('**/api/billing/v1/subscription', async (route: Route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(subData || {
                id: 'sub-123',
                status: 'active',
                plan: {
                    id: 'plan-pro',
                    name: 'Professional',
                    price: 99,
                    interval: 'month',
                },
                current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            }),
        });
    });
}

/**
 * Mock invoices list
 */
export async function mockInvoices(page: Page, invoices?: any[]) {
    await page.route('**/api/billing/v1/invoices*', async (route: Route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(invoices || [
                {
                    id: 'inv-1',
                    amount: 9900,
                    currency: 'usd',
                    status: 'paid',
                    created_at: new Date().toISOString(),
                    pdf_url: 'https://example.com/invoice.pdf',
                },
            ]),
        });
    });
}

/**
 * Mock error response
 */
export async function mockApiError(page: Page, pattern: string, statusCode: number, message: string) {
    await page.route(pattern, async (route: Route) => {
        await route.fulfill({
            status: statusCode,
            contentType: 'application/json',
            body: JSON.stringify({
                error: message,
                code: statusCode,
            }),
        });
    });
}

/**
 * Enable all common mocks for a test
 */
export async function enableCommonMocks(page: Page) {
    await mockUserProfile(page);
    await mockMfaFactors(page);
    await mockApiKeys(page);
    await mockPolicyConfigs(page);
    await mockOrganization(page);
    await mockTeamMembers(page);
    await mockSubscription(page);
    await mockInvoices(page);
}

/**
 * Disable all mocks (use real backend)
 */
export async function disableAllMocks(page: Page) {
    await page.unroute('**/*');
}

// Made with Bob
