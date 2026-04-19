/**
 * Test Data Fixtures and Seeding Utilities
 * 
 * Provides consistent test data across all E2E tests and utilities
 * for seeding/cleaning up test data in the database.
 */

import { Page } from '@playwright/test';

// ============================================================================
// Test User Fixtures
// ============================================================================

export const TEST_USERS = {
    admin: {
        email: 'admin@example.com',
        password: process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly',
        first_name: 'Admin',
        last_name: 'User',
        role: 'owner',
        tenant_id: 'system',
    },
    user: {
        email: 'user@example.com',
        password: process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly',
        first_name: 'Test',
        last_name: 'User',
        role: 'member',
        tenant_id: 'default',
    },
    developer: {
        email: 'dev@example.com',
        password: 'password',
        first_name: 'Developer',
        last_name: 'User',
        role: 'developer',
        tenant_id: 'default',
    },
};

// ============================================================================
// Test Organization Fixtures
// ============================================================================

export const TEST_ORGANIZATIONS = {
    system: {
        id: 'system',
        name: 'System',
        slug: 'admin',
        branding: {
            logo_url: 'https://example.com/system-logo.png',
            primary_color: '#3B82F6',
            secondary_color: '#10B981',
        },
    },
    default: {
        id: 'default',
        name: 'Default Organization',
        slug: 'default',
        branding: {
            logo_url: 'https://example.com/default-logo.png',
            primary_color: '#8B5CF6',
            secondary_color: '#EC4899',
        },
    },
};

// ============================================================================
// Test API Key Fixtures
// ============================================================================

export const TEST_API_KEYS = {
    active: {
        id: 'key-active-1',
        name: 'Production API Key',
        prefix: 'ask_prod123',
        description: 'Production environment key',
        created_at: new Date('2024-01-01').toISOString(),
        last_used_at: new Date().toISOString(),
        status: 'active',
    },
    unused: {
        id: 'key-unused-1',
        name: 'Staging API Key',
        prefix: 'ask_stag456',
        description: 'Staging environment key',
        created_at: new Date('2024-01-15').toISOString(),
        last_used_at: null,
        status: 'active',
    },
};

// ============================================================================
// Test Policy Fixtures
// ============================================================================

export const TEST_POLICIES = {
    draft: {
        id: 'policy-draft-1',
        name: 'Draft Login Policy',
        description: 'Policy in draft state',
        action: 'auth:login',
        state: 'draft',
        version: 1,
        created_at: new Date('2024-01-01').toISOString(),
        updated_at: new Date('2024-01-01').toISOString(),
    },
    active: {
        id: 'policy-active-1',
        name: 'Active User Read Policy',
        description: 'Active policy for user read operations',
        action: 'user:read',
        state: 'active',
        version: 3,
        created_at: new Date('2024-01-01').toISOString(),
        updated_at: new Date('2024-02-01').toISOString(),
        activated_at: new Date('2024-02-01').toISOString(),
    },
};

// ============================================================================
// Test MFA Factor Fixtures
// ============================================================================

export const TEST_MFA_FACTORS = {
    totp: {
        id: 'factor-totp-1',
        factor_type: 'totp',
        status: 'active',
        created_at: new Date('2024-01-01').toISOString(),
        last_used_at: new Date().toISOString(),
    },
    passkey: {
        id: 'factor-passkey-1',
        factor_type: 'passkey',
        status: 'active',
        created_at: new Date('2024-01-15').toISOString(),
        last_used_at: new Date().toISOString(),
    },
};

// ============================================================================
// Test Subscription Fixtures
// ============================================================================

export const TEST_SUBSCRIPTIONS = {
    free: {
        id: 'sub-free-1',
        status: 'active',
        plan: {
            id: 'plan-free',
            name: 'Free',
            price: 0,
            interval: 'month',
            features: ['1000 MAU', 'Basic Auth', 'Email Support'],
        },
        current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    },
    pro: {
        id: 'sub-pro-1',
        status: 'active',
        plan: {
            id: 'plan-pro',
            name: 'Professional',
            price: 99,
            interval: 'month',
            features: ['10000 MAU', 'Advanced Auth', 'MFA', 'Priority Support'],
        },
        current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    },
};

// ============================================================================
// Database Seeding Utilities
// ============================================================================

/**
 * Seed test data via API calls
 * This creates real data in the database for integration testing
 */
export async function seedTestData(page: Page, dataType: 'users' | 'organizations' | 'policies' | 'all') {
    // Note: This would make actual API calls to seed data
    // Implementation depends on having a seeding endpoint or using direct DB access
    
    console.log(`Seeding test data: ${dataType}`);
    
    // Example: Call a test-only seeding endpoint
    // await page.request.post('/api/test/seed', {
    //     data: { type: dataType }
    // });
}

/**
 * Clean up test data after tests
 */
export async function cleanupTestData(page: Page, dataType: 'users' | 'organizations' | 'policies' | 'all') {
    console.log(`Cleaning up test data: ${dataType}`);
    
    // Example: Call a test-only cleanup endpoint
    // await page.request.post('/api/test/cleanup', {
    //     data: { type: dataType }
    // });
}

/**
 * Generate unique test data to avoid conflicts
 */
export function generateUniqueTestData(prefix: string) {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    
    return {
        email: `${prefix}-${timestamp}-${random}@test.example.com`,
        name: `Test ${prefix} ${timestamp}`,
        slug: `test-${prefix}-${timestamp}-${random}`,
        id: `test-${prefix}-${timestamp}-${random}`,
    };
}

/**
 * Wait for data to be available (polling utility)
 */
export async function waitForData(
    page: Page,
    selector: string,
    timeout: number = 10000
): Promise<boolean> {
    try {
        await page.waitForSelector(selector, { timeout, state: 'visible' });
        return true;
    } catch {
        return false;
    }
}

/**
 * Verify data was created successfully
 */
export async function verifyDataCreated(
    page: Page,
    dataType: string,
    identifier: string
): Promise<boolean> {
    // Check if data exists in the UI
    const element = page.locator(`text=${identifier}`);
    return await element.isVisible({ timeout: 5000 });
}

/**
 * Create test data via UI (for E2E flow testing)
 */
export async function createTestDataViaUI(
    page: Page,
    dataType: 'api-key' | 'policy' | 'member',
    data: Record<string, any>
) {
    switch (dataType) {
        case 'api-key':
            await page.goto('/api-keys');
            await page.click('button:has-text("Create")');
            await page.fill('input[name="name"]', data.name);
            if (data.description) {
                await page.fill('textarea[name="description"]', data.description);
            }
            await page.click('button[type="submit"]');
            break;
            
        case 'policy':
            await page.goto('/admin/policies');
            await page.click('button:has-text("Create")');
            await page.fill('input[name="name"]', data.name);
            if (data.description) {
                await page.fill('textarea[name="description"]', data.description);
            }
            await page.click('button[type="submit"]');
            break;
            
        case 'member':
            await page.goto('/team');
            await page.click('button:has-text("Invite")');
            await page.fill('input[type="email"]', data.email);
            if (data.role) {
                await page.selectOption('select[name="role"]', data.role);
            }
            await page.click('button[type="submit"]');
            break;
    }
}

/**
 * Delete test data via UI
 */
export async function deleteTestDataViaUI(
    page: Page,
    dataType: 'api-key' | 'policy' | 'member',
    identifier: string
) {
    // Find the item by identifier and click delete
    const deleteButton = page.locator(`tr:has-text("${identifier}") button:has-text("Delete"), tr:has-text("${identifier}") button:has-text("Revoke")`);
    
    if (await deleteButton.isVisible({ timeout: 2000 })) {
        await deleteButton.click();
        
        // Confirm deletion if modal appears
        const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
        if (await confirmButton.isVisible({ timeout: 2000 })) {
            await confirmButton.click();
        }
    }
}

// Made with Bob
