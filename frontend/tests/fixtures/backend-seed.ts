/**
 * Backend Test Data Seeding Helper
 *
 * Provides functions to seed and cleanup test data via backend API endpoints.
 * Only works in non-production environments.
 */

import { Page } from '@playwright/test';

// Playwright tests run in Node.js, so we can safely use localhost
const API_BASE_URL = 'http://localhost:8080';

/**
 * Seed a test user
 */
export async function seedUser(
    page: Page,
    data: {
        email: string;
        password: string;
        firstName?: string;
        lastName?: string;
        orgId?: string;
    }
): Promise<{ userId: string; email: string; orgId: string }> {
    const response = await page.request.post(`${API_BASE_URL}/api/test/seed/user`, {
        data: {
            email: data.email,
            password: data.password,
            first_name: data.firstName,
            last_name: data.lastName,
            org_id: data.orgId,
        },
    });

    if (!response.ok()) {
        throw new Error(`Failed to seed user: ${response.status()} ${await response.text()}`);
    }

    const result = await response.json();
    return {
        userId: result.user_id,
        email: result.email,
        orgId: result.org_id,
    };
}

/**
 * Seed a test organization
 */
export async function seedOrganization(
    page: Page,
    data: {
        name: string;
        slug?: string;
    }
): Promise<{ orgId: string; name: string; slug: string }> {
    const response = await page.request.post(`${API_BASE_URL}/api/test/seed/organization`, {
        data: {
            name: data.name,
            slug: data.slug,
        },
    });

    if (!response.ok()) {
        throw new Error(`Failed to seed organization: ${response.status()} ${await response.text()}`);
    }

    const result = await response.json();
    return {
        orgId: result.org_id,
        name: result.name,
        slug: result.slug,
    };
}

/**
 * Seed a test API key
 */
export async function seedApiKey(
    page: Page,
    data: {
        name: string;
        orgId: string;
        userId: string;
    }
): Promise<{ keyId: string; key: string }> {
    const response = await page.request.post(`${API_BASE_URL}/api/test/seed/api-key`, {
        data: {
            name: data.name,
            org_id: data.orgId,
            user_id: data.userId,
        },
    });

    if (!response.ok()) {
        throw new Error(`Failed to seed API key: ${response.status()} ${await response.text()}`);
    }

    const result = await response.json();
    return {
        keyId: result.key_id,
        key: result.key,
    };
}

/**
 * Seed a test policy
 */
export async function seedPolicy(
    page: Page,
    data: {
        name: string;
        orgId: string;
        action: string;
    }
): Promise<{ policyId: string }> {
    const response = await page.request.post(`${API_BASE_URL}/api/test/seed/policy`, {
        data: {
            name: data.name,
            org_id: data.orgId,
            action: data.action,
        },
    });

    if (!response.ok()) {
        throw new Error(`Failed to seed policy: ${response.status()} ${await response.text()}`);
    }

    const result = await response.json();
    return {
        policyId: result.policy_id,
    };
}

/**
 * Seed a test MFA factor
 */
export async function seedMfaFactor(
    page: Page,
    data: {
        userId: string;
        factorType: 'totp' | 'backup_codes';
    }
): Promise<{ factorId: string; secret?: string; backupCodes?: string[] }> {
    const response = await page.request.post(`${API_BASE_URL}/api/test/seed/mfa-factor`, {
        data: {
            user_id: data.userId,
            factor_type: data.factorType,
        },
    });

    if (!response.ok()) {
        throw new Error(`Failed to seed MFA factor: ${response.status()} ${await response.text()}`);
    }

    const result = await response.json();
    return {
        factorId: result.factor_id,
        secret: result.secret,
        backupCodes: result.backup_codes,
    };
}

/**
 * Cleanup a specific resource
 */
export async function cleanupResource(
    page: Page,
    resourceType: 'user' | 'organization' | 'api-key' | 'policy' | 'mfa-factor',
    resourceId: string
): Promise<void> {
    const response = await page.request.delete(
        `${API_BASE_URL}/api/test/cleanup/${resourceType}/${resourceId}`
    );

    if (!response.ok() && response.status() !== 404) {
        throw new Error(`Failed to cleanup ${resourceType}: ${response.status()} ${await response.text()}`);
    }
}

/**
 * Cleanup all test data (use with caution!)
 */
export async function cleanupAll(page: Page): Promise<void> {
    const response = await page.request.delete(`${API_BASE_URL}/api/test/cleanup/all`);

    if (!response.ok()) {
        throw new Error(`Failed to cleanup all test data: ${response.status()} ${await response.text()}`);
    }
}

/**
 * Seed a complete test environment (org + user + API key)
 */
export async function seedTestEnvironment(
    page: Page,
    options: {
        orgName?: string;
        userEmail?: string;
        userPassword?: string;
        apiKeyName?: string;
    } = {}
): Promise<{
    org: { orgId: string; name: string; slug: string };
    user: { userId: string; email: string; orgId: string };
    apiKey?: { keyId: string; key: string };
}> {
    const orgName = options.orgName || `Test Org ${Date.now()}`;
    const userEmail = options.userEmail || `test-${Date.now()}@example.com`;
    const userPassword = options.userPassword || 'Test123!@#';

    // Create organization
    const org = await seedOrganization(page, { name: orgName });

    // Create user in organization
    const user = await seedUser(page, {
        email: userEmail,
        password: userPassword,
        firstName: 'Test',
        lastName: 'User',
        orgId: org.orgId,
    });

    // Optionally create API key
    let apiKey;
    if (options.apiKeyName) {
        apiKey = await seedApiKey(page, {
            name: options.apiKeyName,
            orgId: org.orgId,
            userId: user.userId,
        });
    }

    return { org, user, apiKey };
}

/**
 * Cleanup a test environment
 */
export async function cleanupTestEnvironment(
    page: Page,
    environment: {
        org?: { orgId: string };
        user?: { userId: string };
        apiKey?: { keyId: string };
    }
): Promise<void> {
    // Cleanup in reverse order (API key -> user -> org)
    if (environment.apiKey) {
        await cleanupResource(page, 'api-key', environment.apiKey.keyId);
    }
    if (environment.user) {
        await cleanupResource(page, 'user', environment.user.userId);
    }
    if (environment.org) {
        await cleanupResource(page, 'organization', environment.org.orgId);
    }
}

/**
 * Check if backend seeding is available
 */
export async function isBackendSeedingAvailable(page: Page): Promise<boolean> {
    try {
        const response = await page.request.get(`${API_BASE_URL}/health`);
        return response.ok();
    } catch {
        return false;
    }
}

// Made with Bob
