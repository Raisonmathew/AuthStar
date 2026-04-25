/**
 * Scoped Org Factory — Playwright fixture that creates an isolated
 * organization per test and tears it down automatically afterward.
 *
 * Usage in a spec file:
 *
 *   import { test } from '../fixtures/scoped-org';
 *
 *   test('admin can invite member', async ({ scopedOrg, page }) => {
 *     // scopedOrg.orgId, scopedOrg.slug, etc. are ready
 *   });
 */

import { test as base, Page } from '@playwright/test';
import {
    seedOrganization,
    seedUser,
    seedApiKey,
    cleanupResource,
} from './backend-seed';
import {
    addVirtualAuthenticator,
    removeVirtualAuthenticator,
    type VirtualAuthenticator,
} from './webauthn-virtual';

export interface ScopedOrgData {
    orgId: string;
    name: string;
    slug: string;
    /** Admin user seeded automatically with the org */
    admin: {
        userId: string;
        email: string;
        password: string;
    };
    /** Optional API key — only created when seedApiKey option is true */
    apiKey?: {
        keyId: string;
        key: string;
    };
}

export type ScopedOrgOptions = {
    /** Custom org name (default: auto-generated with timestamp) */
    name?: string;
    /** Custom admin email (default: auto-generated) */
    adminEmail?: string;
    /** Custom admin password (default: TestAdmin@123!) */
    adminPassword?: string;
    /** Whether to seed an API key (default: false) */
    seedApiKey?: boolean;
};

const DEFAULT_PASSWORD = 'TestAdmin@123!';

function uniqueSlug(): string {
    return `test-org-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

/**
 * Extended test with `scopedOrg` fixture.
 *
 * Each test using this fixture gets its own organization + admin user.
 * Cleanup happens automatically after the test completes.
 *
 * Also installs a CDP virtual WebAuthn authenticator on every page
 * (`webauthnAuto`, auto-fixture). Any `navigator.credentials.create` /
 * `navigator.credentials.get` call — i.e. any passkey verification popup —
 * is auto-approved with a successful user-verified assertion. This avoids
 * tests hanging on a real biometric / Windows Hello prompt.
 *
 * To opt out for a specific test (e.g. to assert behaviour when no
 * authenticator is present), use:
 *   test.use({ webauthnAutoVerify: false });
 */
export const test = base.extend<{
    scopedOrg: ScopedOrgData;
    scopedOrgOptions: ScopedOrgOptions;
    webauthnAutoVerify: boolean;
    webauthnAuto: VirtualAuthenticator | null;
}>({
    scopedOrgOptions: [{}, { option: true }],

    // Opt-in/out flag — default ON. Set `test.use({ webauthnAutoVerify: false })`
    // in a describe block to disable for tests that exercise the
    // "no authenticator available" path.
    webauthnAutoVerify: [true, { option: true }],

    // Auto-fixture: attaches a virtual authenticator to the page before the
    // test runs and detaches it after. Failures during attach/detach are
    // swallowed so a missing CDP capability never breaks an unrelated test.
    webauthnAuto: [
        async ({ page, webauthnAutoVerify }, use) => {
            if (!webauthnAutoVerify) {
                await use(null);
                return;
            }
            let auth: VirtualAuthenticator | null = null;
            try {
                auth = await addVirtualAuthenticator(page, {
                    protocol: 'ctap2',
                    transport: 'internal',
                    hasResidentKey: true,
                    hasUserVerification: true,
                    isUserVerified: true,
                });
            } catch (e) {
                // CDP not available (e.g. non-Chromium browser) — fall through;
                // tests that genuinely need a passkey will fail loudly with
                // their own error rather than this fixture masking it.
                console.warn('[webauthnAuto] Could not attach virtual authenticator:', (e as Error).message);
            }
            await use(auth);
            if (auth) {
                try {
                    await removeVirtualAuthenticator(page, auth);
                } catch {
                    // Page may already be closed during teardown — ignore.
                }
            }
        },
        { auto: true },
    ],

    scopedOrg: async ({ page, scopedOrgOptions: opts }, use) => {
        const slug = uniqueSlug();
        const orgName = opts.name ?? `E2E ${slug}`;
        const adminEmail = opts.adminEmail ?? `admin-${slug}@e2etest.local`;
        const adminPassword = opts.adminPassword ?? DEFAULT_PASSWORD;

        // 1. Seed org
        const org = await seedOrganization(page, { name: orgName });

        // 2. Seed admin user in that org
        const user = await seedUser(page, {
            email: adminEmail,
            password: adminPassword,
            firstName: 'E2E',
            lastName: 'Admin',
            orgId: org.orgId,
            role: 'admin',
        });

        // 3. Optionally seed API key
        let apiKey: ScopedOrgData['apiKey'];
        if (opts.seedApiKey) {
            const key = await seedApiKey(page, {
                name: `e2e-key-${slug}`,
                orgId: org.orgId,
                userId: user.userId,
            });
            apiKey = { keyId: key.keyId, key: key.key };
        }

        const data: ScopedOrgData = {
            orgId: org.orgId,
            name: orgName,
            slug: org.slug,
            admin: { userId: user.userId, email: adminEmail, password: adminPassword },
            apiKey,
        };

        // Use the fixture value in the test
        await use(data);

        // 4. Teardown — clean up in reverse dependency order
        if (apiKey) {
            await cleanupResource(page, 'api-key', apiKey.keyId).catch(() => {});
        }
        await cleanupResource(page, 'user', user.userId).catch(() => {});
        await cleanupResource(page, 'organization', org.orgId).catch(() => {});
    },
});

export { expect } from '@playwright/test';
