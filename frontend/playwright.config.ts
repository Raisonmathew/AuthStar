import { defineConfig, devices } from '@playwright/test';
import { ADMIN_AUTH_STATE_PATH } from './tests/global-setup';

// Dev-only convenience: outside CI, fall back to the well-known dev token
// that the local backend reads when `TEST_SEED_TOKEN` is unset. CI environments
// MUST provide their own value — the fallback is intentionally not applied
// when CI=true so misconfigured pipelines fail loudly instead of leaking the
// shared dev secret upstream. Library code (tests/fixtures/backend-seed.ts)
// throws on missing env, so this default must be set before any test imports run.
if (!process.env.CI && !process.env.TEST_SEED_TOKEN) {
    process.env.TEST_SEED_TOKEN = 'dev-test-seed-token-change-for-staging';
}

const slowMoMs = process.env.CI ? 0 : Number(process.env.PLAYWRIGHT_SLOW_MO_MS ?? '200');

// Fail-fast: abort the whole suite after N failures.
// CI defaults to 0 (run everything so retries get useful data).
// Local default is 5 — enough to confirm a regression cluster without
// burning 30+ minutes on the same root-cause failure.
// Override with PLAYWRIGHT_MAX_FAILURES=N (0 = unlimited) or use
//   `npx playwright test --max-failures=N` on the CLI.
const maxFailuresEnv = process.env.PLAYWRIGHT_MAX_FAILURES;
const maxFailures = maxFailuresEnv !== undefined
    ? Number(maxFailuresEnv)
    : (process.env.CI ? 0 : 5);

export default defineConfig({
    testDir: './tests',
    timeout: 90_000,
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    maxFailures,
    reporter: 'html',
    globalSetup: './tests/global-setup.ts',

    use: {
        baseURL: 'http://localhost:5173',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        // Enable headed mode for local development (use --headed flag)
        // In CI, this will be overridden to headless
        headless: process.env.CI ? true : false,
    },

    projects: [
        // Default: pre-authed admin for existing tests
        // Excludes user/* and admin/* since dedicated projects cover them cleanly
        {
            name: 'chromium',
            testIgnore: [/user\/.*\.spec\.ts/, /admin\/.*\.spec\.ts/],
            use: {
                ...devices['Desktop Chrome'],
                storageState: ADMIN_AUTH_STATE_PATH,
                launchOptions: {
                    slowMo: slowMoMs,
                },
            },
        },
        // Admin lifecycle: org management, roles, invites, audit
        {
            name: 'admin-journey',
            testMatch: /admin\/.*\.spec\.ts/,
            use: {
                ...devices['Desktop Chrome'],
                storageState: ADMIN_AUTH_STATE_PATH,
                launchOptions: { slowMo: slowMoMs },
            },
        },
        // User onboarding: signup, invite accept, MFA enroll, profile.
        // NO storageState — these tests exercise unauthenticated flows (signup,
        // login, password reset). Each test seeds its own user via the backend
        // seed API and drives the full auth flow from scratch.
        {
            name: 'user-journey',
            testMatch: /user\/.*\.spec\.ts/,
            use: {
                ...devices['Desktop Chrome'],
                launchOptions: { slowMo: slowMoMs },
            },
        },
        // Edge-case & security scenarios
        {
            name: 'edge-cases',
            testMatch: /advanced\/.*\.spec\.ts/,
            use: {
                ...devices['Desktop Chrome'],
                launchOptions: { slowMo: slowMoMs },
            },
        },
    ],

    // Both servers are required: the frontend serves the SPA and the backend
    // satisfies the SPA's silent-refresh / auth-init requests during
    // global-setup. If the backend is missing, global-setup blocks at
    // /u/admin until the 120s timeout fires with a misleading message.
    webServer: [
        {
            command: 'cargo run --bin api_server --manifest-path ../backend/Cargo.toml',
            url: 'http://localhost:3000/health',
            reuseExistingServer: !process.env.CI,
            timeout: 300_000, // first build can be slow; reuse path is instant
            stdout: 'ignore',
            stderr: 'pipe',
        },
        {
            command: 'npm run dev',
            url: 'http://localhost:5173',
            reuseExistingServer: !process.env.CI,
            timeout: 120_000,
        },
    ],
});
