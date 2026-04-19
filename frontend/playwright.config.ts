import { defineConfig, devices } from '@playwright/test';
import { ADMIN_AUTH_STATE_PATH } from './tests/global-setup';

const slowMoMs = process.env.CI ? 0 : Number(process.env.PLAYWRIGHT_SLOW_MO_MS ?? '0');

export default defineConfig({
    testDir: './tests',
    timeout: 90_000,
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
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
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
                // Pre-authenticated state: each test context is seeded with the
                // saved refresh cookie so the app auto-authenticates via token
                // refresh instead of going through the full login flow.
                storageState: ADMIN_AUTH_STATE_PATH,
                launchOptions: {
                    slowMo: slowMoMs,
                },
            },
        },
        // Optional: Add Firefox and WebKit for cross-browser testing
        // Uncomment when needed
        // {
        //     name: 'firefox',
        //     use: { ...devices['Desktop Firefox'] },
        // },
        // {
        //     name: 'webkit',
        //     use: { ...devices['Desktop Safari'] },
        // },
    ],

    webServer: {
        command: 'npm run dev',
        url: 'http://localhost:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 120000, // 2 minutes for server startup
    },
});
