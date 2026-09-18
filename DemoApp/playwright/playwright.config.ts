import { defineConfig, devices } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load .env.local from the demo app root
dotenv.config({ path: path.resolve(__dirname, '../.env.local') });

// Dev convenience — mirror the same TEST_SEED_TOKEN default used by the
// existing frontend/tests/global-setup.ts so both suites work identically.
if (!process.env.CI && !process.env.TEST_SEED_TOKEN) {
  process.env.TEST_SEED_TOKEN = 'dev-test-seed-token-change-for-staging';
}

export const ADMIN_AUTH_STATE_PATH = path.join(__dirname, 'fixtures', '.auth', 'admin.json');

export const BACKEND_URL = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';
export const DEMO_APP_URL = 'http://localhost:4000';
export const PY_SIDECAR_URL = process.env.PYTHON_AGENT_SERVICE_URL || 'http://localhost:8001';

export default defineConfig({
  testDir: './specs',
  timeout: 60_000,
  fullyParallel: false,  // agent API tests mutate shared state
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : 2,
  reporter: [['html', { outputFolder: '../playwright-report' }], ['list']],
  globalSetup: './global-setup.ts',

  use: {
    baseURL: DEMO_APP_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    headless: process.env.CI ? true : false,
  },

  projects: [
    // Human auth — unauthenticated by default
    {
      name: 'human-auth',
      testMatch: /01-human-auth\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    // Admin flows — pre-authed admin session
    {
      name: 'admin-flows',
      testMatch: /02-admin\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: ADMIN_AUTH_STATE_PATH },
    },
    // Agent API tests — pure HTTP via page.request, pre-authed admin
    {
      name: 'agent-api',
      testMatch: /(03-agent-registration|04-agent-token|05-tool-authz)\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: ADMIN_AUTH_STATE_PATH },
    },
    // Audit chain
    {
      name: 'audit',
      testMatch: /06-audit\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: ADMIN_AUTH_STATE_PATH },
    },
    // Security / revocation / tenant isolation
    {
      name: 'security',
      testMatch: /07-security\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: ADMIN_AUTH_STATE_PATH },
    },
    // SDK contract tests (TS + Python)
    {
      name: 'sdk',
      testMatch: /08-sdk\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: ADMIN_AUTH_STATE_PATH },
    },
    // End-to-end golden path
    {
      name: 'golden-path',
      testMatch: /09-e2e-golden-path\/.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: [
    // Demo app (Next.js on port 4000)
    {
      command: 'npm run start',
      cwd: path.resolve(__dirname, '..'),
      url: DEMO_APP_URL,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      stdout: 'ignore',
      stderr: 'pipe',
    },
    // Python sidecar (started separately by CI or developer)
    // In CI: run `uvicorn main:app --port 8001` before playwright
    // Locally: `cd DemoApp/py-agent-service && uvicorn main:app --reload --port 8001`
  ],
});
