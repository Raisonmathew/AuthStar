/**
 * Playwright Global Setup
 *
 * Performs a single admin login before the test suite runs and saves the
 * authenticated browser state (cookies, localStorage) to a fixture file.
 * All tests then start with this state — the app's AppLoadingGuard will
 * exchange the saved refresh cookie for a JWT on first load, so no
 * individual test needs to go through the full login flow.
 *
 * This approach:
 *  - Avoids hitting the auth-flow rate-limit (10 init/min per IP)
 *  - Eliminates repeated login overhead (~3–5 s per test)
 *  - Keeps tests isolated (each gets a fresh context seeded from the file)
 */

import { chromium, FullConfig } from '@playwright/test';
import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const ADMIN_AUTH_STATE_PATH = path.join(
    __dirname,
    'fixtures',
    '.auth',
    'admin.json',
);

export const USER_AUTH_STATE_PATH = path.join(
    __dirname,
    'fixtures',
    '.auth',
    'user.json',
);

async function globalSetup(_config: FullConfig) {
    const browser = await chromium.launch();

    // ----- Admin account -----
    {
        const context = await browser.newContext();
        const page = await context.newPage();

        await page.goto('http://localhost:5173/u/admin');

        // Wait for the email step (past AppLoadingGuard + flow init)
        await page.waitForSelector('input[type="email"]', { timeout: 30_000 });
        await page.fill('input[type="email"]', 'admin@example.com');
        await page.click('button[type="submit"]');

        // Wait for password step
        await page.waitForSelector('input[type="password"]', { timeout: 30_000 });
        await page.fill('input[type="password"]', process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly');
        await page.click('button[type="submit"]');

        // Wait for successful redirect to admin dashboard
        await page.waitForURL('**/admin/dashboard', { timeout: 30_000 });

        // Save cookies (incl. HttpOnly refresh token) + localStorage
        await context.storageState({ path: ADMIN_AUTH_STATE_PATH });
        await context.close();
    }

    await browser.close();

    // ----- Upgrade admin sessions to AAL2 -----
    // Admin dashboard routes require AAL2 (NIST SP 800-63B). Password login
    // only yields AAL1. In production a passkey/TOTP step-up satisfies AAL2,
    // but headless Playwright cannot perform WebAuthn ceremonies. Promote the
    // sessions directly so the test suite can exercise admin pages.
    upgradeAdminSessionsToAAL2();

    // ----- Seed audit events -----
    // The EIAA auth flow does not write to the audit_events table, so we seed
    // test data directly via psql so audit-log tests have rows to work with.
    seedAuditEvents();
}

function seedAuditEvents() {
    const pgHost = process.env.PGHOST ?? 'localhost';
    const pgPort = process.env.PGPORT ?? '5432';
    const pgUser = process.env.PGUSER ?? 'idaas_user';
    const pgDb = process.env.PGDATABASE ?? 'idaas';
    const pgPassword = process.env.PGPASSWORD ?? 'dev_password_change_me';
    const sqlFile = path.join(__dirname, 'fixtures', 'seed-audit-events.sql');

    const runPsql = (psqlCmd: string) =>
        execSync(`${psqlCmd} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -f "${sqlFile}"`, {
            env: { ...process.env, PGPASSWORD: pgPassword },
            stdio: 'pipe',
            timeout: 10_000,
        });

    try {
        runPsql('psql');
        console.log('[global-setup] Seeded audit events');
    } catch {
        try {
            const psqlPath = process.platform === 'win32'
                ? '"C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe"'
                : 'psql';
            runPsql(psqlPath);
            console.log('[global-setup] Seeded audit events (full path)');
        } catch (e2) {
            console.warn('[global-setup] Could not seed audit events:', (e2 as Error).message);
        }
    }
}

function upgradeAdminSessionsToAAL2() {
    const pgHost = process.env.PGHOST ?? 'localhost';
    const pgPort = process.env.PGPORT ?? '5432';
    const pgUser = process.env.PGUSER ?? 'idaas_user';
    const pgDb = process.env.PGDATABASE ?? 'idaas';
    const pgPassword = process.env.PGPASSWORD ?? 'dev_password_change_me';

    const sql = `UPDATE sessions SET aal_level = 2 WHERE user_id = 'user_admin' AND revoked = false AND aal_level < 2`;

    const runPsql = (psqlCmd: string) =>
        execSync(`${psqlCmd} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -c "${sql}"`, {
            env: { ...process.env, PGPASSWORD: pgPassword },
            stdio: 'pipe',
            timeout: 10_000,
        });

    try {
        runPsql('psql');
        console.log('[global-setup] Upgraded admin sessions to AAL2');
    } catch {
        try {
            const psqlPath = process.platform === 'win32'
                ? '"C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe"'
                : 'psql';
            runPsql(psqlPath);
            console.log('[global-setup] Upgraded admin sessions to AAL2 (full path)');
        } catch (e2) {
            console.warn('[global-setup] Could not upgrade sessions to AAL2:', (e2 as Error).message);
        }
    }
}

export default globalSetup;
