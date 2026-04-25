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
        // If a saved auth state exists, seed the browser context with it so
        // the React app can do silentRefresh from the stored refresh cookie
        // rather than showing the login form from scratch.
        const fs = await import('fs');
        const savedStateExists = fs.existsSync(ADMIN_AUTH_STATE_PATH);
        const context = await browser.newContext(
            savedStateExists ? { storageState: ADMIN_AUTH_STATE_PATH } : {}
        );
        const page = await context.newPage();

        // Mock the EIAA runtime keys endpoint BEFORE navigating.
        // If the capsule runtime gRPC service is not running, this endpoint
        // returns 502 and main.tsx blocks React from mounting (retries 4×
        // with backoff). Mocking it lets the bootstrap complete regardless of
        // whether the runtime service is up.
        await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: '[]',
            })
        );

        await page.goto('http://localhost:5173/u/admin');

        // React mounts, does silentRefresh, then either:
        //   a) redirects to /admin/dashboard (session still valid), or
        //   b) shows the email login form (session expired/missing).
        // We race both possibilities — each leg catches its own timeout so
        // Promise.race never throws, even on a slow cold start.
        const outcome = await Promise.race([
            page.waitForURL('**/admin/dashboard', { timeout: 120_000 })
                .then(() => 'authenticated' as const)
                .catch(() => 'timeout' as const),
            page.waitForSelector('input[type="email"]', { timeout: 120_000 })
                .then(() => 'needs-login' as const)
                .catch(() => 'timeout' as const),
        ]);

        if (outcome === 'timeout') {
            // Neither happened — probe both servers so the failure message
            // tells us exactly which side is down (the most common cause).
            const finalUrl = page.url();
            const probe = async (url: string) => {
                try {
                    const res = await fetch(url, { signal: AbortSignal.timeout(2_000) });
                    return `${res.status}`;
                } catch (e) {
                    return `unreachable (${(e as Error).message})`;
                }
            };
            const [feStatus, beStatus] = await Promise.all([
                probe('http://localhost:5173/'),
                probe('http://localhost:3000/health'),
            ]);
            console.log(`[global-setup] Timeout! Current URL: ${finalUrl}`);
            console.log(`[global-setup]   frontend (5173): ${feStatus}`);
            console.log(`[global-setup]   backend  (3000): ${beStatus}`);
            if (!finalUrl.includes('/admin/dashboard')) {
                throw new Error(
                    `[global-setup] Login form and dashboard both timed out. ` +
                    `Current URL: ${finalUrl}. frontend=${feStatus}, backend=${beStatus}. ` +
                    'Both servers must be running (Playwright now starts them via webServer; ' +
                    'check the per-server startup logs above).'
                );
            }
            // URL IS the dashboard — treated as authenticated below
        }

        if (outcome === 'needs-login') {
            await page.fill('input[type="email"]', 'admin@example.com');
            await page.click('button[type="submit"]');

            await page.waitForSelector('input[type="password"]', { timeout: 30_000 });
            await page.fill('input[type="password"]', process.env.IDAAS_BOOTSTRAP_PASSWORD ?? 'Admin@1234!DevOnly');
            await page.click('button[type="submit"]');

            await page.waitForURL('**/admin/dashboard', { timeout: 90_000 });
        }

        // Save cookies (incl. HttpOnly refresh token) + localStorage
        await context.storageState({ path: ADMIN_AUTH_STATE_PATH });
        await context.close();
    }

    await browser.close();

    // ----- Upgrade admin sessions to AAL3 -----
    // Admin routes now require up to AAL3 for some sensitive actions. Password
    // login only yields AAL1, and Playwright cannot reliably complete the live
    // step-up ceremonies during the suite. Promote the seeded admin sessions so
    // the tests can exercise the protected admin flows deterministically.
    upgradeAdminSessionsToAAL3();

    // ----- Reset admin risk state -----
    // The "invalid password shows error" test intentionally submits wrong
    // passwords. These accumulate in auth_attempts and risk_evaluations across
    // successive test runs. After ~6 failed attempts in an hour the risk engine
    // disallows the 'password' capability entirely, causing global-setup's own
    // login (and loginAsAdmin) to fail. Reset the counters before each run so
    // the slate is clean regardless of prior runs.
    resetAdminRiskState();

    // ----- Restore admin memberships -----
    // Backend bootstrap *should* keep `user_admin` as owner of 'system' and
    // admin of 'default' via ON CONFLICT DO UPDATE. In practice some tests
    // (and earlier broken cleanup paths) demote the membership, leaving the
    // role-management tests permanently 403. Restore the canonical roles
    // here so admin-journey tests are deterministic across runs.
    resetAdminMemberships();

    // NOTE: user_admin admin role in 'default' org is guaranteed by
    // backend bootstrap (see backend/.../bootstrap.rs) which runs on every
    // backend start with `ON CONFLICT DO UPDATE SET role = 'admin'`.
    // Tests that mutate role membership MUST restore it themselves.

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

function upgradeAdminSessionsToAAL3() {
    const pgHost = process.env.PGHOST ?? 'localhost';
    const pgPort = process.env.PGPORT ?? '5432';
    const pgUser = process.env.PGUSER ?? 'idaas_user';
    const pgDb = process.env.PGDATABASE ?? 'idaas';
    const pgPassword = process.env.PGPASSWORD ?? 'dev_password_change_me';

    const sql = `UPDATE sessions SET aal_level = 3 WHERE user_id = 'user_admin' AND revoked = false AND aal_level < 3`;

    const runPsql = (psqlCmd: string) =>
        execSync(`${psqlCmd} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -c "${sql}"`, {
            env: { ...process.env, PGPASSWORD: pgPassword },
            stdio: 'pipe',
            timeout: 10_000,
        });

    try {
        runPsql('psql');
        console.log('[global-setup] Upgraded admin sessions to AAL3');
    } catch {
        try {
            const psqlPath = process.platform === 'win32'
                ? '"C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe"'
                : 'psql';
            runPsql(psqlPath);
            console.log('[global-setup] Upgraded admin sessions to AAL3 (full path)');
        } catch (e2) {
            console.warn('[global-setup] Could not upgrade sessions to AAL3:', (e2 as Error).message);
        }
    }
}

function resetAdminRiskState() {
    const pgHost = process.env.PGHOST ?? 'localhost';
    const pgPort = process.env.PGPORT ?? '5432';
    const pgUser = process.env.PGUSER ?? 'idaas_user';
    const pgDb = process.env.PGDATABASE ?? 'idaas';
    const pgPassword = process.env.PGPASSWORD ?? 'dev_password_change_me';

    // Clear failed auth attempts so the risk engine doesn't block password auth.
    // Also clear persisted risk evaluations and reset the user's failed-attempt
    // counter so each run starts from a known-good state.
    const sql = [
        `DELETE FROM auth_attempts WHERE user_id = 'user_admin' OR email = 'admin@example.com'`,
        `DELETE FROM risk_evaluations WHERE subject_id = 'user_admin'`,
        `UPDATE users SET failed_login_attempts = 0, locked = false, locked_at = NULL WHERE id = 'user_admin'`,
    ].join('; ');

    const runPsql = (psqlCmd: string) =>
        execSync(`${psqlCmd} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -c "${sql}"`, {
            env: { ...process.env, PGPASSWORD: pgPassword },
            stdio: 'pipe',
            timeout: 10_000,
        });

    try {
        runPsql('psql');
        console.log('[global-setup] Reset admin risk state');
    } catch {
        try {
            const psqlPath = process.platform === 'win32'
                ? '"C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe"'
                : 'psql';
            runPsql(psqlPath);
            console.log('[global-setup] Reset admin risk state (full path)');
        } catch (e2) {
            console.warn('[global-setup] Could not reset admin risk state:', (e2 as Error).message);
        }
    }
}

function resetAdminMemberships() {
    const pgHost = process.env.PGHOST ?? 'localhost';
    const pgPort = process.env.PGPORT ?? '5432';
    const pgUser = process.env.PGUSER ?? 'idaas_user';
    const pgDb = process.env.PGDATABASE ?? 'idaas';
    const pgPassword = process.env.PGPASSWORD ?? 'dev_password_change_me';

    // Restore canonical admin memberships (mirrors backend bootstrap intent).
    // UPDATE-only — bootstrap is responsible for inserting; we only correct
    // the role if a previous test demoted it.
    const sql = [
        `UPDATE memberships SET role = 'owner' WHERE id = 'membership_admin_system'`,
        `UPDATE memberships SET role = 'admin' WHERE id = 'membership_admin_default'`,
    ].join('; ');

    const runPsql = (psqlCmd: string) =>
        execSync(`${psqlCmd} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -c "${sql}"`, {
            env: { ...process.env, PGPASSWORD: pgPassword },
            stdio: 'pipe',
            timeout: 10_000,
        });

    try {
        runPsql('psql');
        console.log('[global-setup] Restored admin memberships');
    } catch {
        try {
            const psqlPath = process.platform === 'win32'
                ? '"C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe"'
                : 'psql';
            runPsql(psqlPath);
            console.log('[global-setup] Restored admin memberships (full path)');
        } catch (e2) {
            console.warn('[global-setup] Could not restore admin memberships:', (e2 as Error).message);
        }
    }
}

export default globalSetup;
