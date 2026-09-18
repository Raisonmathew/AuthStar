/**
 * DemoApp Playwright Global Setup
 *
 * 1. Verifies Docker stack is healthy (backend + optional Python sidecar)
 * 2. Walks the EIAA auth flow to obtain an admin session
 * 3. Upgrades admin sessions to AAL3 (bypasses step-up gate on agent:manage routes)
 * 4. Saves browser storage state to fixtures/.auth/admin.json
 *
 * Pattern mirrors frontend/tests/global-setup.ts exactly so the two suites
 * remain consistent.
 */
import { chromium, FullConfig } from '@playwright/test';
import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const ADMIN_AUTH_STATE_PATH = path.join(__dirname, 'fixtures', '.auth', 'admin.json');

const BACKEND_URL = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';
const DEMO_APP_URL = 'http://localhost:4000';

async function globalSetup(_config: FullConfig) {
  // ── Ensure fixtures/.auth/ exists ──
  const authDir = path.dirname(ADMIN_AUTH_STATE_PATH);
  if (!fs.existsSync(authDir)) fs.mkdirSync(authDir, { recursive: true });

  const browser = await chromium.launch({ headless: !!process.env.CI });

  // ── Admin sign-in ──
  {
    const savedStateExists = fs.existsSync(ADMIN_AUTH_STATE_PATH);
    const context = await browser.newContext(
      savedStateExists ? { storageState: ADMIN_AUTH_STATE_PATH } : {},
    );
    const page = await context.newPage();

    // Mock EIAA runtime keys so the demo app boots even when capsule runtime is down
    await page.route('**/api/eiaa/v1/runtime/keys', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }),
    );

    await page.goto(`${DEMO_APP_URL}/sign-in`);

    // Check if we can navigate straight to the dashboard (token still valid)
    const outcome = await Promise.race([
      page.waitForURL(`${DEMO_APP_URL}/dashboard`, { timeout: 20_000 })
        .then(() => 'authenticated' as const)
        .catch(() => 'needs-login' as const),
      page.waitForSelector('[data-testid="sign-in-form"]', { timeout: 20_000 })
        .then(() => 'needs-login' as const)
        .catch(() => 'needs-login' as const),
    ]);

    if (outcome === 'needs-login') {
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
      const adminPw = process.env.IDAAS_BOOTSTRAP_PASSWORD ?? '';

      await page.fill('[data-testid="input-email"]', adminEmail);
      await page.fill('[data-testid="input-password"]', adminPw);
      await page.click('[data-testid="btn-submit"]');
      await page.waitForURL(`${DEMO_APP_URL}/dashboard`, { timeout: 30_000 });
    }

    await context.storageState({ path: ADMIN_AUTH_STATE_PATH });
    await context.close();
  }

  await browser.close();

  // ── Upgrade admin sessions to AAL3 ──
  upgradeAdminSessionsToAAL3();

  // ── Reset admin risk state ──
  resetAdminRiskState();

  // ── Clean up leftover e2e API keys from previous runs ──
  purgeStaleE2eApiKeys();

  // ── Remove stale capsules with wrong model_id, flush Redis cache ──
  removeStaleTestCapsules();
}

// ── DB helpers (same pattern as frontend/tests/global-setup.ts) ─────────────

function runSql(sql: string): void {
  const pgContainer = process.env.PG_CONTAINER ?? 'idaas-postgres-dev';
  const pgUser      = process.env.PGUSER     ?? 'idaas_user';
  const pgDb        = process.env.PGDATABASE ?? 'idaas';
  const pgPassword  = process.env.PGPASSWORD ?? 'dev_password_change_me';
  const pgHost      = process.env.PGHOST     ?? 'localhost';
  const pgPort      = process.env.PGPORT     ?? '5432';
  const escaped = sql.replace(/"/g, '\\"');
  const localEnv = { ...process.env, PGPASSWORD: pgPassword };

  for (const psql of ['psql']) {
    try {
      execSync(
        `${psql} -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} -c "${escaped}"`,
        { env: localEnv, stdio: 'pipe', timeout: 10_000 },
      );
      return;
    } catch { /* fall through to docker */ }
  }
  try {
    const dockerHost = process.env.DOCKER_HOST || 'unix:///var/folders/vq/x07t3ld9093bcxk810xvbtv40000gn/T/podman/podman-machine-default-api.sock';
    execSync(
      `docker exec ${pgContainer} psql -U ${pgUser} -d ${pgDb} -c "${escaped}"`,
      { env: { ...process.env, DOCKER_HOST: dockerHost }, stdio: 'pipe', timeout: 10_000 },
    );
  } catch {
    console.warn('[global-setup] Could not run SQL — is Postgres running?');
  }
}

function upgradeAdminSessionsToAAL3() {
  try {
    runSql(`UPDATE sessions SET aal_level = 3 WHERE user_id = 'user_admin' AND revoked = false AND aal_level < 3`);
    console.log('[global-setup] Upgraded admin sessions to AAL3');
  } catch (e) {
    console.warn('[global-setup] AAL3 upgrade skipped:', (e as Error).message);
  }
}

function removeStaleTestCapsules() {
  try {
    // Delete capsules compiled for wrong model IDs (gpt-4o, unknown-model-xyz-9999)
    // that were created by security-test runs. All e2e agent tests use claude-3-5-sonnet-20241022.
    // The most-recent capsule row (ORDER BY created_at DESC) is what EIAA serves,
    // so bad rows must be removed or they silently deny all claude agents.
    runSql(`
      DELETE FROM eiaa_capsules
      WHERE action IN ('agent:send_email','agent:web_search','agent:make_payment')
        AND ast_bytes IS NOT NULL
        AND (
          encode(ast_bytes,'escape') LIKE '%"model_id":"gpt-4o"%'
          OR encode(ast_bytes,'escape') LIKE '%"model_id":"unknown-%'
        )
    `);
    console.log('[global-setup] Removed stale test capsules with wrong model_id');
  } catch (e) {
    console.warn('[global-setup] Stale capsule removal skipped:', (e as Error).message);
  }
  // Flush Redis cache so fresh DB rows are loaded on next request
  try {
    const dockerHost = process.env.DOCKER_HOST || 'unix:///var/folders/vq/x07t3ld9093bcxk810xvbtv40000gn/T/podman/podman-machine-default-api.sock';
    execSync(
      `docker exec idaas-redis-dev redis-cli DEL capsule:system:agent:send_email capsule:system:agent:web_search capsule:system:agent:make_payment`,
      { env: { ...process.env, DOCKER_HOST: dockerHost }, stdio: 'pipe', timeout: 5_000 },
    );
    console.log('[global-setup] Flushed capsule Redis cache entries');
  } catch (e) {
    console.warn('[global-setup] Redis capsule flush skipped:', (e as Error).message);
  }
}

function purgeStaleE2eApiKeys() {
  try {
    // Revoke all API keys whose name matches e2e test patterns (e2e-key_*, demo-key_*, etc.)
    // This prevents hitting the 5-key billing quota ceiling across test runs.
    runSql(
      `UPDATE api_keys SET revoked_at = NOW() WHERE revoked_at IS NULL AND (name LIKE 'e2e-key_%' OR name LIKE 'demo-key_%' OR name LIKE 'sdk-agent%' OR name LIKE 'testkey%' OR name LIKE 'test-key%' OR name LIKE 'int-test-%' OR name LIKE 'integration-test%')`,
    );
    console.log('[global-setup] Purged stale e2e API keys');
  } catch (e) {
    console.warn('[global-setup] API key purge skipped:', (e as Error).message);
  }
}

function resetAdminRiskState() {
  try {
    runSql([
      `DELETE FROM auth_attempts WHERE created_at > NOW() - INTERVAL '2 hours'`,
      `UPDATE users SET failed_login_attempts = 0, locked = false, locked_at = NULL WHERE id = 'user_admin'`,
    ].join('; '));
    console.log('[global-setup] Reset admin risk state');
  } catch (e) {
    console.warn('[global-setup] Risk state reset skipped:', (e as Error).message);
  }
}

export default globalSetup;
