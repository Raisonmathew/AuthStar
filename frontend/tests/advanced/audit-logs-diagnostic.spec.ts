/**
 * DIAGNOSTIC: Audit Log End-to-End Verification
 *
 * Drives the audit log page like a real browser, captures every API response,
 * triggers known-audited admin actions, and queries the DB directly to compare
 * against what the UI renders.
 *
 * Goal: prove whether audit logging is working, broken, or partially silent.
 */

import { test, expect } from '@playwright/test';
import type { APIResponse } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { ADMIN_AUTH_STATE_PATH } from '../global-setup';

test.use({ storageState: ADMIN_AUTH_STATE_PATH });

const PG_HOST = process.env.PGHOST ?? 'localhost';
const PG_PORT = process.env.PGPORT ?? '5432';
const PG_USER = process.env.PGUSER ?? 'idaas_user';
const PG_DB = process.env.PGDATABASE ?? 'idaas';
const PG_PASS = process.env.PGPASSWORD ?? 'dev_password_change_me';

function psql(sql: string): string {
    const psqlPath = process.platform === 'win32'
        ? 'C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe'
        : 'psql';
    return execFileSync(
        psqlPath,
        ['-h', PG_HOST, '-p', PG_PORT, '-U', PG_USER, '-d', PG_DB, '-tAc', sql],
        { env: { ...process.env, PGPASSWORD: PG_PASS }, encoding: 'utf-8', timeout: 10_000 },
    ).trim();
}

test.describe('Audit Log Diagnostic', () => {
    test('full pipeline: UI <-> API <-> DB', async ({ page, context }) => {
        const apiResponses: { url: string; status: number; body: any }[] = [];

        page.on('response', async (resp) => {
            const url = resp.url();
            if (!url.includes('/api/admin/v1/events') && !url.includes('/api/admin/v1/audit')) return;
            try {
                const body = await resp.json().catch(() => null);
                apiResponses.push({ url, status: resp.status(), body });
            } catch { /* ignore */ }
        });

        // ─── Step 1: Snapshot DB before navigating ──────────────────────────────
        // Admin user (user_admin) is scoped to tenant_id='system' (provider tenant).
        const TENANT = 'system';
        const dbCountBefore = parseInt(psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}'`
        ), 10);
        const dbLatestBefore = psql(
            `SELECT event_type || '|' || COALESCE(actor_email, '<NULL>') || '|' || COALESCE(target_id, '-') FROM audit_events WHERE tenant_id = '${TENANT}' ORDER BY created_at DESC LIMIT 5`
        );
        const nullActorBefore = parseInt(psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}' AND actor_email IS NULL`
        ), 10);
        console.log('[diag] DB total events (', TENANT, ') BEFORE:', dbCountBefore);
        console.log('[diag] DB rows with NULL actor_email BEFORE:', nullActorBefore);
        console.log('[diag] DB latest 5 BEFORE:\n' + dbLatestBefore);

        // ─── Step 2: Open the audit page ────────────────────────────────────────
        await page.goto('/admin/monitoring/logs', { waitUntil: 'domcontentloaded' });
        await expect(page.locator('h2:has-text("Audit & Compliance")')).toBeVisible();
        await page.waitForLoadState('networkidle');

        const listResp = apiResponses.find(r =>
            r.url.includes('/api/admin/v1/events') &&
            !r.url.includes('/stats') &&
            !r.url.match(/\/events\/[^?/]+(\?|$)/)
        );
        const statsResp = apiResponses.find(r => r.url.includes('/api/admin/v1/events/stats'));

        console.log('[diag] /events response status:', listResp?.status);
        console.log('[diag] /events count returned:', listResp?.body?.events?.length ?? 'n/a');
        console.log('[diag] /events/stats:', JSON.stringify(statsResp?.body));

        // ─── Step 3: Verify UI vs API vs DB ─────────────────────────────────────
        const uiRowCount = await page.locator('tbody tr, [data-testid="audit-event"]').count();
        console.log('[diag] UI rendered rows:', uiRowCount);

        const apiCount: number = listResp?.body?.events?.length ?? 0;
        expect(apiCount, 'API returned at least the seeded events').toBeGreaterThan(0);
        const statsTotal = statsResp?.body?.totalEvents ?? statsResp?.body?.total_events;
        expect(statsTotal, 'Stats total should match DB').toBe(dbCountBefore);

        // ─── Step 4: Trigger a known-audited action (API key create + revoke) ───
        // This exercises the audit emission code path in api_keys.rs (L58, L86).
        // Use the in-browser fetch so cookies + CSRF token are honoured by the
        // app's interceptors (page.request runs in node and skips the React layer).
        const created: { ok: boolean; status: number; body: any } = await page.evaluate(async (name) => {
            const csrfMatch = document.cookie.match(/(?:^|;\s*)__csrf=([^;]+)/);
            const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
            const r = await fetch('/api/v1/api-keys', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
                body: JSON.stringify({ name, scopes: ['keys:read'] }),
            });
            const txt = await r.text();
            let body: any = null; try { body = JSON.parse(txt); } catch { body = txt; }
            return { ok: r.ok, status: r.status, body };
        }, `diag-audit-${Date.now()}`);
        console.log('[diag] Create status:', created.status, 'body:', JSON.stringify(created.body).slice(0, 200));
        expect(created.ok, 'API key create should succeed').toBeTruthy();
        const keyId = created.body?.id ?? created.body?.api_key?.id ?? created.body?.key?.id;
        console.log('[diag] Created API key id:', keyId);
        expect(keyId, 'Response must include an id').toBeTruthy();

        let revokeStatus = 0;
        if (keyId) {
            const rev = await page.evaluate(async (id) => {
                const csrfMatch = document.cookie.match(/(?:^|;\s*)__csrf=([^;]+)/);
                const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
                const r = await fetch(`/api/v1/api-keys/${id}`, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: { 'X-CSRF-Token': csrf },
                });
                return { ok: r.ok, status: r.status };
            }, keyId);
            revokeStatus = rev.status;
            console.log('[diag] Revoke status:', revokeStatus);
        }

        // Audit recording is fire-and-forget — give it a moment.
        await page.waitForTimeout(800);

        // ─── Step 5: Re-snapshot DB ─────────────────────────────────────────────
        const dbCountAfter = parseInt(psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}'`
        ), 10);
        const dbNew = psql(
            `SELECT event_type || '|' || COALESCE(target_id, '-') || '|' || COALESCE(actor_email, '<NULL>') ` +
            `FROM audit_events WHERE tenant_id = '${TENANT}' AND created_at > NOW() - INTERVAL '30 seconds' ` +
            `ORDER BY created_at DESC`
        );
        console.log('[diag] DB total AFTER:', dbCountAfter, '(delta:', dbCountAfter - dbCountBefore, ')');
        console.log('[diag] DB new events in last 30s:\n' + dbNew);

        const apiKeyCreatedRow = psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}' AND event_type = 'api_key.created' AND created_at > NOW() - INTERVAL '30 seconds'`
        );
        const apiKeyRevokedRow = psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}' AND event_type = 'api_key.revoked' AND created_at > NOW() - INTERVAL '30 seconds'`
        );
        const apiKeyNullActor = psql(
            `SELECT COUNT(*) FROM audit_events WHERE tenant_id = '${TENANT}' AND event_type LIKE 'api_key.%' AND actor_email IS NULL AND created_at > NOW() - INTERVAL '30 seconds'`
        );
        console.log('[diag] api_key.* rows in last 30s with NULL actor_email:', apiKeyNullActor);
        console.log('[diag] api_key.created rows in last 30s:', apiKeyCreatedRow);
        console.log('[diag] api_key.revoked rows in last 30s:', apiKeyRevokedRow);

        // ─── Step 6: Reload page, see if new events appear ──────────────────────
        apiResponses.length = 0;
        await page.reload({ waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(500);

        const uiTextAfter = await page.locator('tbody').first().innerText().catch(() => '');
        console.log('[diag] UI table text (first 600 chars):\n' + uiTextAfter.slice(0, 600));

        const seesCreate = uiTextAfter.includes('api_key') && uiTextAfter.match(/created/i);
        const seesRevoke = uiTextAfter.match(/revoked/i);
        console.log('[diag] UI shows api_key.created?', !!seesCreate);
        console.log('[diag] UI shows api_key.revoked?', !!seesRevoke);

        // ─── Step 7: Final verdicts ─────────────────────────────────────────────
        const findings: string[] = [];
        if (created.ok && parseInt(apiKeyCreatedRow, 10) === 0) {
            findings.push('BUG: api_key.created succeeded but NO audit row was inserted');
        }
        if (revokeStatus >= 200 && revokeStatus < 300 && parseInt(apiKeyRevokedRow, 10) === 0) {
            findings.push('BUG: api_key.revoked succeeded but NO audit row was inserted');
        }
        if (dbCountAfter - dbCountBefore < 2) {
            findings.push(`SUSPICIOUS: only ${dbCountAfter - dbCountBefore} new audit rows after 2 admin actions (expected >=2)`);
        }
        if (statsTotal !== dbCountBefore) {
            findings.push(`MISMATCH: /stats total=${statsTotal} but DB count=${dbCountBefore}`);
        }
        if (apiCount > uiRowCount && apiCount > 0) {
            findings.push(`UI RENDER: API returned ${apiCount} events but UI rendered ${uiRowCount} rows`);
        }
        if (parseInt(apiKeyNullActor, 10) > 0) {
            findings.push(`BUG: ${apiKeyNullActor} api_key.* audit rows just inserted have NULL actor_email (audit emission missing actor)`);
        }

        console.log('\n========== AUDIT DIAGNOSTIC VERDICT ==========');
        if (findings.length === 0) {
            console.log('PASS: pipeline appears healthy');
        } else {
            findings.forEach(f => console.log('  - ' + f));
        }
        console.log('==============================================\n');
    });
});
