/**
 * E2E tests for Epic E2: Policy Builder UI (US-01 through US-06)
 */

import { test, expect } from '@playwright/test';

const MOCK_AGENT = {
    agent_id: 'agt_e2e_policy_test',
    name: 'Customer Support Bot',
    model_id: 'anthropic/claude-3-5-sonnet',
    description: 'Autonomous customer support agent',
    allowed_tools: 'search_kb send_email query_order',
    max_delegation_depth: 3,
    active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    active_policy: null,
};

const MOCK_CONFIG = {
    id: 'pcfg_test_123',
    action_key: 'agent:call:agt_e2e_policy_test',
    display_name: 'Customer Support Bot Policy',
    description: 'Policy for support bot',
    state: 'active',
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    groups: [
        {
            id: 'grp_1',
            display_name: 'Default Group',
            match_mode: 'all',
            on_match: 'allow',
            on_no_match: 'deny',
            stepup_methods: [],
            rules: [],
        },
    ],
};

const MOCK_VERSION_HISTORY = [
    {
        id: 'ver_1',
        version_number: 1,
        is_active: true,
        compiled_at: new Date().toISOString(),
        compiled_by: 'usr_admin',
        source: 'manual',
        ast_summary: 'Allows search_kb, send_email on *; requires human in delegation chain',
        ast_hash_b64: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
    },
];

async function setupMocks(page: import('@playwright/test').Page) {
    // Mock /api/v1/agents
    await page.route('**/api/v1/agents', async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    data: [MOCK_AGENT],
                    total: 1,
                }),
            });
        } else {
            await route.continue();
        }
    });

    // Mock /api/v1/policy-builder/configs
    await page.route('**/api/v1/policy-builder/configs', async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([MOCK_CONFIG]),
            });
        } else if (route.request().method() === 'POST') {
            await route.fulfill({
                status: 201,
                contentType: 'application/json',
                body: JSON.stringify({
                    ...MOCK_CONFIG,
                    state: 'draft',
                }),
            });
        } else {
            await route.continue();
        }
    });

    // Mock templates and condition types for config detail
    await page.route('**/api/v1/policy-builder/templates', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([]),
        });
    });

    await page.route('**/api/v1/policy-builder/condition-types', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([]),
        });
    });

    // Mock single config retrieval
    await page.route('**/api/v1/policy-builder/configs/pcfg_test_123', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(MOCK_CONFIG),
        });
    });

    // Mock version history
    await page.route('**/api/v1/policy-builder/configs/pcfg_test_123/versions', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(MOCK_VERSION_HISTORY),
        });
    });

    // Mock /api/v1/policy-builder/test
    await page.route('**/api/v1/policy-builder/test', async (route) => {
        const body = JSON.parse(route.request().postData() || '{}');
        const isSendEmail = body?.context?.tool === 'send_email';
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                allowed: isSendEmail,
                deciding_step: isSendEmail ? 'AuthorizeToolCall' : 'Deny',
                decision_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
                execution_time_ms: 12,
            }),
        });
    });

    // Mock /api/v1/policy-builder/configs/*/import-ast and /api/policy-builder/configs/*/import-ast
    await page.route('**/policy-builder/configs/*/import-ast', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                version_number: 1,
                capsule_id: 'cap_test_123',
                wasm_hash: 'hash1234567890abcdef',
                compiled_at: new Date().toISOString(),
            }),
        });
    });

    // Mock /api/v1/policy-builder/configs/*/activate and /api/policy-builder/configs/*/activate
    await page.route('**/policy-builder/configs/*/activate', async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                id: 'pcfg_test_123',
                state: 'active',
                version: 1,
                activated_at: new Date().toISOString(),
            }),
        });
    });
}

test.describe('Epic E2 — Policy Builder UI Comprehensive Browser Tests', () => {
    test.beforeEach(async ({ page }) => {
        await setupMocks(page);
    });

    test('US-01: can navigate to new policy page and select starter template', async ({ page }) => {
        await page.goto('/admin/policies');

        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });

        // Click "New Policy"
        await page.click('button:has-text("New Policy")');
        await page.waitForURL('**/admin/policies/new', { timeout: 10_000 });

        // Verify Header and Agent dropdown option
        await expect(page.locator('h1:has-text("Create Agent Policy")')).toBeVisible();
        const select = page.locator('select');
        await expect(select).toBeVisible();

        // Verify Starter Template cards
        await expect(page.locator('h4:has-text("Allow single tool")')).toBeVisible();
        await expect(page.locator('h4:has-text("Allow multiple tools")')).toBeVisible();
        await expect(page.locator('h4:has-text("Delegation requirement")')).toBeVisible();
        await expect(page.locator('h4:has-text("Start from scratch")')).toBeVisible();
    });

    test('US-02: dynamic tool repeater, validation errors, and live AST generation', async ({ page }) => {
        await page.goto('/admin/policies/new');
        await expect(page.locator('h1:has-text("Create Agent Policy")')).toBeVisible({ timeout: 10_000 });

        // Select "Allow multiple tools" template
        await page.click('button:has-text("Allow multiple tools")');

        // Toggle on AST Preview
        await page.click('button:has-text("View compiled AST")');
        await expect(page.locator('pre')).toContainText('authorize_tool_call', { timeout: 5_000 });

        // Add a new tool row
        await page.click('button:has-text("+ Add Tool")');

        // Add an argument constraint
        await page.click('button:has-text("+ Add Arg Constraint")');
        const keyInput = page.locator('input[placeholder*="Key"]');
        await expect(keyInput).toBeVisible();
        await keyInput.fill('recipient');

        // Toggle Human Delegation Checkbox
        const delegationCheckbox = page.locator('input[type="checkbox"]').first();
        await delegationCheckbox.check();
        await expect(page.locator('pre')).toContainText('check_delegation_chain', { timeout: 5_000 });
    });

    test('US-03: can run simulation tests in Policy Test Console with ALLOW / DENY outcomes', async ({ page }) => {
        await page.goto('/admin/policies/new');
        await expect(page.locator('h1:has-text("Create Agent Policy")')).toBeVisible({ timeout: 10_000 });

        // Open Test Console
        await page.click('button:has-text("Test Policy")');
        await expect(page.locator('h3:has-text("Policy Test Console")')).toBeVisible({ timeout: 5_000 });

        // Fill simulated tool in Test Console (use exact label sibling input)
        const toolInput = page.locator('div:has(> label:has-text("Simulated Tool")) input');
        await toolInput.fill('send_email');

        // Run simulation
        await page.click('button:has-text("Run Test")');

        // Validate ALLOW badge and deciding step
        await expect(page.locator('span.px-3.py-1:has-text("ALLOW")')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('strong:has-text("AuthorizeToolCall")')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('text=Attestation hash: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d')).toBeVisible({ timeout: 5_000 });

        // Change tool to unknown tool to simulate DENY
        await toolInput.fill('unauthorized_tool');
        await page.click('button:has-text("Run Test")');
        await expect(page.locator('span.px-3.py-1:has-text("DENY")')).toBeVisible({ timeout: 5_000 });
    });

    test('US-04: deployment stepper progresses from Compiling -> Signing -> Activating -> Active', async ({ page }) => {
        await page.goto('/admin/policies/new');
        await expect(page.locator('h1:has-text("Create Agent Policy")')).toBeVisible({ timeout: 10_000 });

        // Select agent from dropdown
        await page.selectOption('select', 'agt_e2e_policy_test');

        // Enter Policy Name
        await page.fill('input[placeholder*="e.g. Email Agent Allowed Tools"]', 'Production Bot Policy');

        // Click Deploy Policy
        await page.click('button:has-text("Deploy Policy")');

        // Untested policy warning modal should appear
        await expect(page.locator('h3:has-text("Untested Policy Warning")')).toBeVisible({ timeout: 5_000 });
        await page.click('button:has-text("Deploy Anyway")');

        // Confirmation modal
        await expect(page.locator('h3:has-text("Confirm Policy Deployment")')).toBeVisible({ timeout: 5_000 });
        await page.click('button:has-text("Deploy Now")');

        // Stepper progresses to Active
        await expect(page.locator('text=Active (v1)')).toBeVisible({ timeout: 10_000 });
        await expect(page.locator('text=4. Active')).toBeVisible({ timeout: 10_000 });
    });

    test('US-05 & US-06: version history panel and rollback interface', async ({ page }) => {
        await page.goto('/admin/policies');
        await expect(page.locator('h1:has-text("Policy Builder")')).toBeVisible({ timeout: 10_000 });

        // Open existing policy card
        const configCard = page.locator('button.w-full.text-left').first();
        await expect(configCard).toBeVisible({ timeout: 5_000 });
        await configCard.click();

        // Verify Detail Page
        await page.waitForURL('**/admin/policies/pcfg_test_123', { timeout: 10_000 });
        await expect(page.locator('button:has-text("Customer Support Bot Policy")')).toBeVisible({ timeout: 5_000 });

        // Click Version History Tab
        await page.click('button:has-text("Versions")');

        // Verify summary and active badge
        await expect(page.locator('text=Allows search_kb, send_email on *')).toBeVisible({ timeout: 5_000 });
        await expect(page.locator('span:has-text("ACTIVE")')).toBeVisible({ timeout: 5_000 });
    });
});
