/**
 * Agent Webhook Configuration — Playwright UI Test Suite
 *
 * Coverage areas:
 *   WH-1  Navigation — sidebar "Webhooks" link, page title, empty state
 *   WH-2  Add endpoint — modal open/close, validation (https, secret length)
 *   WH-3  Add endpoint — happy path, one-time secret reveal, list update
 *   WH-4  Edit webhook — opens pre-filled modal, saves update
 *   WH-5  Delete webhook — confirmation gate, optimistic removal
 *   WH-6  Test delivery — dispatches synthetic event, success toast
 *   WH-7  Payload format callout — static info block always visible
 *   WH-8  Edge cases — network errors show error toasts
 *
 * Strategy:
 *   All API calls are mocked with page.route() so no real backend is required.
 *   Mocks are registered before page.goto() to avoid race conditions.
 *   Login is mocked via the loginAsAdmin fixture pattern.
 */

import { test, expect } from '../fixtures/test-utils';

const BASE = 'http://localhost:5173';

// ---- Fixtures ----------------------------------------------------------------

const WEBHOOK_1 = {
    id: 'whk_test0000000000000001',
    url: 'https://hooks.example.com/authstar',
    secret_masked: '********',
    description: 'Production receiver',
    active: true,
    last_delivery_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    last_delivery_status: 200,
    last_delivery_success: true,
    created_at: new Date(Date.now() - 86400 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 86400 * 1000).toISOString(),
};

const WEBHOOK_2 = {
    id: 'whk_test0000000000000002',
    url: 'https://staging.example.com/events',
    secret_masked: '********',
    description: null,
    active: true,
    last_delivery_at: null,
    last_delivery_status: null,
    last_delivery_success: null,
    created_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 3600 * 1000).toISOString(),
};

const CREATED_WEBHOOK = {
    id: 'whk_test0000000000000003',
    url: 'https://new.example.com/hooks',
    secret: 'supersecretvalue1234',
    description: null,
    active: true,
    created_at: new Date().toISOString(),
};

// ---- Auth mock helper --------------------------------------------------------

async function mockAuthAndNavigate(page: import('@playwright/test').Page, path: string) {
    // Provide a synthetic JWT payload for the token refresh so AuthContext
    // considers itself authenticated without hitting a real backend.
    const fakeJwt = [
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9',
        btoa(JSON.stringify({ sub: 'usr_admin', sid: 'sess_test', tenant_id: 'org_test', session_type: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 })).replace(/=/g, ''),
        'FAKESIGNATURE',
    ].join('.');

    await page.route('**/api/v1/token/refresh', route =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                access_token: fakeJwt,
                user: { id: 'usr_admin', email: 'admin@test.local', first_name: 'Test', last_name: 'Admin' },
            }),
        })
    );
    await page.route('**/api/eiaa/v1/runtime/keys', route =>
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );
    // Mock whoami so AdminLayout lets us through
    await page.route('**/api/admin/v1/whoami', route =>
        route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'usr_admin', email: 'admin@test.local' }) })
    );
    await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle', timeout: 30_000 });
}

// =============================================================================
// WH-1: Navigation
// =============================================================================

test.describe('WH-1 Navigation', () => {
    test('sidebar shows Webhooks link under AI Agents', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await expect(page.getByRole('link', { name: 'Webhooks' })).toBeVisible();
    });

    test('page heading is "Webhook Endpoints"', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await expect(page.getByRole('heading', { name: 'Webhook Endpoints' })).toBeVisible();
    });

    test('empty state prompt is shown when no webhooks exist', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await expect(page.getByText('No webhook endpoints')).toBeVisible();
        await expect(page.getByText('Add an HTTPS endpoint to start receiving real-time agent events.')).toBeVisible();
    });
});

// =============================================================================
// WH-2: Add endpoint — validation
// =============================================================================

test.describe('WH-2 Add endpoint — validation', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await expect(page.getByTestId('webhook-modal')).toBeVisible();
    });

    test('modal closes on Cancel', async ({ page }) => {
        await page.getByRole('button', { name: 'Cancel' }).click();
        await expect(page.getByTestId('webhook-modal')).not.toBeVisible();
    });

    test('modal closes on X button', async ({ page }) => {
        await page.getByRole('button', { name: 'Close' }).click();
        await expect(page.getByTestId('webhook-modal')).not.toBeVisible();
    });

    test('shows URL validation error when URL is not https', async ({ page }) => {
        await page.getByLabel('Endpoint URL').fill('http://insecure.example.com/hook');
        await page.getByLabel('HMAC Secret').fill('supersecretvalue1234');
        await page.getByRole('button', { name: 'Add Endpoint' }).click();
        await expect(page.getByText('URL must start with https://')).toBeVisible();
    });

    test('shows secret length validation error when secret is too short', async ({ page }) => {
        await page.getByLabel('Endpoint URL').fill('https://hooks.example.com/authstar');
        await page.getByLabel('HMAC Secret').fill('tooshort');
        await page.getByRole('button', { name: 'Add Endpoint' }).click();
        await expect(page.getByText('Secret must be at least 16 characters')).toBeVisible();
    });

    test('submit button is labelled "Add Endpoint"', async ({ page }) => {
        await expect(page.getByRole('button', { name: 'Add Endpoint' }).last()).toBeVisible();
    });
});

// =============================================================================
// WH-3: Add endpoint — happy path
// =============================================================================

test.describe('WH-3 Add endpoint — happy path', () => {
    test('creates webhook and shows secret reveal modal', async ({ page }) => {
        await page.route('**/api/v1/webhooks', async route => {
            if (route.request().method() === 'GET') {
                await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
            } else if (route.request().method() === 'POST') {
                await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(CREATED_WEBHOOK) });
            } else {
                await route.continue();
            }
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        // Open modal and fill form
        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await page.getByLabel('Endpoint URL').fill(CREATED_WEBHOOK.url);
        await page.getByLabel('HMAC Secret').fill(CREATED_WEBHOOK.secret);
        await page.getByRole('button', { name: 'Add Endpoint' }).last().click();

        // Secret reveal modal appears
        await expect(page.getByTestId('secret-reveal-modal')).toBeVisible();
        await expect(page.getByTestId('webhook-secret-value')).toContainText(CREATED_WEBHOOK.secret);
    });

    test('secret reveal has Copy button', async ({ page }) => {
        await page.route('**/api/v1/webhooks', async route => {
            if (route.request().method() === 'GET') {
                await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
            } else {
                await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(CREATED_WEBHOOK) });
            }
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await page.getByLabel('Endpoint URL').fill(CREATED_WEBHOOK.url);
        await page.getByLabel('HMAC Secret').fill(CREATED_WEBHOOK.secret);
        await page.getByRole('button', { name: 'Add Endpoint' }).last().click();

        await expect(page.getByTestId('secret-reveal-modal')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Copy' })).toBeVisible();
    });

    test('closing secret reveal shows webhook in list', async ({ page }) => {
        let listCallCount = 0;
        await page.route('**/api/v1/webhooks', async route => {
            if (route.request().method() === 'GET') {
                listCallCount++;
                const list = listCallCount === 1 ? [] : [{ ...WEBHOOK_1, id: CREATED_WEBHOOK.id, url: CREATED_WEBHOOK.url }];
                await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(list) });
            } else {
                await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(CREATED_WEBHOOK) });
            }
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await page.getByLabel('Endpoint URL').fill(CREATED_WEBHOOK.url);
        await page.getByLabel('HMAC Secret').fill(CREATED_WEBHOOK.secret);
        await page.getByRole('button', { name: 'Add Endpoint' }).last().click();
        await expect(page.getByTestId('secret-reveal-modal')).toBeVisible();

        await page.getByRole('button', { name: 'Done' }).click();
        await expect(page.getByTestId('secret-reveal-modal')).not.toBeVisible();
        // New URL should now appear in the list (optimistically added before Done was clicked)
        await expect(page.getByText(CREATED_WEBHOOK.url)).toBeVisible();
    });
});

// =============================================================================
// WH-4: Edit webhook
// =============================================================================

test.describe('WH-4 Edit webhook', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/webhooks', route => {
            if (route.request().method() === 'GET') {
                return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_1]) });
            }
            return route.continue();
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
        await expect(page.getByText(WEBHOOK_1.url)).toBeVisible();
    });

    test('Edit button opens modal with URL pre-filled', async ({ page }) => {
        await page.getByRole('button', { name: 'Edit webhook' }).click();
        await expect(page.getByTestId('webhook-modal')).toBeVisible();
        await expect(page.getByLabel('Endpoint URL')).toHaveValue(WEBHOOK_1.url);
    });

    test('Edit modal title is "Edit Webhook"', async ({ page }) => {
        await page.getByRole('button', { name: 'Edit webhook' }).click();
        await expect(page.getByRole('heading', { name: 'Edit Webhook' })).toBeVisible();
    });

    test('description is pre-filled when set', async ({ page }) => {
        await page.getByRole('button', { name: 'Edit webhook' }).click();
        await expect(page.getByLabel('Description')).toHaveValue(WEBHOOK_1.description!);
    });

    test('saving edit calls PUT and shows success toast', async ({ page }) => {
        const updatedUrl = 'https://updated.example.com/hook';
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}`, route => {
            if (route.request().method() === 'PUT') {
                return route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ ...WEBHOOK_1, url: updatedUrl }),
                });
            }
            return route.continue();
        });

        await page.getByRole('button', { name: 'Edit webhook' }).click();
        await page.getByLabel('Endpoint URL').fill(updatedUrl);
        await page.getByRole('button', { name: 'Save Changes' }).click();

        await expect(page.getByText('Webhook updated')).toBeVisible();
        await expect(page.getByTestId('webhook-modal')).not.toBeVisible();
    });
});

// =============================================================================
// WH-5: Delete webhook
// =============================================================================

test.describe('WH-5 Delete webhook', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_1]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
        await expect(page.getByText(WEBHOOK_1.url)).toBeVisible();
    });

    test('Remove button shows confirmation UI', async ({ page }) => {
        await page.getByRole('button', { name: 'Remove webhook' }).click();
        await expect(page.getByText('Remove this webhook? This cannot be undone.')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Remove' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
    });

    test('Cancel dismisses confirmation without deleting', async ({ page }) => {
        await page.getByRole('button', { name: 'Remove webhook' }).click();
        await expect(page.getByText('Remove this webhook? This cannot be undone.')).toBeVisible();
        await page.getByRole('button', { name: 'Cancel' }).last().click();
        await expect(page.getByText('Remove this webhook? This cannot be undone.')).not.toBeVisible();
        await expect(page.getByText(WEBHOOK_1.url)).toBeVisible();
    });

    test('confirming Remove calls DELETE and removes row', async ({ page }) => {
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}`, route => {
            if (route.request().method() === 'DELETE') {
                return route.fulfill({ status: 204 });
            }
            return route.continue();
        });

        await page.getByRole('button', { name: 'Remove webhook' }).click();
        await page.getByRole('button', { name: 'Remove' }).last().click();

        await expect(page.getByText('Webhook removed')).toBeVisible();
        await expect(page.getByText(WEBHOOK_1.url)).not.toBeVisible();
    });
});

// =============================================================================
// WH-6: Test delivery
// =============================================================================

test.describe('WH-6 Test delivery', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_1, WEBHOOK_2]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
    });

    test('Test button is visible for each webhook row', async ({ page }) => {
        const testButtons = page.getByRole('button', { name: 'Send test event' });
        await expect(testButtons).toHaveCount(2);
    });

    test('clicking Test dispatches event and shows success toast', async ({ page }) => {
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}/test`, route =>
            route.fulfill({ status: 202 })
        );

        await page.getByRole('button', { name: 'Send test event' }).first().click();
        await expect(page.getByText('Test event dispatched')).toBeVisible();
    });

    test('Test button shows "Sending…" while in-flight', async ({ page }) => {
        let resolveTest!: () => void;
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}/test`, route =>
            new Promise<void>(resolve => {
                resolveTest = () => { resolve(); route.fulfill({ status: 202 }); };
            })
        );

        await page.getByRole('button', { name: 'Send test event' }).first().click();
        await expect(page.getByText('Sending…')).toBeVisible();
        resolveTest();
        await expect(page.getByText('Test event dispatched')).toBeVisible();
    });

    test('Test failure shows error toast', async ({ page }) => {
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}/test`, route =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'internal error' }) })
        );

        await page.getByRole('button', { name: 'Send test event' }).first().click();
        await expect(page.getByText('Failed to dispatch test event')).toBeVisible();
    });
});

// =============================================================================
// WH-7: Payload format callout (static content)
// =============================================================================

test.describe('WH-7 Payload format callout', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
    });

    test('callout shows X-AuthStar-Signature header example', async ({ page }) => {
        await expect(page.getByText('X-AuthStar-Signature', { exact: false })).toBeVisible();
    });

    test('callout lists all three event types', async ({ page }) => {
        await expect(page.getByText('agent.action.authorized')).toBeVisible();
        await expect(page.getByText('agent.action.denied')).toBeVisible();
        await expect(page.getByText('agent.task.completed')).toBeVisible();
    });

    test('"Payload format" section is always visible even with no webhooks', async ({ page }) => {
        await expect(page.getByText('Payload format (HMAC-SHA256 signed)')).toBeVisible();
    });
});

// =============================================================================
// WH-8: Edge cases — network errors
// =============================================================================

test.describe('WH-8 Edge cases', () => {
    test('network error on load shows error toast', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'server error' }) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');
        await expect(page.getByText('Failed to load webhooks')).toBeVisible();
    });

    test('create API error shows error toast', async ({ page }) => {
        await page.route('**/api/v1/webhooks', async route => {
            if (route.request().method() === 'GET') {
                await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
            } else {
                await route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ message: 'Webhook URL must use the https:// scheme' }) });
            }
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await page.getByLabel('Endpoint URL').fill('https://hooks.example.com/test');
        await page.getByLabel('HMAC Secret').fill('supersecretvalue1234');
        await page.getByRole('button', { name: 'Add Endpoint' }).last().click();

        await expect(page.getByText('Failed to register webhook')).toBeVisible();
    });

    test('delete API error shows error toast', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_1]) })
        );
        await page.route(`**/api/v1/webhooks/${WEBHOOK_1.id}`, route => {
            if (route.request().method() === 'DELETE') {
                return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'internal error' }) });
            }
            return route.continue();
        });
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await expect(page.getByText(WEBHOOK_1.url)).toBeVisible();
        await page.getByRole('button', { name: 'Remove webhook' }).click();
        await page.getByRole('button', { name: 'Remove' }).last().click();
        await expect(page.getByText('Failed to remove webhook')).toBeVisible();
    });

    test('webhook row displays delivery status correctly', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_1]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        // Last delivery status should be rendered (200 was set on WEBHOOK_1)
        await expect(page.getByText('200', { exact: false })).toBeVisible();
    });

    test('webhook with no delivery shows "Never"', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([WEBHOOK_2]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await expect(page.getByText('Never')).toBeVisible();
    });

    test('Escape key closes the Add Endpoint modal', async ({ page }) => {
        await page.route('**/api/v1/webhooks', route =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) })
        );
        await mockAuthAndNavigate(page, '/admin/agents/webhooks');

        await page.getByRole('button', { name: 'Add Endpoint' }).first().click();
        await expect(page.getByTestId('webhook-modal')).toBeVisible();
        await page.keyboard.press('Escape');
        await expect(page.getByTestId('webhook-modal')).not.toBeVisible();
    });
});
