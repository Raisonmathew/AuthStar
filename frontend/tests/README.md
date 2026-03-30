# E2E Testing Guide

## Overview

This directory contains end-to-end (E2E) tests for the AuthStar IDaaS platform using Playwright. The tests cover authentication flows, user management, admin features, and the Policy Builder.

## Running Tests

### Prerequisites

```bash
cd frontend
npm install
```

### Run All Tests (Headless)

```bash
npm test
```

### Run Tests with Browser Visibility (Headed Mode)

To see the browser while tests are running:

```bash
npm test -- --headed
```

This will:
- Open a visible browser window
- Slow down actions by 100ms for better visibility
- Show each step as it executes
- Useful for debugging and understanding test flows

### Run Specific Test File

```bash
npm test tests/user/profile.spec.ts
npm test tests/admin/api-keys.spec.ts
```

### Run Tests in Debug Mode

Step through tests line by line:

```bash
npm test -- --debug
```

### Run Tests in UI Mode

Interactive test runner with time-travel debugging:

```bash
npm run test:ui
```

### Run Tests in Specific Browser

```bash
npm test -- --project=chromium
npm test -- --project=firefox
npm test -- --project=webkit
```

## Test Structure

```
tests/
├── fixtures/
│   └── test-utils.ts          # Shared test utilities and helpers
├── auth/
│   ├── admin-login.spec.ts    # Admin authentication flows
│   ├── user-login.spec.ts     # User authentication flows
│   └── step-up-requirement.spec.ts  # Step-up authentication
├── user/
│   ├── profile.spec.ts        # User profile management
│   └── mfa.spec.ts            # MFA enrollment and management
├── admin/
│   ├── admin-console.spec.ts  # Admin console navigation
│   ├── api-keys.spec.ts       # API keys management
│   ├── policy-builder.spec.ts # Policy Builder features
│   ├── organization.spec.ts   # Organization settings
│   └── billing.spec.ts        # Billing and subscriptions
├── protection/
│   └── route-guards.spec.ts   # Route protection and guards
└── tenant/
    └── tenant-login.spec.ts   # Multi-tenant authentication
```

## Test Utilities

### Available Helpers

```typescript
import { 
  test, 
  expect, 
  loginAsAdmin, 
  loginAsUser, 
  clearSession,
  getSessionStorageItem 
} from '../fixtures/test-utils';
```

- `loginAsAdmin(page)` - Authenticate as system admin
- `loginAsUser(page)` - Authenticate as regular user
- `clearSession(page)` - Clear all session data
- `getSessionStorageItem(page, key)` - Read session storage

### Example Test

```typescript
test('can update profile', async ({ page }) => {
  await loginAsUser(page);
  await page.goto('/profile');
  
  await page.fill('input[name="first_name"]', 'John');
  await page.click('button[type="submit"]');
  
  await expect(page.locator('text=/success/i')).toBeVisible();
});
```

## Configuration

### Playwright Config (`playwright.config.ts`)

Key settings:
- **Headed Mode**: Enabled by default in development (`--headed` flag)
- **Slow Motion**: 100ms delay between actions in headed mode
- **Screenshots**: Captured on failure
- **Videos**: Recorded on failure
- **Trace**: Captured on first retry

### Environment Variables

```bash
# CI mode (headless, no slow motion)
CI=true npm test

# Custom base URL
BASE_URL=http://localhost:3000 npm test
```

## Test Coverage

### Current Coverage (After Updates)

| Category | Tests | Coverage |
|----------|-------|----------|
| Authentication | 8 | ✅ High |
| User Profile | 5 | ✅ High |
| MFA Management | 7 | ✅ High |
| API Keys | 7 | ✅ High |
| Policy Builder | 13 | ✅ High |
| Organization | 11 | ✅ High |
| Billing | 11 | ✅ High |
| Route Protection | 3 | ✅ Medium |
| **Total** | **65+** | **~60%** |

### Missing Coverage (Future Work)

- Passkeys/WebAuthn flows
- SSO connections (OAuth/SAML)
- Custom domains management
- Audit log verification
- EIAA capsule execution
- Hosted auth flows
- Advanced policy features

## Best Practices

### 1. Use Semantic Selectors

```typescript
// ✅ Good - semantic and resilient
await page.click('button:has-text("Save")');
await page.locator('[data-testid="submit-button"]').click();

// ❌ Bad - brittle
await page.click('.btn-primary.mt-4');
```

### 2. Wait for Elements

```typescript
// ✅ Good - explicit wait
await page.waitForSelector('input[name="email"]');
await page.fill('input[name="email"]', 'user@example.com');

// ❌ Bad - race condition
await page.fill('input[name="email"]', 'user@example.com');
```

### 3. Use test.skip() for Conditional Tests

```typescript
test('can enable feature', async ({ page }) => {
  const featureToggle = page.locator('button:has-text("Enable")');
  
  if (!await featureToggle.isVisible({ timeout: 2000 })) {
    test.skip(); // Feature already enabled
  }
  
  await featureToggle.click();
});
```

### 4. Clean Up After Tests

```typescript
test.beforeEach(async ({ page }) => {
  await clearSession(page);
});

test.afterEach(async ({ page }) => {
  // Clean up test data if needed
});
```

## Debugging

### View Test Report

```bash
npm run test:report
```

### Enable Verbose Logging

```bash
DEBUG=pw:api npm test
```

### Pause Test Execution

```typescript
test('debug test', async ({ page }) => {
  await page.goto('/profile');
  await page.pause(); // Opens Playwright Inspector
});
```

### Take Screenshots

```typescript
await page.screenshot({ path: 'debug.png' });
```

## CI/CD Integration

Tests run automatically in CI with:
- Headless mode
- 2 retries on failure
- Single worker (no parallelization)
- HTML report generation

### GitHub Actions Example

```yaml
- name: Run E2E Tests
  run: |
    cd frontend
    npm ci
    npm test
  env:
    CI: true
```

## Troubleshooting

### Tests Timing Out

Increase timeout in test:
```typescript
test('slow operation', async ({ page }) => {
  test.setTimeout(60000); // 60 seconds
  // ... test code
});
```

### Flaky Tests

1. Add explicit waits
2. Use `waitForLoadState('networkidle')`
3. Increase timeout for specific selectors
4. Check for race conditions

### Browser Not Visible

Ensure you're using the `--headed` flag:
```bash
npm test -- --headed
```

## Contributing

When adding new tests:

1. Follow existing test structure
2. Use descriptive test names
3. Add comments for complex logic
4. Update this README if adding new test categories
5. Ensure tests are idempotent (can run multiple times)

## Resources

- [Playwright Documentation](https://playwright.dev)
- [Best Practices](https://playwright.dev/docs/best-practices)
- [Debugging Guide](https://playwright.dev/docs/debug)