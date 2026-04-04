# Integration Guide: Adding IDaaS to Your Application

Complete guide for integrating the IDaaS Platform into your application using the official SDKs.

## SDK Overview

| SDK | Package | Use Case |
|-----|---------|----------|
| **@idaas/core** | `sdks/core` | Framework-agnostic TypeScript/JS client |
| **@idaas/react** | `sdks/react` | React components + context provider |
| **@idaas/elements** | `sdks/elements` | Framework-free web components (`<idaas-sign-in>`) |
| **idaas-client** | `sdks/python` | Python server-side integration |
| **go-sdk** | `sdks/go` | Go server-side integration |

---

## 🚀 Quick Start — React (5 Minutes)

### 1. Install the SDK

```bash
npm install @idaas/react @idaas/core
```

### 2. Wrap Your App with IDaaSProvider

```tsx
// src/main.tsx
import { IDaaSProvider } from '@idaas/react';

function App() {
  return (
    <IDaaSProvider
      publishableKey="pk_test_your-instance-id"
      apiUrl="http://localhost:3000"  // optional for self-hosted
    >
      <YourAppRoutes />
    </IDaaSProvider>
  );
}
```

**Publishable Key Format:**
- Test: `pk_test_{instanceId}` → resolves to `https://{instanceId}.idaas-test.dev`
- Live: `pk_live_{instanceId}` → resolves to `https://{instanceId}.idaas.app`
- When `apiUrl` is provided, it overrides the key-derived URL (use for self-hosted / local dev).

### 3. Use the Hook

```tsx
import { useIDaaS } from '@idaas/react';

function Dashboard() {
  const { client } = useIDaaS();
  const [user, setUser] = useState(null);

  useEffect(() => {
    client.getCurrentUser().then(setUser);
  }, [client]);

  return <p>Welcome, {user?.email}</p>;
}
```

### 4. Add the UserButton

```tsx
import { UserButton } from '@idaas/react';

function Header() {
  return (
    <nav>
      <UserButton
        showEmail={true}
        showName={true}
        theme="light"
        onSignOut={() => window.location.href = '/'}
      />
    </nav>
  );
}
```

---

## 🌐 Quick Start — Web Components (Any Framework)

For Vue, Angular, Svelte, or plain HTML — use `@idaas/elements`:

```html
<script type="module">
  import '@idaas/elements';
</script>

<!-- Drop-in sign-in form -->
<idaas-sign-in
  api-url="https://api.example.com"
  org-id="my-org"
></idaas-sign-in>

<script>
  document.querySelector('idaas-sign-in')
    .addEventListener('idaas:success', (e) => {
      console.log('Signed in:', e.detail);
      window.location.href = '/dashboard';
    });
</script>
```

**Available Components:**

| Element | Purpose | Events |
|---------|---------|--------|
| `<idaas-sign-in>` | Sign-in form with OAuth + passkey support | `idaas:success`, `idaas:error` |
| `<idaas-sign-up>` | Sign-up form with dynamic fields from manifest | `idaas:success`, `idaas:error` |
| `<idaas-user-button>` | User menu with sign-out | `idaas:signed-out` |

All components render inside Shadow DOM with theme support via CSS custom properties.

---

## 📚 Core SDK — Framework-Agnostic Integration

### Initialize the Client

```typescript
import { IDaaSClient } from '@idaas/core';

const client = new IDaaSClient({
  apiUrl: 'http://localhost:3000',
  apiKey: 'your-api-key',        // optional, for server-side
  mode: 'browser',               // 'browser' (default) or 'server'
});
```

In **browser** mode, the client uses httpOnly cookies for refresh tokens. In **server** mode, use `client.setToken(jwt)` for token management.

### Authentication

```typescript
// Sign up
await client.signUp({
  email: 'user@example.com',
  password: 'securePassword123',
  firstName: 'Jane',
  lastName: 'Doe',
});

// Sign in
const result = await client.signIn({
  identifier: 'user@example.com',
  password: 'securePassword123',
});
// result: { user, sessionId, jwt, mfaRequired?, challengeToken? }

// Get current user
const user = await client.getCurrentUser();

// Sign out
await client.signOut();

// Refresh token
await client.refreshToken();
```

### Organizations (Multi-Tenant)

```typescript
// List user's organizations
const orgs = await client.listOrganizations();

// Create organization
const org = await client.createOrganization('Acme Corp', 'acme-corp');

// Get organization details
const details = await client.getOrganization(orgId);
```

### MFA

```typescript
// Setup TOTP — returns QR code URI + secret
const setup = await client.setupTotp();
// setup: { qrCodeUri, secret, manualEntryKey }

// Verify TOTP code to enable MFA
await client.verifyTotp('123456');

// Check MFA status
const status = await client.getMfaStatus();
```

### Billing

```typescript
// Get subscription
const sub = await client.getSubscription();

// Create checkout session (redirects to Stripe)
const checkout = await client.createSubscription(priceId);
```

### Tenant Manifest

The manifest API provides dynamic branding and flow configuration per tenant:

```typescript
const manifest = await client.getManifest(orgId);
// manifest: { org_id, org_name, slug, version, branding, flows }
```

Response includes:
- **branding**: `logo_url`, `primary_color`, `background_color`, `text_color`, `font_family`
- **flows.sign_in**: `oauth_providers[]`, `passkey_enabled`, `email_password_enabled`
- **flows.sign_up**: `fields[]` (dynamic form fields with type, label, required, order)

This endpoint is public and cacheable (`Cache-Control: public, max-age=60, stale-while-revalidate=300`).

---

## 🔐 EIAA Flow Engine (Advanced)

The Evaluative Identity Attestation Architecture provides stateful, server-driven authentication flows.

### Using FlowManager

```typescript
import { FlowManager } from '@idaas/core';

const flow = new FlowManager({
  apiUrl: 'http://localhost:3000',
  orgId: 'my-org',
});

// Listen for events
flow.addEventListener('step', (e) => {
  console.log('Next step:', e.detail); // Render UI for this step
});

flow.addEventListener('decision', (e) => {
  console.log('Flow complete:', e.detail); // User authenticated
});

flow.addEventListener('error', (e) => {
  console.error('Flow error:', e.detail);
});

// Start flow
await flow.init();

// Identify user
await flow.identify('user@example.com');

// Submit credential
await flow.submit('password', 'securePassword123');
```

### Flow Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/flow/init` | Initialize flow → returns `flow_id` + `flow_token` |
| GET | `/api/auth/flow/{flowId}` | Get flow status |
| POST | `/api/auth/flow/{flowId}/identify` | Identify user by email |
| POST | `/api/auth/flow/{flowId}/submit` | Submit credential (password, OTP, etc.) |
| POST | `/api/auth/flow/{flowId}/complete` | Complete flow → issue JWT + session cookies |

All flow requests after init require `Authorization: Bearer {flowToken}`. The flow token is ephemeral and validated server-side with SHA-256 + constant-time comparison.

### Signup Flow Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/signup/flows` | Initialize signup flow |
| POST | `/api/signup/flows/{flowId}/submit` | Submit verification step |
| POST | `/api/signup/decisions/{ref}/commit` | Finalize signup (requires `flow_id` in body) |

---

## 🐍 Python SDK

```python
from idaas import IDaaSClient

client = IDaaSClient(
    api_url="https://api.example.com",
    api_key="your-api-key"  # optional
)

# Authentication
result = client.sign_in(identifier="user@example.com", password="secret")
client.set_token(result["jwt"])

# User
user = client.get_current_user()

# Organizations
orgs = client.list_organizations()
org = client.create_organization(name="Acme Corp", slug="acme-corp")

# MFA
setup = client.setup_totp()
client.verify_totp("123456")

# Manifest
manifest = client.get_manifest(org_id="org-id")
```

**Data classes:** `User` (id, email, first_name, last_name, email_verified, mfa_enabled), `Organization` (id, name, slug, created_at).

**Requirements:** Python ≥ 3.8, `requests ≥ 2.31.0`

---

## 🔵 Go SDK

```go
package main

import "github.com/idaas/go-sdk"

func main() {
    client := idaas.NewClient("https://api.example.com", "your-api-key")

    // Sign in
    result, _ := client.SignIn(idaas.SignInRequest{
        Identifier: "user@example.com",
        Password:   "secret",
    })
    client.SetToken(result["jwt"].(string))

    // Get current user
    user, _ := client.GetCurrentUser()

    // Organizations
    orgs, _ := client.ListOrganizations()
    org, _ := client.CreateOrganization("Acme Corp", "acme-corp")

    // Manifest
    manifest, _ := client.GetManifest("org-id")
}
```

**Dependencies:** Go standard library only.

---

## 🔐 EIAA Attestation Verification

Verify the cryptographic attestation signatures returned by the EIAA runtime to ensure responses haven't been tampered with.

### Browser (TypeScript)

```typescript
import { verifyAttestation, initAttestationVerifierFromKeys } from '@idaas/core';

// Initialize verifier with runtime public keys
await initAttestationVerifierFromKeys(runtimeKeys);

// Verify attestation on any response
const result = await verifyAttestation(response.attestation, expectedNonce);
if (!result.valid) {
  throw new Error('Security Alert: Invalid attestation signature!');
}
```

**Important:** Body serialization uses lexicographically sorted keys (alphabetical order) to match Rust's `BTreeMap` behavior.

### Auto-Verification Interceptor

The built-in `APIClient` in `frontend/src/lib/api/client.ts` already handles attestation verification automatically:
- Prefetches runtime public keys (10-minute TTL cache)
- Verifies Ed25519 signatures on all responses containing attestations
- Dispatches `auth:step-up-required` custom events on 403 responses

---

## 📡 Complete API Reference

### Authentication (`/api/v1/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sign-up` | Create account (sends verification email) |
| POST | `/api/v1/sign-in` | Authenticate with email/password |
| POST | `/api/v1/logout` | Revoke session |
| POST | `/api/v1/token/refresh` | Refresh JWT via httpOnly cookie |
| GET | `/api/v1/user` | Get current user |
| PATCH | `/api/v1/user` | Update profile |
| POST | `/api/v1/user/change-password` | Change password |
| POST | `/api/v1/verify` | Verify email address |

### MFA (`/api/mfa/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/mfa/totp/setup` | Generate TOTP secret + QR code |
| POST | `/api/mfa/totp/verify` | Verify TOTP code + enable MFA |
| POST | `/api/mfa/totp/challenge` | Verify TOTP during login |
| POST | `/api/mfa/backup-codes` | Generate backup codes |
| POST | `/api/mfa/backup-codes/verify` | Verify + consume backup code |
| GET | `/api/mfa/status` | Get MFA status |
| POST | `/api/mfa/disable` | Disable MFA (requires TOTP code) |

### Passkeys (`/api/v1/passkeys/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/passkeys/register/start` | Start WebAuthn registration |
| POST | `/api/v1/passkeys/register/finish` | Complete registration |
| POST | `/api/v1/passkeys/start` | Start passkey authentication |
| POST | `/api/v1/passkeys/finish` | Complete authentication |
| GET | `/api/v1/passkeys` | List user's passkeys |
| DELETE | `/api/v1/passkeys/{credentialId}` | Delete passkey |

### Organizations (`/api/v1/organizations/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations` | List user's organizations |
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations/{id}` | Get organization details |
| POST | `/api/v1/organizations/{id}/switch` | Switch active organization |

### Billing (`/api/billing/v1/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/billing/v1/subscription` | Get subscription |
| GET | `/api/billing/v1/invoices` | List invoices |
| POST | `/api/billing/v1/checkout` | Create Stripe checkout session |
| POST | `/api/billing/v1/subscription/cancel` | Cancel subscription |
| POST | `/api/billing/v1/portal` | Create Stripe customer portal |
| POST | `/api/billing/v1/webhook` | Stripe webhook (signature verified) |

### Hosted Pages (`/api/hosted/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/hosted/organizations/{slug}` | Get org branding + config |

### SDK Manifest

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sdk/manifest?org_id={id}` | Get tenant manifest (public, cacheable) |

---

## 🏢 Multi-Tenant Integration Pattern

### React — Organization Context

```tsx
import { useIDaaS } from '@idaas/react';
import { useState, useEffect, createContext, useContext } from 'react';

interface OrgContextType {
  organizations: Organization[];
  activeOrg: Organization | null;
  switchOrg: (orgId: string) => void;
}

const OrgContext = createContext<OrgContextType | undefined>(undefined);

export function OrganizationProvider({ children }: { children: React.ReactNode }) {
  const { client } = useIDaaS();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);

  useEffect(() => {
    client.listOrganizations().then((orgs) => {
      setOrganizations(orgs);
      if (orgs.length > 0) setActiveOrg(orgs[0]);
    });
  }, [client]);

  const switchOrg = (orgId: string) => {
    const org = organizations.find(o => o.id === orgId);
    if (org) setActiveOrg(org);
  };

  return (
    <OrgContext.Provider value={{ organizations, activeOrg, switchOrg }}>
      {children}
    </OrgContext.Provider>
  );
}

export const useOrganization = () => {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error('useOrganization must be within OrganizationProvider');
  return ctx;
};
```

### Permission-Based Access

Permissions are included in JWT claims. Parse them client-side:

```typescript
function usePermissions() {
  const { client } = useIDaaS();
  const token = client.getToken();

  if (!token) return { hasPermission: () => false };

  const payload = JSON.parse(atob(token.split('.')[1]));
  const permissions: string[] = payload.org_permissions || [];

  const hasPermission = (perm: string) =>
    permissions.includes(perm) || permissions.includes('*');

  return { permissions, hasPermission };
}

// Usage
function TeamSettings() {
  const { hasPermission } = usePermissions();
  if (!hasPermission('team:manage')) return <p>Access denied</p>;
  return <TeamManagementUI />;
}
```

---

## ⚠️ Security Best Practices

1. **Never store JWT in `localStorage` or `sessionStorage`** — the IDaaS frontend stores JWT in memory only. Refresh tokens use httpOnly cookies.
2. **Always verify attestations** — EIAA responses include Ed25519 signatures. The built-in API client verifies these automatically.
3. **Use publishable keys, not secret keys, in client code** — publishable keys (`pk_test_*`, `pk_live_*`) are safe to expose in browser bundles.
4. **Validate on the server** — never trust client-side permission checks alone. The backend enforces RBAC via the `EiaaAuthzLayer` middleware.

---

## 🚀 Deployment Checklist

- [ ] Set production API URL (`apiUrl` or publishable key)
- [ ] Configure CORS on backend (`ALLOWED_ORIGINS` in `.env`)
- [ ] Verify HTTPS is enforced (session cookies require `Secure` flag)
- [ ] Set `SESSION_COOKIE_DOMAIN` to your production domain
- [ ] Test token refresh flow (httpOnly cookie must be sent cross-origin)
- [ ] Test MFA enrollment + challenge flow
- [ ] Verify attestation verification is working
- [ ] Test passkey registration on target devices
- [ ] Verify Stripe webhook endpoint is accessible

---

## 🔍 Troubleshooting

### "401 Unauthorized" errors

The JWT may be expired (15-minute expiry). The SDK auto-refreshes via httpOnly cookie, but verify:

```typescript
const { client } = useIDaaS();

// Force refresh
await client.refreshToken();

// Check if token exists
const token = client.getToken();
console.log('Has token:', !!token);
```

### CORS errors

Configure the backend's `ALLOWED_ORIGINS` environment variable:

```env
ALLOWED_ORIGINS=https://your-app.com,https://www.your-app.com
```

Ensure `withCredentials: true` is set (the SDK does this automatically).

### EIAA attestation failures

1. Ensure runtime public keys are fetched: the API client calls `/api/v1/runtime/keys`
2. Check that response body serialization matches (alphabetical key order)
3. Verify system clocks are in sync (attestations have `expires_at_unix`)

### Web Components not rendering

Ensure you import the elements module before using the tags:

```html
<script type="module">
  import '@idaas/elements';
</script>
<!-- Components must be used AFTER the import -->
<idaas-sign-in api-url="..." org-id="..."></idaas-sign-in>
```

---

## 📚 Further Reading

- [Architecture Overview](ARCHITECTURE.md)
- [Technical Overview](TECHNICAL_OVERVIEW.md)
- [React SDK README](../sdks/react/README.md)
- [Publishable Keys](../sdks/react/PUBLISHABLE_KEYS.md)
- [Go SDK README](../sdks/go/README.md)
- [Python SDK README](../sdks/python/README.md)
