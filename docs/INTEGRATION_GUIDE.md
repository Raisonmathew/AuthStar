# IDaaS Integration Guide - Current Application Status

This guide describes the integration surface that exists in the current repository. It was refreshed on 2026-05-10 against the backend router, SDK package exports, frontend routes, and the updated architecture/API documentation.

For the complete route catalog, see [API_ENDPOINTS.md](API_ENDPOINTS.md). For system boundaries and runtime behavior, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Current Integration Surface

IDaaS can be integrated in four main ways:

| Surface | Current status | Best fit |
|---|---|---|
| Hosted frontend route | Implemented in the React app at `/u/:slug` | Fastest tenant-branded login experience |
| Web Components | Implemented in `@idaas/elements`; uses the current `/api/auth/flow` API | Vue, Angular, Svelte, static HTML, or React apps that want drop-in auth UI |
| React SDK | `@idaas/react` currently exports `IDaaSProvider`, `useIDaaS`, `UserButton`, and manifest types | React apps that need provider context, manifest loading, and a user menu |
| Core TypeScript SDK | `@idaas/core` exports `IDaaSClient`, `IDaaSServerClient`, `FlowManager`, `ManifestCache`, and attestation helpers | Framework-free browser/server integrations and custom auth UI |
| Python SDK | Requests-based server client in `sdks/python` | Server-side automation and backend integrations |
| Go SDK | Standard-library server client in `sdks/go` | Go services and server-to-server integrations |
| Protocol endpoints | OAuth 2.0/OIDC AS, external SSO SP, SAML IdP/SP, SCIM 2.0, API keys, publishable keys | Enterprise identity and provisioning integrations |

### Important SDK Route-Alignment Notes

The backend's current helper authentication routes are:

| Operation | Current backend route |
|---|---|
| Sign up | `POST /api/v1/sign-up` |
| Sign in | `POST /api/v1/sign-in` |
| Logout | `POST /api/v1/logout` |
| Refresh token | `POST /api/v1/token/refresh` |

The current `FlowManager` and sign-in/sign-up web components use the live `/api/auth/flow/*` route family. The `IDaaSClient.signUp`, `IDaaSClient.signIn`, `IDaaSClient.signOut`, Python `sign_up`/`sign_in`/`sign_out`, and Go `SignUp`/`SignIn`/`SignOut` helper methods still point at legacy `/api/v1/auth/*` paths in source. Until those SDK wrappers are patched or released with route-aligned paths, prefer one of these options for browser authentication:

- Use the hosted UI at `/u/:slug`.
- Use `@idaas/elements`, which drives the current flow API.
- Use `FlowManager` directly.
- Call the current helper endpoints directly if you intentionally want the simpler email/password API.

## Base URLs, Keys, and Browser Storage

Development API URL:

```text
http://localhost:3000
```

Development frontend URL:

```text
http://localhost:5173
```

Publishable keys are safe for browser bundles and are used for SDK bootstrap and tenant manifest access. Current SDK code expects this shape:

```text
pk_{env}_{instanceId}
```

Examples:

```text
pk_test_acme
pk_live_acme
```

The React provider maps those keys to hosted domains unless `apiUrl` is provided:

| Key prefix | Derived API URL |
|---|---|
| `pk_test_*` | `https://{instanceId}.idaas-test.dev` |
| `pk_live_*` | `https://{instanceId}.idaas.app` |

For self-hosted and local development, always pass `apiUrl` explicitly.

Browser security model:

- Access JWTs should remain in memory.
- Refresh tokens are HttpOnly cookies set by the backend.
- Browser clients must send credentials/cookies for refresh flows.
- Mutating browser requests use CSRF protection via `/api/csrf-token` and the `X-CSRF-Token` header.
- The frontend stores only the active organization id in `sessionStorage`.

## Recommended Browser Integration

### Option 1: Hosted Login Page

Use the hosted React route when you want IDaaS to own the login UI:

```text
http://localhost:5173/u/{organizationSlug}
```

The hosted page uses the current auth-flow API and tenant branding/configuration from the backend.

### Option 2: Web Components

Use `@idaas/elements` when your application is not React or when you want a drop-in form that already follows the current flow API.

```bash
npm install @idaas/elements
```

```html
<script type="module">
  import '@idaas/elements';
</script>

<idaas-sign-in
  api-url="http://localhost:3000"
  org-id="acme"
></idaas-sign-in>

<script>
  document.querySelector('idaas-sign-in')
    .addEventListener('idaas:success', (event) => {
      console.log('Authentication decision:', event.detail);
      window.location.href = '/dashboard';
    });
</script>
```

Available elements:

| Element | Current behavior | Events |
|---|---|---|
| `<idaas-sign-in>` | Starts `/api/auth/flow/init`, identifies the user, submits password steps, and renders OAuth buttons from the manifest | `idaas:success`, `idaas:error` |
| `<idaas-sign-up>` | Starts a flow and renders manifest-driven signup fields | `idaas:success`, `idaas:error` |
| `<idaas-user-button>` | Loads current user; sign-out currently inherits the core client's legacy sign-out route and should be route-aligned before production use | `idaas:signed-out` |

OAuth buttons generated by the sign-in element redirect to:

```text
/api/auth/sso/{provider}/authorize
```

Supported provider names depend on tenant configuration. The current UI includes Google, GitHub, and Microsoft icons.

### Option 3: React Provider and User Menu

Use `@idaas/react` for app-wide configuration, manifest loading, and the user menu.

```bash
npm install @idaas/react @idaas/core
```

```tsx
import { IDaaSProvider } from '@idaas/react';

export function App() {
  return (
    <IDaaSProvider
      publishableKey="pk_test_acme"
      apiUrl="http://localhost:3000"
    >
      <YourRoutes />
    </IDaaSProvider>
  );
}
```

```tsx
import { UserButton, useIDaaS } from '@idaas/react';
import { useEffect, useState } from 'react';

export function Header() {
  return (
    <nav>
      <UserButton onSignOut={() => { window.location.href = '/'; }} />
    </nav>
  );
}

export function CurrentUserCard() {
  const { client, manifest } = useIDaaS();
  const [user, setUser] = useState<unknown>(null);

  useEffect(() => {
    client.getCurrentUser().then(setUser).catch(() => setUser(null));
  }, [client]);

  return (
    <pre>{JSON.stringify({ user, tenant: manifest?.org_name }, null, 2)}</pre>
  );
}
```

Current React package note: `@idaas/react` does not currently export `SignIn` or `SignUp` React components. Use the hosted page, web components, or `FlowManager` for sign-in/sign-up UI.

## Custom Flow UI With `FlowManager`

`FlowManager` is the current low-level browser API for server-driven authentication flows. It emits DOM-style events so it can be used with any framework.

```ts
import { FlowManager } from '@idaas/core';

const flow = new FlowManager({
  apiUrl: 'http://localhost:3000',
  orgId: 'acme',
});

flow.addEventListener('step', (event) => {
  const { step, manifest, flowId } = (event as CustomEvent).detail;
  console.log('Render next step:', { flowId, step, manifest });
});

flow.addEventListener('decision', (event) => {
  const { decisionRef, achievedAal } = (event as CustomEvent).detail;
  console.log('Flow complete:', { decisionRef, achievedAal });
});

flow.addEventListener('error', (event) => {
  console.error('Flow error:', (event as CustomEvent).detail);
});

await flow.init();
await flow.identify('user@example.com');
await flow.submit('Password', 'securePassword123');
```

Current auth-flow endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/flow/init` | Initialize a flow and return `flow_id`, `flow_token`, manifest, and first UI step |
| `GET` | `/api/auth/flow/:flow_id` | Read flow status |
| `POST` | `/api/auth/flow/:flow_id/identify` | Identify the user by email/username |
| `POST` | `/api/auth/flow/:flow_id/submit` | Submit a credential or factor step |
| `POST` | `/api/auth/flow/:flow_id/complete` | Complete a flow and issue session material where applicable |

All flow requests after initialization require:

```http
Authorization: Bearer {flow_token}
```

Signup flow endpoints are separate:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/signup/flows` | Initialize signup flow |
| `POST` | `/api/signup/flows/:flow_id/submit` | Submit verification step |
| `POST` | `/api/signup/decisions/:decision_ref/commit` | Finalize signup decision; request body includes `flow_id` |

## Core SDK Usage

The framework-agnostic TypeScript client is still useful for manifest, current-user, organization, MFA, billing, and attestation-aware API calls.

```ts
import { IDaaSClient } from '@idaas/core';

const client = new IDaaSClient({
  apiUrl: 'http://localhost:3000',
  apiKey: 'pk_test_acme',
  mode: 'browser',
});

const manifest = await client.getManifest('acme');
const user = await client.getCurrentUser();
const organizations = await client.listOrganizations();
const mfaStatus = await client.getMfaStatus();
```

Server mode stores a bearer token in the client instance instead of relying on browser cookies:

```ts
import { IDaaSServerClient } from '@idaas/core';

const serverClient = new IDaaSServerClient({
  apiUrl: 'http://localhost:3000',
  apiKey: 'sk_or_server_api_key',
});

serverClient.setToken(identityJwt);
const user = await serverClient.getCurrentUser();
```

## Direct API Reference for Integrators

Use [API_ENDPOINTS.md](API_ENDPOINTS.md) for the full reference. The most common integration endpoints are below.

### Helper Authentication

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/sign-up` | Initiate email/password signup |
| `POST` | `/api/v1/sign-in` | Sign in with email/password |
| `POST` | `/api/v1/logout` | Revoke current session |
| `POST` | `/api/v1/token/refresh` | Refresh access JWT from refresh cookie/session |
| `POST` | `/api/v1/auth/step-up` | Submit step-up factor for current session |
| `GET` | `/api/v1/auth/step-up/passkey-challenge` | Create passkey challenge for step-up |

### Current User and Organizations

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/user` | Get current user profile |
| `PATCH` | `/api/v1/user` | Update current user profile |
| `POST` | `/api/v1/user/change-password` | Change current user's password |
| `GET` | `/api/v1/organizations` | List user's organizations |
| `POST` | `/api/v1/organizations` | Create an organization |
| `POST` | `/api/v1/auth/switch-org` | Switch active organization |

### Tenant Manifest and Hosted Configuration

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/sdk/manifest?org_id=:id` | Public tenant manifest for SDK/bootstrap UI |
| `GET` | `/api/hosted/organizations/:slug` | Hosted organization branding/config |
| `POST` | `/api/hosted/auth/flows` | Legacy hosted flow initialization |
| `POST` | `/api/hosted/auth/flows/:flow_id/submit` | Legacy hosted flow step submission |

Manifest responses include only safe client-side fields:

```json
{
  "org_id": "org_123",
  "org_name": "Acme",
  "slug": "acme",
  "version": 42,
  "branding": {
    "logo_url": "https://example.com/logo.png",
    "primary_color": "#2563eb",
    "background_color": "#ffffff",
    "text_color": "#111827",
    "font_family": "Inter"
  },
  "flows": {
    "sign_in": {
      "oauth_providers": [
        { "provider": "google", "label": "Continue with Google", "enabled": true }
      ],
      "passkey_enabled": true,
      "email_password_enabled": true
    },
    "sign_up": {
      "fields": []
    }
  }
}
```

### MFA and Passkeys

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/mfa/totp/setup` | Generate TOTP secret and QR code |
| `POST` | `/api/mfa/totp/verify` | Verify and enable TOTP |
| `POST` | `/api/mfa/totp/challenge` | Verify TOTP during login/challenge |
| `POST` | `/api/mfa/backup-codes` | Generate backup codes |
| `POST` | `/api/mfa/backup-codes/verify` | Verify and consume backup code |
| `GET` | `/api/mfa/status` | Get MFA status |
| `POST` | `/api/mfa/disable` | Disable MFA |
| `POST` | `/api/passkeys/authenticate/start` | Start public passkey authentication |
| `POST` | `/api/passkeys/authenticate/finish` | Finish public passkey authentication |
| `POST` | `/api/passkeys/register/start` | Start protected passkey enrollment |
| `POST` | `/api/passkeys/register/finish` | Finish protected passkey enrollment |
| `GET` | `/api/passkeys` | List current user's passkeys |
| `DELETE` | `/api/passkeys/:credential_id` | Delete a passkey |

### SSO, OAuth 2.0, OIDC, SAML, and SCIM

| Surface | Endpoints | Purpose |
|---|---|---|
| External OAuth/OIDC SSO | `/api/auth/sso/:provider/authorize`, `/api/auth/sso/:provider/callback` | Sign in to IDaaS with providers such as Google, GitHub, and Microsoft |
| SAML SP login | `/api/auth/sso/saml/*` | Sign in to IDaaS using an enterprise SAML identity provider |
| OAuth 2.0/OIDC AS | `/oauth/*`, `/.well-known/*`, `/api/oauth/*` | IDaaS acts as an authorization server for customer applications |
| SAML IdP | `/api/saml/idp/:tenant_id/*` | IDaaS issues SAML responses to service providers |
| SCIM 2.0 | `/scim/v2/*`, `/api/admin/v1/scim/*` | Inbound user/group provisioning and admin token/config management |

Common OAuth/OIDC endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/oauth/authorize` | Authorization endpoint |
| `POST` | `/oauth/token` | Token endpoint |
| `POST` | `/oauth/revoke` | Token revocation |
| `POST` | `/oauth/introspect` | Token introspection |
| `GET` | `/oauth/userinfo` | OIDC UserInfo |
| `POST` | `/oauth/par` | Pushed Authorization Request |
| `POST` | `/oauth/device_authorization` | Device authorization grant |
| `POST` | `/oauth/register` | Dynamic client registration |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/jwks.json` | JWKS |

### API Keys, Billing, and Decisions

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/api-keys` | List API keys |
| `POST` | `/api/v1/api-keys` | Create API key |
| `DELETE` | `/api/v1/api-keys/:id` | Revoke API key |
| `GET` | `/api/v1/publishable-keys` | List publishable keys |
| `POST` | `/api/v1/publishable-keys` | Create publishable key |
| `DELETE` | `/api/v1/publishable-keys/:id` | Revoke publishable key |
| `GET` | `/api/billing/v1/subscription` | Get subscription |
| `GET` | `/api/billing/v1/invoices` | List invoices |
| `POST` | `/api/billing/v1/checkout` | Create Stripe checkout session |
| `POST` | `/api/billing/v1/portal` | Create Stripe customer portal session |
| `POST` | `/api/billing/v1/webhook` | Stripe webhook handler |
| `GET` | `/api/decisions/:decision_ref` | Read EIAA decision details |
| `GET` | `/api/decisions/:decision_ref/verify` | Verify decision attestation |

## Authorization Model: EIAA, Not JWT Permissions

EIAA means Entitlement-Independent Authentication Architecture in this codebase.

The important invariant for integrators is simple: IDaaS session JWTs are identity-only. They carry subject, tenant/session context, issuer, audience, expiry, and related identity claims. They do not carry roles, permissions, scopes, or entitlements for IDaaS protected operations.

Authorization happens server-side:

1. The API verifies the identity JWT and active session.
2. Route middleware maps the request to an EIAA action.
3. Risk, tenant, subject, session, and request context are evaluated.
4. The EIAA runtime executes a signed WASM policy capsule.
5. The decision is audited and may return allow, deny, or step-up required.

Client-side checks are acceptable only for UI convenience, such as hiding a navigation item. They are not security controls.

Avoid patterns like this:

```ts
const payload = JSON.parse(atob(token.split('.')[1]));
const permissions = payload.org_permissions;
```

Instead, call the relevant backend endpoint and let `EiaaAuthzLayer` enforce the operation. If an operation requires additional proof, the backend returns a step-up error such as `AUTH_STEP_UP_REQUIRED`.

## EIAA Attestation Verification

Responses that include EIAA attestations can be cryptographically verified with runtime public keys from:

```text
GET /api/eiaa/v1/runtime/keys
```

The core SDK verifies attestations automatically when a response contains an `attestation` field. The default is fail-closed if runtime keys cannot be loaded.

```ts
import { IDaaSClient } from '@idaas/core';

const client = new IDaaSClient({
  apiUrl: 'http://localhost:3000',
  verifyAttestations: true,
  runtimeKeyTtlMs: 10 * 60 * 1000,
});
```

For manual verification:

```ts
import { AttestationVerifier } from '@idaas/core';

const verifier = new AttestationVerifier();
await verifier.initFromKeys(runtimeKeys);

const result = await verifier.verify(attestation);
if (!result.valid) {
  throw new Error(result.error ?? 'Invalid EIAA attestation');
}
```

Important implementation detail: canonical body serialization uses lexicographically sorted keys to match Rust's `BTreeMap` behavior.

## Server-Side SDKs

### Python

```python
from idaas import IDaaSClient

client = IDaaSClient(
    api_url="http://localhost:3000",
    api_key="server-or-publishable-key"
)

client.set_token(identity_jwt)
user = client.get_current_user()
orgs = client.list_organizations()
manifest = client.get_manifest(org_id="acme")
```

Current status: Python helper methods for `sign_up`, `sign_in`, and `sign_out` still use legacy `/api/v1/auth/*` paths in source. For current backend compatibility, use direct requests to `/api/v1/sign-up`, `/api/v1/sign-in`, and `/api/v1/logout`, or update those wrapper paths before relying on them.

### Go

```go
package main

import "github.com/idaas/go-sdk"

func main() {
    client := idaas.NewClient("http://localhost:3000", "server-or-publishable-key")
    client.SetToken(identityJwt)

    user, err := client.GetCurrentUser()
    if err != nil {
        panic(err)
    }

    _, _ = user, err
}
```

Current status: Go helper methods for `SignUp`, `SignIn`, and `SignOut` still use legacy `/api/v1/auth/*` paths in source. For current backend compatibility, call the current helper endpoints directly or update those wrapper paths before relying on them.

## Admin and Enterprise Integrations

Administrative configuration lives under `/api/admin/v1/*` and is protected by admin session checks plus EIAA actions. Current admin surfaces include:

- Applications/OAuth clients.
- API keys and publishable keys.
- SSO connections and SAML metadata import.
- LDAP/Active Directory connections and mappers.
- SCIM token/config/event administration.
- Users, groups, roles, required actions, lockout, and password policy management.
- Policy builder, EIAA audit, billing, domains, branding, and security settings.

Enterprise protocols:

- Use OAuth 2.0/OIDC when applications need delegated authorization, ID tokens, UserInfo, consent, device flow, PAR, or dynamic registration.
- Use SAML IdP endpoints when IDaaS must authenticate users into SAML service providers.
- Use SAML SP or external OIDC SSO endpoints when IDaaS should accept an enterprise identity provider as an upstream authenticator.
- Use SCIM when an enterprise customer needs automated user/group provisioning into IDaaS.

## Deployment Checklist

- Set `apiUrl` for self-hosted or local deployments.
- Configure `ALLOWED_ORIGINS` for browser clients.
- Serve browser clients and API over HTTPS in production so cookies can use `Secure`.
- Configure refresh-cookie domain/path for your production topology.
- Confirm `/api/csrf-token` is reachable from browser clients.
- Confirm `/api/eiaa/v1/runtime/keys` is reachable for attestation verification.
- Configure `PASSKEY_RP_ID` and `PASSKEY_ORIGIN` before enabling passkeys in production-like environments.
- Configure `FACTOR_ENCRYPTION_KEY` before enabling TOTP/MFA in production-like environments.
- Configure `COMPILER_SK_B64` before relying on EIAA capsule signing in production-like environments.
- Configure Stripe keys and verify `/api/billing/v1/webhook` is reachable if billing is enabled.
- Test OAuth/OIDC redirect URIs, SAML metadata, and SCIM bearer tokens per tenant before go-live.

## Troubleshooting

### `401 Unauthorized`

Common causes:

- The access JWT expired and refresh failed.
- Browser cookies are not being sent because `withCredentials`/CORS/cookie domain settings are wrong.
- Server-side SDK code did not call `setToken(jwt)` before an authenticated request.

Browser check:

```ts
await client.refreshToken();
const user = await client.getCurrentUser();
```

### `403 AUTH_STEP_UP_REQUIRED`

The request reached a protected route, but EIAA policy requires stronger proof. Trigger the step-up UI and submit an allowed factor through:

```text
POST /api/v1/auth/step-up
```

### CSRF failures

Fetch a CSRF token first and include it on mutating browser requests:

```text
GET /api/csrf-token
X-CSRF-Token: {token}
```

The core browser client caches CSRF tokens from cookies when available.

### Attestation failures

Check these first:

- Runtime public keys are fetched from `/api/eiaa/v1/runtime/keys`.
- Response body canonicalization matches lexicographically sorted key ordering.
- Runtime keys are not stale; force a key reload if an unknown runtime key is reported.
- System clocks are close enough for attestation expiry checks.

### Web Components do not render

Make sure the elements module is imported before custom elements are used:

```html
<script type="module">
  import '@idaas/elements';
</script>

<idaas-sign-in api-url="http://localhost:3000" org-id="acme"></idaas-sign-in>
```

### React `SignIn` or `SignUp` import fails

That is expected with the current package. `@idaas/react` exports `IDaaSProvider`, `useIDaaS`, and `UserButton`; use `@idaas/elements`, `FlowManager`, or the hosted `/u/:slug` route for sign-in and sign-up UI.

## Further Reading

- [API_ENDPOINTS.md](API_ENDPOINTS.md) - route-level API reference.
- [ARCHITECTURE.md](ARCHITECTURE.md) - current application architecture.
- [SYSTEM_DESIGN_UML.md](SYSTEM_DESIGN_UML.md) - visual system design diagrams.
- [../sdks/react/README.md](../sdks/react/README.md) - React SDK package notes.
- [../sdks/python/README.md](../sdks/python/README.md) - Python SDK package notes.
- [../sdks/go/README.md](../sdks/go/README.md) - Go SDK package notes.
