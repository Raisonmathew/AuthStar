# IDaaS API Endpoints Reference

Comprehensive documentation of all public API endpoints in the IDaaS backend.

**Base URL**: `http://localhost:3000` (development) / Production URL varies by deployment

**API Version**: v1

**Route source**: validated against `backend/crates/api_server/src/router.rs` and route modules on 2026-05-10.

> Current mount notes: authentication flows are mounted under `/api/auth/flow`, SSO under `/api/auth/sso`, EIAA under `/api/eiaa/v1`, billing under `/api/billing/v1`, MFA under `/api/mfa`, passkeys under `/api/passkeys`, domains under `/api/domains`, and decision lookups under `/api/decisions`.

---

## Table of Contents

- [Authentication & Authorization](#authentication--authorization)
- [Action Tokens](#action-tokens)
- [User Management](#user-management)
- [Credentials & Required Actions](#credentials--required-actions)
- [Organizations & Tenants](#organizations--tenants)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [Passkeys (WebAuthn)](#passkeys-webauthn)
- [SSO & OAuth](#sso--oauth)
- [OAuth 2.0 Authorization Server](#oauth-20-authorization-server)
- [SAML IdP & SCIM](#saml-idp--scim)
- [EIAA (Policy Execution)](#eiaa-policy-execution)
- [Policy Builder](#policy-builder)
- [Billing & Subscriptions](#billing--subscriptions)
- [Roles & Permissions](#roles--permissions)
- [API Keys & Publishable Keys](#api-keys--publishable-keys)
- [Admin Endpoints](#admin-endpoints)
- [Invitations](#invitations)
- [Custom Domains](#custom-domains)
- [Decisions & Verification](#decisions--verification)

---

## Authentication & Authorization

### Public Authentication Routes

| Method | Path | Description | Auth Required | Request Body | Response |
|--------|------|-------------|---------------|--------------|----------|
| `POST` | `/api/v1/sign-up` | Initiate user signup | No | `HelperSignupRequest` | `HelperSignupResponse` |
| `POST` | `/api/v1/sign-in` | Sign in with email/password | No | `HelperSigninRequest` | `HelperSigninResponse` |
| `POST` | `/api/v1/logout` | Log out current session | Yes (JWT) | - | - |
| `POST` | `/api/v1/token/refresh` | Refresh JWT token using refresh cookie/session | Refresh cookie/session | - | `HelperRefreshResponse` |

#### Request/Response Types

**HelperSignupRequest**
```json
{
  "email": "string (email)",
  "password": "string (min 8 chars)",
  "firstName": "string (optional)",
  "lastName": "string (optional)",
  "deviceSignals": "object (optional)",
  "org_slug": "string (optional)"
}
```

**HelperSigninRequest**
```json
{
  "identifier": "string (email/username)",
  "password": "string",
  "tenantId": "string (optional)",
  "deviceSignals": "object (optional)"
}
```

**HelperSigninResponse**
```json
{
  "user": "UserResponse",
  "sessionId": "string",
  "jwt": "string",
  "decisionRef": "string"
}
```

### Authentication Flow (EIAA-Compliant)

| Method | Path | Description | Auth Required | Rate Limited |
|--------|------|-------------|---------------|--------------|
| `POST` | `/api/auth/flow/init` | Initialize authentication flow | No | Yes (per-IP) |
| `GET` | `/api/auth/flow/:flow_id` | Get flow status | Flow token | No |
| `POST` | `/api/auth/flow/:flow_id/identify` | Identify user in flow | Flow token | Yes (per-IP) |
| `POST` | `/api/auth/flow/:flow_id/submit` | Submit credential step | Flow token | Yes (per-IP+flow) |
| `POST` | `/api/auth/flow/:flow_id/complete` | Complete authentication | Flow token | No |

**InitFlowRequest**
```json
{
  "org_id": "string",
  "app_id": "string (optional)",
  "device": "WebDeviceInput (optional)",
  "intent": "login | signup | resetpassword (optional)"
}
```

**IdentifyRequest**
```json
{
  "identifier": "string (email/username)",
  "device": "WebDeviceInput (optional)"
}
```

**SubmitStepRequest**
```json
{
  "capability": "Password | TOTP | Passkey | EmailOTP",
  "value": "string (optional)"
}
```

### Step-Up Authentication

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/auth/step-up` | Submit step-up factor and elevate current session | Yes (JWT) |
| `GET` | `/api/v1/auth/step-up/passkey-challenge` | Create passkey challenge for step-up | Yes (JWT) |

---

## Action Tokens

Public action-token endpoint used for one-time tokenized operations such as email verification or required account actions.

| Method | Path | Description | Auth Required | Request Body |
|--------|------|-------------|---------------|--------------|
| `POST` | `/api/v1/actions/consume` | Verify and consume a signed action token with replay protection | No | `{ "token": "string" }` |

---

## User Management

### Current User

| Method | Path | Description | Auth Required | Request Body | Response |
|--------|------|-------------|---------------|--------------|----------|
| `GET` | `/api/v1/user` | Get current user profile | Yes (JWT) | - | `UserResponse` |
| `PATCH` | `/api/v1/user` | Update current user profile | Yes (JWT) | `UpdateProfileRequest` | `SuccessResponse` |
| `POST` | `/api/v1/user/change-password` | Change user password | Yes (JWT) | `ChangePasswordRequest` | `SuccessResponse` |

**UpdateProfileRequest**
```json
{
  "firstName": "string (optional)",
  "lastName": "string (optional)",
  "profileImageUrl": "string (optional)"
}
```

**ChangePasswordRequest**
```json
{
  "currentPassword": "string",
  "newPassword": "string"
}
```

### User Factors (MFA Enrollment)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/user/factors/enroll` | Start MFA factor enrollment | Yes (JWT) |
| `POST` | `/api/v1/user/factors/verify` | Verify and activate factor | Yes (JWT) |
| `GET` | `/api/v1/user/factors` | List enrolled factors | Yes (JWT) |
| `DELETE` | `/api/v1/user/factors/:id` | Remove MFA factor | Yes (JWT) |

---

## Credentials & Required Actions

### Unified Credentials

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/credentials` | List all credentials registered for the current user across credential providers | Yes (JWT) |

### Required Actions

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/required-actions` | List pending required actions for current user | Yes (JWT) |
| `GET` | `/api/v1/required-actions/:code/challenge` | Create/read challenge data for a required action | Yes (JWT) |
| `POST` | `/api/v1/required-actions/:code/complete` | Complete a required action | Yes (JWT) |

---

## Organizations & Tenants

| Method | Path | Description | Auth Required | Request Body | Response |
|--------|------|-------------|---------------|--------------|----------|
| `GET` | `/api/v1/organizations` | List user's organizations | Yes (JWT) | - | `OrganizationListItem[]` |
| `POST` | `/api/v1/organizations` | Create new organization | Yes (JWT) | `CreateOrganizationRequest` | `OrganizationListItem` |
| `POST` | `/api/v1/auth/switch-org` | Switch active organization | Yes (JWT) | `SwitchOrgRequest` | `SwitchOrgResponse` |

**CreateOrganizationRequest**
```json
{
  "name": "string (1-100 chars)",
  "slug": "string (1-63 chars, optional)"
}
```

**SwitchOrgRequest**
```json
{
  "organization_id": "string"
}
```

### Organization Configuration

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/organizations/:id` | Get org config (public) | No |
| `PATCH` | `/api/organizations/:id/branding` | Update org branding | Yes (Admin) |
| `PATCH` | `/api/organizations/:id/auth-config` | Update auth config | Yes (Admin) |
| `GET` | `/api/org-config/login-methods` | Get login methods | Yes (JWT) |
| `PATCH` | `/api/org-config/login-methods` | Update login methods | Yes (Admin) |

---

## Multi-Factor Authentication (MFA)

| Method | Path | Description | Auth Required | Request Body | Response |
|--------|------|-------------|---------------|--------------|----------|
| `POST` | `/api/mfa/totp/setup` | Setup TOTP (get secret & QR) | Yes (JWT) | - | `SetupResponse` |
| `POST` | `/api/mfa/totp/verify` | Verify TOTP setup | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `POST` | `/api/mfa/totp/challenge` | Verify TOTP during login | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `POST` | `/api/mfa/backup-codes` | Generate backup codes | Yes (JWT) | - | `BackupCodesResponse` |
| `POST` | `/api/mfa/backup-codes/verify` | Verify backup code | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `GET` | `/api/mfa/status` | Get MFA status | Yes (JWT) | - | `MfaStatusResponse` |
| `POST` | `/api/mfa/disable` | Disable MFA | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |

**SetupResponse**
```json
{
  "secret": "string",
  "qrCodeUri": "string",
  "manualEntryKey": "string"
}
```

**MfaStatusResponse**
```json
{
  "totpEnabled": "boolean",
  "backupCodesEnabled": "boolean",
  "backupCodesRemaining": "number"
}
```

---

## Passkeys (WebAuthn)

### Authentication Routes (Public)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/passkeys/authenticate/start` | Start passkey authentication | No |
| `POST` | `/api/passkeys/authenticate/finish` | Complete passkey authentication | No |

### Management Routes (Protected)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/passkeys/register/start` | Start passkey registration | Yes (JWT) |
| `POST` | `/api/passkeys/register/finish` | Complete passkey registration | Yes (JWT) |
| `GET` | `/api/passkeys` | List user's passkeys | Yes (JWT) |
| `DELETE` | `/api/passkeys/:credential_id` | Delete a passkey | Yes (JWT) |

**StartAuthenticationRequest**
```json
{
  "email": "string",
  "org_id": "string (optional)"
}
```

**FinishAuthenticationRequest**
```json
{
  "user_id": "string",
  "session_id": "string",
  "response": "PublicKeyCredential"
}
```

---

## SSO & OAuth

### SSO Authentication

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/auth/sso/:provider/authorize` | Initiate OAuth/OIDC flow | No |
| `GET` | `/api/auth/sso/:provider/callback` | OAuth/OIDC callback handler | No |
| `GET` | `/api/auth/sso/saml/metadata` | SAML SP metadata endpoint | No |
| `GET` | `/api/auth/sso/saml/:connection_id/authorize` | Initiate SAML SP auth | No |
| `POST` | `/api/auth/sso/saml/acs` | SAML ACS (assertion consumer) | No |
| `GET` | `/api/auth/sso/saml/:connection_id/logout` | Initiate SAML SP single logout | No |
| `GET` | `/api/auth/sso/saml/slo` | SAML single logout redirect binding | No |
| `POST` | `/api/auth/sso/saml/slo` | SAML single logout POST binding | No |

---

## OAuth 2.0 Authorization Server

### Public OAuth Endpoints

| Method | Path | Description | Auth Required | Rate Limited |
|--------|------|-------------|---------------|--------------|
| `GET` | `/oauth/authorize` | Authorization endpoint (RFC 6749 §3.1) | No | Yes (public tier) |
| `POST` | `/oauth/token` | Token endpoint (RFC 6749 §3.2) | No | Yes (strict) |
| `POST` | `/oauth/revoke` | Token revocation (RFC 7009) | No | Yes (public tier) |
| `POST` | `/oauth/introspect` | Token introspection (RFC 7662) | Client Auth | Yes (public tier) |
| `GET` | `/oauth/userinfo` | OIDC UserInfo endpoint | OAuth Access Token | Yes (public tier) |
| `POST` | `/oauth/par` | Pushed Authorization Request (RFC 9126) | Client Auth | Yes (public tier) |
| `POST` | `/oauth/device_authorization` | Device Authorization Grant (RFC 8628) | Client Auth | Yes (public tier) |
| `POST` | `/oauth/register` | Dynamic Client Registration (RFC 7591) | Initial access / registration policy | Yes (public tier) |
| `GET` | `/oauth/register/:client_id` | Read registered OAuth client metadata | Client Auth | Yes (public tier) |
| `PUT` | `/oauth/register/:client_id` | Update registered OAuth client metadata | Client Auth | Yes (public tier) |
| `DELETE` | `/oauth/register/:client_id` | Delete registered OAuth client metadata | Client Auth | Yes (public tier) |

### Protected OAuth Endpoints

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/oauth/consent` | Check consent status | Yes (JWT) |
| `POST` | `/api/oauth/consent` | Grant/deny consent | Yes (JWT + EIAA) |
| `POST` | `/api/oauth/device/approve` | Approve/deny OAuth device flow request | Yes (JWT + EIAA) |

### Discovery Endpoints

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery | No |
| `GET` | `/.well-known/jwks.json` | JSON Web Key Set | No |

**Authorization Request Parameters**
- `response_type`: `code` (authorization code flow)
- `client_id`: Application client ID
- `redirect_uri`: Registered redirect URI
- `scope`: Space-separated scopes
- `state`: CSRF protection token
- `code_challenge`: PKCE code challenge (S256)
- `code_challenge_method`: `S256`
- `nonce`: OIDC nonce (optional)

**Token Request (Authorization Code)**
```json
{
  "grant_type": "authorization_code",
  "code": "string",
  "redirect_uri": "string",
  "client_id": "string",
  "client_secret": "string",
  "code_verifier": "string (PKCE)"
}
```

**Token Request (Refresh Token)**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "string",
  "client_id": "string",
  "client_secret": "string"
}
```

**Token Request (Device Code)**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "string",
  "client_id": "string"
}
```

**Pushed Authorization Request**
```json
{
  "response_type": "code",
  "client_id": "string",
  "client_secret": "string (confidential clients)",
  "redirect_uri": "string",
  "scope": "openid profile email",
  "state": "string",
  "code_challenge": "string",
  "code_challenge_method": "S256",
  "nonce": "string (optional)",
  "tenant_id": "string (optional)",
  "response_mode": "query | fragment | form_post | jwt | query.jwt | fragment.jwt | form_post.jwt"
}
```

---

## SAML IdP & SCIM

### SAML Identity Provider Endpoints

Mounted under `/api/saml/idp`. Public metadata/config routes are rate-limited; SSO requires an authenticated IDaaS user session.

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/saml/idp/:tenant_id/metadata` | SAML IdP metadata XML for tenant | No |
| `GET` | `/api/saml/idp/:tenant_id/config` | SAML IdP config summary | No |
| `GET` | `/api/saml/idp/:tenant_id/sso` | SAML IdP SSO redirect binding; consumes `SAMLRequest` and optional `RelayState` | Yes (JWT) |

### SCIM 2.0 Discovery Endpoints

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM service provider capabilities | No |
| `GET` | `/scim/v2/Schemas` | SCIM user/group schemas | No |

### SCIM 2.0 Resource Endpoints

Authenticated with a SCIM bearer token bound to one tenant.

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/scim/v2/Users` | List SCIM users | SCIM Bearer Token |
| `POST` | `/scim/v2/Users` | Create SCIM user | SCIM Bearer Token |
| `GET` | `/scim/v2/Users/:id` | Get SCIM user | SCIM Bearer Token |
| `PUT` | `/scim/v2/Users/:id` | Replace SCIM user | SCIM Bearer Token |
| `DELETE` | `/scim/v2/Users/:id` | Delete/deactivate SCIM user | SCIM Bearer Token |
| `GET` | `/scim/v2/Groups` | List SCIM groups | SCIM Bearer Token |
| `POST` | `/scim/v2/Groups` | Create SCIM group | SCIM Bearer Token |
| `GET` | `/scim/v2/Groups/:id` | Get SCIM group | SCIM Bearer Token |
| `PUT` | `/scim/v2/Groups/:id` | Replace SCIM group | SCIM Bearer Token |
| `DELETE` | `/scim/v2/Groups/:id` | Delete SCIM group | SCIM Bearer Token |

---

## EIAA (Policy Execution)

### Policy Management

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/eiaa/v1/capsules/compile` | Compile policy capsule | Yes (Tenant Admin) |
| `POST` | `/api/eiaa/v1/execute` | Execute capsule | Yes (JWT) |
| `POST` | `/api/eiaa/v1/verify` | Verify attestation | Yes (JWT) |
| `GET` | `/api/eiaa/v1/runtime/keys` | Get runtime public keys for attestation bootstrapping | No |

**CapsuleSpec**
```json
{
  "program": "Program (AST)",
  "tenant_id": "string",
  "action": "string",
  "not_before_unix": "number",
  "not_after_unix": "number"
}
```

**ExecuteRequest**
```json
{
  "capsule": "CompiledCapsule",
  "input": "object (context)",
  "expires_at_unix": "number (optional)"
}
```

---

## Policy Builder

### Templates

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/templates` | List templates | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/templates` | Create template | Yes (Platform Admin) |
| `GET` | `/api/v1/policy-builder/templates/:slug` | Get template | Yes (Developer) |
| `PUT` | `/api/v1/policy-builder/templates/:slug` | Update template | Yes (Platform Admin) |
| `DELETE` | `/api/v1/policy-builder/templates/:slug` | Deprecate template | Yes (Platform Admin) |
| `GET` | `/api/v1/policy-builder/templates/:slug/conditions` | List supported conditions | Yes (Developer) |

### Actions

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/actions` | List actions | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/actions` | Create action | Yes (Admin) |
| `PUT` | `/api/v1/policy-builder/actions/:id` | Update action | Yes (Admin) |
| `DELETE` | `/api/v1/policy-builder/actions/:id` | Delete action | Yes (Admin) |

### Configurations

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/configs` | List policy configs | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/configs` | Create config | Yes (Admin) |
| `GET` | `/api/v1/policy-builder/configs/:id` | Get config | Yes (Developer) |
| `PUT` | `/api/v1/policy-builder/configs/:id` | Update config | Yes (Admin) |
| `DELETE` | `/api/v1/policy-builder/configs/:id` | Archive config | Yes (Admin) |

### Rule Groups

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/policy-builder/configs/:id/groups` | Add group | Yes (Admin) |
| `POST` | `/api/v1/policy-builder/configs/:id/groups/reorder` | Reorder groups | Yes (Admin) |
| `PUT` | `/api/v1/policy-builder/configs/:id/groups/:gid` | Update group | Yes (Admin) |
| `DELETE` | `/api/v1/policy-builder/configs/:id/groups/:gid` | Remove group | Yes (Admin) |

### Rules

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules` | Add rule | Yes (Admin) |
| `POST` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/reorder` | Reorder rules | Yes (Admin) |
| `PUT` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid` | Update rule | Yes (Admin) |
| `DELETE` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid` | Remove rule | Yes (Admin) |

### Conditions

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/condition-types` | List condition types | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid/conditions` | Add condition | Yes (Admin) |
| `POST` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/reorder` | Reorder conditions | Yes (Admin) |
| `PUT` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/:cid` | Update condition | Yes (Admin) |
| `DELETE` | `/api/v1/policy-builder/configs/:id/groups/:gid/rules/:rid/conditions/:cid` | Remove condition | Yes (Admin) |

### Compilation & Activation

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/configs/:id/preview` | Preview compiled AST | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/configs/:id/simulate` | Simulate policy execution | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/configs/:id/compile` | Compile to capsule | Yes (Admin) |
| `POST` | `/api/v1/policy-builder/configs/:id/activate` | Activate policy version | Yes (Admin) |

### Version Management

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/configs/:id/versions` | List versions | Yes (Developer) |
| `GET` | `/api/v1/policy-builder/configs/:id/versions/:vid` | Get version | Yes (Developer) |
| `POST` | `/api/v1/policy-builder/configs/:id/versions/:vid/rollback` | Rollback to version | Yes (Admin) |
| `POST` | `/api/v1/policy-builder/configs/:id/versions/:vid/diff` | Diff versions | Yes (Developer) |
| `GET` | `/api/v1/policy-builder/configs/:id/versions/:vid/export-ast` | Export AST | Yes (Developer) |

### AST Import/Export

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/policy-builder/configs/:id/import-ast` | Import raw AST | Yes (Developer) |
| `GET` | `/api/v1/policy-builder/configs/:id/export-ast` | Export raw AST | Yes (Developer) |

### Audit

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/policy-builder/configs/:id/audit` | Get config audit log | Yes (Admin) |
| `GET` | `/api/v1/policy-builder/audit` | Get tenant-wide audit | Yes (Admin) |

---

## Billing & Subscriptions

### Read-Only Routes

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/billing/v1/subscription?org_id=:id` | Get subscription details | Yes (Org Member) |
| `GET` | `/api/billing/v1/invoices?org_id=:id` | List invoices | Yes (Org Member) |

### Write Routes

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/billing/v1/checkout` | Create checkout session | Yes (Org Admin) |
| `POST` | `/api/billing/v1/subscription/cancel` | Cancel subscription | Yes (Org Admin) |
| `POST` | `/api/billing/v1/portal` | Create billing portal session | Yes (Org Admin) |

### Webhooks

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/billing/v1/webhook` | Stripe webhook handler | Stripe Signature |

**CheckoutRequest**
```json
{
  "org_id": "string",
  "price_id": "string",
  "success_url": "string",
  "cancel_url": "string",
  "customer_email": "string (optional)"
}
```

---

## Roles & Permissions

### Read Routes

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/organizations/:org_id/roles` | List org roles | Yes (Org Member) |
| `GET` | `/api/v1/organizations/:org_id/members` | List org members | Yes (Org Member) |

### Write Routes (Roles)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/organizations/:org_id/roles` | Create role | Yes (Org Admin) |
| `DELETE` | `/api/v1/organizations/:org_id/roles/:role_id` | Delete role | Yes (Org Admin) |

### Write Routes (Members)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/organizations/:org_id/members` | Add member by email | Yes (Org Admin) |
| `PATCH` | `/api/v1/organizations/:org_id/members/:user_id` | Update member role | Yes (Org Admin) |
| `DELETE` | `/api/v1/organizations/:org_id/members/:user_id` | Remove member | Yes (Org Admin) |

**CreateRoleRequest**
```json
{
  "name": "string",
  "description": "string (optional)",
  "permissions": ["string"]
}
```

**AddMemberRequest**
```json
{
  "email": "string",
  "role": "string (default: member)"
}
```

---

## API Keys & Publishable Keys

### API Keys

| Method | Path | Description | Auth Required | Scope Required |
|--------|------|-------------|---------------|----------------|
| `GET` | `/api/v1/api-keys` | List API keys | Yes (JWT or API Key) | `keys:read` |
| `POST` | `/api/v1/api-keys` | Create API key | Yes (JWT or API Key) | `keys:write` |
| `DELETE` | `/api/v1/api-keys/:id` | Revoke API key | Yes (JWT or API Key) | `keys:write` |

**CreateApiKeyRequest**
```json
{
  "name": "string",
  "scopes": ["string"],
  "expires_at": "timestamp (optional)"
}
```

### Publishable Keys

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/publishable-keys` | List publishable keys | Yes (JWT) |
| `POST` | `/api/v1/publishable-keys` | Create publishable key | Yes (JWT) |
| `DELETE` | `/api/v1/publishable-keys/:id` | Revoke publishable key | Yes (JWT) |

**CreatePublishableKeyRequest**
```json
{
  "environment": "test | live",
  "name": "string (optional, defaults to Default)"
}
```

Publishable key environments are intentionally `test` and `live`, matching the public SDK key format `pk_test_{org_slug}` and `pk_live_{org_slug}`. Deployment stages such as development, staging, and production should be modeled by choosing the correct key and API URL for that deployment, not by creating additional publishable key environment names. Only one active publishable key is allowed per tenant/environment; revoke the old key before creating a replacement for the same environment.

---

## Admin Endpoints

Base path: `/api/admin/v1`. All admin endpoints require an authenticated admin session and the `admin:manage` EIAA action unless noted otherwise.

### Applications (OAuth Clients)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/apps` | List applications | Yes (Admin) |
| `POST` | `/api/admin/v1/apps` | Create application | Yes (Admin) |
| `PUT` | `/api/admin/v1/apps/:id` | Update application | Yes (Admin) |
| `DELETE` | `/api/admin/v1/apps/:id` | Delete application | Yes (Admin) |
| `POST` | `/api/admin/v1/apps/:id/rotate-secret` | Rotate client secret | Yes (Admin) |

### Sessions

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/sessions?user_id=:id` | List sessions | Yes (Admin) |
| `DELETE` | `/api/admin/v1/sessions/:session_id` | Revoke session | Yes (Admin) |
| `DELETE` | `/api/admin/v1/sessions/user/:user_id` | Revoke all user sessions | Yes (Admin) |

### SSO Connections

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/sso` | List SSO connections | Yes (Admin) |
| `POST` | `/api/admin/v1/sso` | Create SSO connection | Yes (Admin) |
| `GET` | `/api/admin/v1/sso/:id` | Get SSO connection | Yes (Admin) |
| `PUT` | `/api/admin/v1/sso/:id` | Update SSO connection | Yes (Admin) |
| `DELETE` | `/api/admin/v1/sso/:id` | Delete SSO connection | Yes (Admin) |
| `POST` | `/api/admin/v1/sso/:id/test` | Test SSO connection | Yes (Admin) |
| `PUT` | `/api/admin/v1/sso/:id/toggle` | Enable/disable connection | Yes (Admin) |
| `POST` | `/api/admin/v1/sso/saml/import-metadata` | Import SAML metadata into an SSO connection config | Yes (Admin) |

**CreateConnectionRequest**
```json
{
  "provider": "oauth | saml",
  "name": "string",
  "config": "object (provider-specific)"
}
```

### Audit & Events

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/audit` | Query EIAA execution audit logs | Yes (Admin) |
| `GET` | `/api/admin/v1/audit/stats` | Get EIAA audit statistics | Yes (Admin) |
| `GET` | `/api/admin/v1/audit/:id` | Get one EIAA execution audit record | Yes (Admin) |
| `GET` | `/api/admin/v1/events` | Query audit events | Yes (Admin) |
| `GET` | `/api/admin/v1/events/stats` | Get audit event statistics | Yes (Admin) |
| `GET` | `/api/admin/v1/events/:id` | Get one audit event | Yes (Admin) |

### Client Scopes

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/client-scopes` | List OAuth client scopes | Yes (Admin) |
| `POST` | `/api/admin/v1/client-scopes` | Create OAuth client scope | Yes (Admin) |
| `DELETE` | `/api/admin/v1/client-scopes/:name` | Delete OAuth client scope | Yes (Admin) |
| `POST` | `/api/admin/v1/client-scopes/clients/:client_id/:kind/:scope_name` | Assign scope to a client | Yes (Admin) |
| `DELETE` | `/api/admin/v1/client-scopes/clients/:client_id/:kind/:scope_name` | Unassign scope from a client | Yes (Admin) |

### Users

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/users` | List users | Yes (Admin) |
| `POST` | `/api/admin/v1/users` | Create user | Yes (Admin) |
| `GET` | `/api/admin/v1/users/:id` | Get user | Yes (Admin) |
| `PATCH` | `/api/admin/v1/users/:id` | Update user | Yes (Admin) |
| `DELETE` | `/api/admin/v1/users/:id` | Delete user | Yes (Admin) |
| `GET` | `/api/admin/v1/users/:id/attributes` | List custom user attributes | Yes (Admin) |
| `PUT` | `/api/admin/v1/users/:id/attributes` | Replace custom user attributes | Yes (Admin) |
| `PATCH` | `/api/admin/v1/users/:id/attributes` | Patch custom user attributes | Yes (Admin) |
| `POST` | `/api/admin/v1/users/:id/lock` | Lock user | Yes (Admin) |
| `POST` | `/api/admin/v1/users/:id/unlock` | Unlock user | Yes (Admin) |
| `POST` | `/api/admin/v1/users/:id/required-actions` | Assign required actions | Yes (Admin) |
| `POST` | `/api/admin/v1/users/:id/force-password-change` | Force password change | Yes (Admin) |
| `DELETE` | `/api/admin/v1/users/:id/force-password-change` | Clear forced password change | Yes (Admin) |
| `POST` | `/api/admin/v1/users/:id/impersonate` | Start admin impersonation session | Yes (Admin) |

### Groups

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/groups` | List groups | Yes (Admin) |
| `POST` | `/api/admin/v1/groups` | Create group | Yes (Admin) |
| `GET` | `/api/admin/v1/groups/:id` | Get group | Yes (Admin) |
| `PATCH` | `/api/admin/v1/groups/:id` | Update group | Yes (Admin) |
| `DELETE` | `/api/admin/v1/groups/:id` | Delete group | Yes (Admin) |
| `POST` | `/api/admin/v1/groups/:id/members` | Add group member | Yes (Admin) |
| `DELETE` | `/api/admin/v1/groups/:id/members/:user_id` | Remove group member | Yes (Admin) |
| `POST` | `/api/admin/v1/groups/:id/roles` | Assign role to group | Yes (Admin) |
| `DELETE` | `/api/admin/v1/groups/:id/roles/:role_id` | Remove role from group | Yes (Admin) |

### LDAP / Active Directory

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/ldap` | List LDAP connections | Yes (Admin) |
| `POST` | `/api/admin/v1/ldap` | Create LDAP connection | Yes (Admin) |
| `PUT` | `/api/admin/v1/ldap/:id` | Update LDAP connection | Yes (Admin) |
| `PATCH` | `/api/admin/v1/ldap/:id` | Patch LDAP connection enablement/settings | Yes (Admin) |
| `DELETE` | `/api/admin/v1/ldap/:id` | Delete LDAP connection | Yes (Admin) |
| `POST` | `/api/admin/v1/ldap/:id/test` | Test LDAP connection | Yes (Admin) |
| `POST` | `/api/admin/v1/ldap/:id/sync` | Trigger LDAP sync | Yes (Admin) |
| `GET` | `/api/admin/v1/ldap/:id/sync-runs` | List LDAP sync run history | Yes (Admin) |
| `GET` | `/api/admin/v1/ldap/:id/mappers` | List LDAP attribute mappers | Yes (Admin) |
| `POST` | `/api/admin/v1/ldap/:id/mappers` | Create LDAP attribute mapper | Yes (Admin) |
| `PUT` | `/api/admin/v1/ldap/:id/mappers/:mapper_id` | Update LDAP attribute mapper | Yes (Admin) |
| `DELETE` | `/api/admin/v1/ldap/:id/mappers/:mapper_id` | Delete LDAP attribute mapper | Yes (Admin) |

LDAP sync uses RFC 2696 paged results when `page_size` is configured. User imports honor `trust_email` for identity verification state, use the configured connection `port` for sync/login/password writeback, and treat `edit_mode = "UNSYNCED"` as import-once: new LDAP users are initialized, but existing local users are not overwritten by later sync mapper updates. Group-to-role mappers use `mapper_type = "role"` with config `{ "ldap_group_dn": "cn=admins,...", "membership_role": "admin" }`; legacy `{ "ldap_groups_dn", "role" }` payloads remain accepted for backward compatibility.

### Security Policies

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/security/password-policy` | Get password policy | Yes (Admin) |
| `PUT` | `/api/admin/v1/security/password-policy` | Update password policy | Yes (Admin) |
| `GET` | `/api/admin/v1/security/lockout-policy` | Get default credential lockout policy | Yes (Admin) |
| `PUT` | `/api/admin/v1/security/lockout-policy` | Update default credential lockout policy | Yes (Admin) |
| `GET` | `/api/admin/v1/security/lockout-policies` | List factor-specific lockout policies | Yes (Admin) |
| `GET` | `/api/admin/v1/security/lockout-policy/:factor_kind` | Get factor-specific lockout policy | Yes (Admin) |
| `PUT` | `/api/admin/v1/security/lockout-policy/:factor_kind` | Update factor-specific lockout policy | Yes (Admin) |
| `GET` | `/api/admin/v1/security/locked-users` | List locked users | Yes (Admin) |
| `GET` | `/api/admin/v1/security/lockout/:user_id/state` | Get user lockout state | Yes (Admin) |
| `POST` | `/api/admin/v1/security/lockout/:user_id/reset` | Reset user lockout state | Yes (Admin) |

### SCIM Administration

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/admin/v1/scim/tokens` | List SCIM tokens | Yes (Admin) |
| `POST` | `/api/admin/v1/scim/tokens` | Create SCIM token | Yes (Admin) |
| `DELETE` | `/api/admin/v1/scim/tokens/:id` | Revoke SCIM token | Yes (Admin) |
| `GET` | `/api/admin/v1/scim/config` | Get SCIM config | Yes (Admin) |
| `POST` | `/api/admin/v1/scim/enable` | Enable SCIM | Yes (Admin) |
| `POST` | `/api/admin/v1/scim/disable` | Disable SCIM | Yes (Admin) |
| `POST` | `/api/admin/v1/scim/rotate-token` | Rotate primary SCIM token | Yes (Admin) |
| `GET` | `/api/admin/v1/scim/events` | List SCIM provisioning events | Yes (Admin) |

### Authentication

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/admin/v1/auth/login` | EIAA-compliant admin login; returns provisional admin token and step-up requirement | No |
| `GET` | `/api/admin/v1/whoami` | Return current admin session identity/probe result | Yes (Admin) |

---

## Invitations

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/invitations/:token` | Get invitation details | No |
| `POST` | `/api/v1/invitations/:token/accept` | Accept invitation | Yes (JWT) |

**InvitationInfo Response**
```json
{
  "id": "string",
  "organization_name": "string",
  "organization_slug": "string",
  "email": "string",
  "role": "string",
  "inviter_name": "string (optional)",
  "expires_at": "string (ISO 8601)"
}
```

---

## Custom Domains

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/domains?org_id=:id` | List custom domains | Yes (Org Member) |
| `POST` | `/api/domains` | Add custom domain | Yes (Org Admin) |
| `GET` | `/api/domains/:id` | Get domain details | Yes (Org Member) |
| `DELETE` | `/api/domains/:id?org_id=:id` | Delete domain | Yes (Org Admin) |
| `POST` | `/api/domains/:id/verify` | Verify domain ownership | Yes (Org Admin) |
| `POST` | `/api/domains/:id/primary` | Set as primary domain | Yes (Org Admin) |

**AddDomainRequest**
```json
{
  "org_id": "string",
  "domain": "string"
}
```

---

## Decisions & Verification

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/decisions/:decision_ref` | Get decision details | Yes (JWT, tenant-scoped) |
| `GET` | `/api/decisions/:decision_ref/verify` | Verify decision attestation | Yes (JWT, tenant-scoped) |
| `GET` | `/api/v1/audit/reexecution/verify/:decision_ref` | Re-execute and verify a historical EIAA decision | Yes (JWT, tenant-scoped) |
| `POST` | `/api/v1/audit/reexecution/verify/batch` | Batch re-execute and verify decisions | Yes (JWT, tenant-scoped) |
| `GET` | `/api/v1/audit/reexecution/history` | List historical EIAA executions available for verification | Yes (JWT, tenant-scoped) |

**VerificationResponse**
```json
{
  "decisionRef": "string",
  "verified": "boolean",
  "verificationDetails": {
    "signatureValid": "boolean",
    "hashMatch": "boolean",
    "notExpired": "boolean",
    "decision": "object",
    "attestationTimestamp": "string (ISO 8601)"
  }
}
```

---

## Signup Flow

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/signup/flows` | Initialize signup flow | No |
| `POST` | `/api/signup/flows/:flow_id/submit` | Submit verification step | No |
| `POST` | `/api/signup/decisions/:decision_ref/commit` | Commit signup decision | No |

**InitFlowRequest**
```json
{
  "signup_ticket_id": "string"
}
```

**CommitRequest**
```json
{
  "flow_id": "string"
}
```

---

## Hosted Pages

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/hosted/organizations/:slug` | Get hosted organization branding/config | No |
| `POST` | `/api/hosted/auth/flows` | Initialize legacy hosted auth flow | No |
| `POST` | `/api/hosted/auth/flows/:flow_id/submit` | Submit legacy hosted flow step | Flow token |

---

## SDK & Manifest

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/sdk/manifest?org_id=:id` | Get organization manifest | Publishable Key |

---

## CSRF

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/csrf-token` | Issue CSRF token for browser clients before mutating requests | No |

---

## Development/Test Endpoints

Only available when the backend is built without the `production` feature. These endpoints exist for E2E tests and local test-data setup.

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/test/seed/user` | Seed a test user | No (non-production only) |
| `POST` | `/api/test/seed/organization` | Seed a test organization | No (non-production only) |
| `POST` | `/api/test/seed/membership` | Seed a test membership | No (non-production only) |
| `POST` | `/api/test/seed/invitation` | Seed a test invitation | No (non-production only) |
| `POST` | `/api/test/seed/api-key` | Seed a test API key | No (non-production only) |
| `POST` | `/api/test/seed/policy` | Seed a test policy | No (non-production only) |
| `POST` | `/api/test/seed/mfa-factor` | Seed a test MFA factor | No (non-production only) |
| `POST` | `/api/test/elevate-session` | Elevate a test session | No (non-production only) |
| `POST` | `/api/test/verification-code` | Fetch a test verification code | No (non-production only) |
| `DELETE` | `/api/test/cleanup/:resource_type/:resource_id` | Clean up one seeded resource | No (non-production only) |
| `DELETE` | `/api/test/cleanup/all` | Clean up all seeded test resources | No (non-production only) |

---

## Health & Metrics

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/health` | Health check endpoint | No |
| `GET` | `/health/ready` | Readiness check endpoint | No |
| `GET` | `/metrics` | Prometheus metrics | No (internal) |

---

## Authentication Methods Summary

| Method | Header/Cookie | Usage |
|--------|---------------|-------|
| **JWT (Cookie)** | `Cookie: session=<jwt>` | Browser-based authenticated requests |
| **JWT (Bearer)** | `Authorization: Bearer <jwt>` | API clients, mobile apps |
| **API Key** | `Authorization: Bearer <api_key>` | Server-to-server API calls |
| **Publishable Key** | `X-Publishable-Key: <key>` | SDK initialization, manifest access |
| **Flow Token** | `Authorization: Bearer <flow_token>` | Auth flow step validation |
| **OAuth Access Token** | `Authorization: Bearer <access_token>` | OAuth userinfo endpoint |

---

## Rate Limiting

| Endpoint Pattern | Limit | Window |
|-----------------|-------|--------|
| `/oauth/token` | 10 requests | per IP per 60s |
| `/api/auth/flow/init` | 10 requests | per IP per 60s |
| `/api/auth/flow/:id/identify` | 5 requests | per IP per 60s |
| `/api/auth/flow/:id/submit` | 5 requests | per (IP, flow_id) per 60s |

---

## Error Response Format

All errors follow a consistent format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable description",
  "details": "object (optional)"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `unauthorized` | 401 | Missing or invalid credentials |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `conflict` | 409 | Resource already exists |
| `flow_expired` | 410 | Authentication flow expired |
| `internal_error` | 500 | Server error |

---

## OAuth Error Codes (RFC 6749)

| Code | Description |
|------|-------------|
| `invalid_request` | Missing or malformed parameter |
| `unauthorized_client` | Client not authorized for this grant type |
| `access_denied` | Resource owner denied consent |
| `unsupported_response_type` | Authorization server does not support this response type |
| `invalid_scope` | Requested scope is invalid or unknown |
| `server_error` | Internal server error |
| `temporarily_unavailable` | Server temporarily unavailable |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Invalid authorization code or refresh token |
| `unsupported_grant_type` | Grant type not supported |

---

## Notes

- **Tenant Isolation**: All authenticated endpoints enforce tenant isolation via `tenant_id` in JWT claims or database queries
- **EIAA Enforcement**: Most write operations execute through EIAA policy capsules for authorization decisions
- **Audit Trail**: All sensitive operations (login, role changes, key creation) are logged to the audit system
- **CORS**: Configured per-tenant via organization settings
- **CSRF Protection**: Required for state-changing operations from browser clients

---

**Last Updated**: 2026-05-10, validated against backend route modules
**API Server Version**: See `Cargo.toml` in backend/crates/api_server
