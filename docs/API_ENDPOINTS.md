# IDaaS API Endpoints Reference

Comprehensive documentation of all public API endpoints in the IDaaS backend.

**Base URL**: `http://localhost:3000` (development) / Production URL varies by deployment

**API Version**: v1

---

## Table of Contents

- [Authentication & Authorization](#authentication--authorization)
- [User Management](#user-management)
- [Organizations & Tenants](#organizations--tenants)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [Passkeys (WebAuthn)](#passkeys-webauthn)
- [SSO & OAuth](#sso--oauth)
- [OAuth 2.0 Authorization Server](#oauth-20-authorization-server)
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
| `POST` | `/api/v1/auth/sign-up` | Initiate user signup | No | `HelperSignupRequest` | `HelperSignupResponse` |
| `POST` | `/api/v1/auth/sign-in` | Sign in with email/password | No | `HelperSigninRequest` | `HelperSigninResponse` |
| `POST` | `/api/v1/auth/logout` | Log out current session | Yes (JWT) | - | - |
| `POST` | `/api/v1/auth/token/refresh` | Refresh JWT token | Yes (JWT) | - | `HelperRefreshResponse` |

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
| `POST` | `/api/v1/auth-flow/init` | Initialize authentication flow | No | Yes (per-IP) |
| `GET` | `/api/v1/auth-flow/:flow_id` | Get flow status | Flow token | No |
| `POST` | `/api/v1/auth-flow/:flow_id/identify` | Identify user in flow | Flow token | Yes (per-IP) |
| `POST` | `/api/v1/auth-flow/:flow_id/submit` | Submit credential step | Flow token | Yes (per-IP+flow) |
| `POST` | `/api/v1/auth-flow/:flow_id/complete` | Complete authentication | Flow token | No |

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
| `POST` | `/api/v1/auth/step-up/init` | Initialize step-up auth | Yes (JWT) |
| `POST` | `/api/v1/auth/step-up/:session_id/submit` | Submit step-up credential | Yes (JWT) |
| `POST` | `/api/v1/auth/step-up/:session_id/complete` | Complete step-up | Yes (JWT) |

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

## Organizations & Tenants

| Method | Path | Description | Auth Required | Request Body | Response |
|--------|------|-------------|---------------|--------------|----------|
| `GET` | `/api/v1/organizations` | List user's organizations | Yes (JWT) | - | `OrganizationListItem[]` |
| `POST` | `/api/v1/organizations` | Create new organization | Yes (JWT) | `CreateOrganizationRequest` | `OrganizationListItem` |
| `POST` | `/api/v1/organizations/switch` | Switch active organization | Yes (JWT) | `SwitchOrgRequest` | `SwitchOrgResponse` |

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
| `POST` | `/api/v1/mfa/totp/setup` | Setup TOTP (get secret & QR) | Yes (JWT) | - | `SetupResponse` |
| `POST` | `/api/v1/mfa/totp/verify` | Verify TOTP setup | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `POST` | `/api/v1/mfa/totp/challenge` | Verify TOTP during login | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `POST` | `/api/v1/mfa/backup-codes` | Generate backup codes | Yes (JWT) | - | `BackupCodesResponse` |
| `POST` | `/api/v1/mfa/backup-codes/verify` | Verify backup code | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |
| `GET` | `/api/v1/mfa/status` | Get MFA status | Yes (JWT) | - | `MfaStatusResponse` |
| `POST` | `/api/v1/mfa/disable` | Disable MFA | Yes (JWT) | `VerifyCodeRequest` | `VerifyResponse` |

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
| `POST` | `/api/v1/passkeys/auth/start` | Start passkey authentication | No |
| `POST` | `/api/v1/passkeys/auth/finish` | Complete passkey authentication | No |

### Management Routes (Protected)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/passkeys/register/start` | Start passkey registration | Yes (JWT) |
| `POST` | `/api/v1/passkeys/register/finish` | Complete passkey registration | Yes (JWT) |
| `GET` | `/api/v1/passkeys` | List user's passkeys | Yes (JWT) |
| `DELETE` | `/api/v1/passkeys/:credential_id` | Delete a passkey | Yes (JWT) |

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
| `GET` | `/api/v1/sso/:provider/authorize` | Initiate OAuth/OIDC flow | No |
| `GET` | `/api/v1/sso/:provider/callback` | OAuth callback handler | No |
| `GET` | `/api/v1/sso/saml/metadata` | SAML metadata endpoint | No |
| `GET` | `/api/v1/sso/saml/:connection_id/authorize` | Initiate SAML auth | No |
| `POST` | `/api/v1/sso/saml/acs` | SAML ACS (assertion consumer) | No |

---

## OAuth 2.0 Authorization Server

### Public OAuth Endpoints

| Method | Path | Description | Auth Required | Rate Limited |
|--------|------|-------------|---------------|--------------|
| `GET` | `/oauth/authorize` | Authorization endpoint (RFC 6749 §3.1) | No | No |
| `POST` | `/oauth/token` | Token endpoint (RFC 6749 §3.2) | No | Yes (strict) |
| `POST` | `/oauth/revoke` | Token revocation (RFC 7009) | No | No |
| `POST` | `/oauth/introspect` | Token introspection (RFC 7662) | Client Auth | No |
| `GET` | `/oauth/userinfo` | OIDC UserInfo endpoint | OAuth Access Token | No |

### Protected OAuth Endpoints

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/oauth/consent` | Check consent status | Yes (JWT) |
| `POST` | `/oauth/consent` | Grant/deny consent | Yes (JWT) |

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

---

## EIAA (Policy Execution)

### Policy Management

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/eiaa/capsules/compile` | Compile policy capsule | Yes (Tenant Admin) |
| `POST` | `/api/v1/eiaa/execute` | Execute capsule | Yes (JWT) |
| `POST` | `/api/v1/eiaa/verify` | Verify attestation | Yes (JWT) |
| `GET` | `/api/v1/eiaa/runtime/keys` | Get runtime public keys | Yes (JWT) |

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
| `GET` | `/api/v1/billing/subscription?org_id=:id` | Get subscription details | Yes (Org Member) |
| `GET` | `/api/v1/billing/invoices?org_id=:id` | List invoices | Yes (Org Member) |

### Write Routes

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/billing/checkout` | Create checkout session | Yes (Org Admin) |
| `POST` | `/api/v1/billing/subscription/cancel` | Cancel subscription | Yes (Org Admin) |
| `POST` | `/api/v1/billing/portal` | Create billing portal session | Yes (Org Admin) |

### Webhooks

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/api/v1/billing/webhook` | Stripe webhook handler | Stripe Signature |

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
  "environment": "development | staging | production"
}
```

---

## Admin Endpoints

Base path: `/api/admin/v1`

### Applications (OAuth Clients)

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/admin/apps` | List applications | Yes (Admin) |
| `POST` | `/admin/apps` | Create application | Yes (Admin) |
| `PUT` | `/admin/apps/:id` | Update application | Yes (Admin) |
| `DELETE` | `/admin/apps/:id` | Delete application | Yes (Admin) |
| `POST` | `/admin/apps/:id/rotate-secret` | Rotate client secret | Yes (Admin) |

### Sessions

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/admin/sessions?user_id=:id` | List sessions | Yes (Admin) |
| `DELETE` | `/admin/sessions/:session_id` | Revoke session | Yes (Admin) |
| `DELETE` | `/admin/sessions/user/:user_id` | Revoke all user sessions | Yes (Admin) |

### SSO Connections

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/admin/sso` | List SSO connections | Yes (Admin) |
| `POST` | `/admin/sso` | Create SSO connection | Yes (Admin) |
| `GET` | `/admin/sso/:id` | Get SSO connection | Yes (Admin) |
| `PUT` | `/admin/sso/:id` | Update SSO connection | Yes (Admin) |
| `DELETE` | `/admin/sso/:id` | Delete SSO connection | Yes (Admin) |
| `POST` | `/admin/sso/:id/test` | Test SSO connection | Yes (Admin) |
| `PUT` | `/admin/sso/:id/toggle` | Enable/disable connection | Yes (Admin) |

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
| `GET` | `/admin/audit` | Query audit logs | Yes (Admin) |
| `GET` | `/admin/events` | Query events | Yes (Admin) |

### Authentication

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `POST` | `/admin/auth/verify-admin` | Verify admin privileges | Yes (Admin) |

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
| `GET` | `/api/v1/domains?org_id=:id` | List custom domains | Yes (Org Member) |
| `POST` | `/api/v1/domains` | Add custom domain | Yes (Org Admin) |
| `GET` | `/api/v1/domains/:id` | Get domain details | Yes (Org Member) |
| `DELETE` | `/api/v1/domains/:id?org_id=:id` | Delete domain | Yes (Org Admin) |
| `POST` | `/api/v1/domains/:id/verify` | Verify domain ownership | Yes (Org Admin) |
| `POST` | `/api/v1/domains/:id/primary` | Set as primary domain | Yes (Org Admin) |

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
| `GET` | `/api/v1/decisions/:decision_ref` | Get decision details | Yes (JWT, tenant-scoped) |
| `GET` | `/api/v1/decisions/:decision_ref/verify` | Verify decision attestation | Yes (JWT, tenant-scoped) |

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
| `POST` | `/api/v1/signup/flows` | Initialize signup flow | No |
| `POST` | `/api/v1/signup/flows/:flow_id/submit` | Submit verification step | No |
| `POST` | `/api/v1/signup/decisions/:decision_ref/commit` | Commit signup decision | No |

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
| `POST` | `/hosted/flow/init` | Initialize hosted auth flow | No |
| `POST` | `/hosted/flow/:flow_id/submit` | Submit hosted flow step | Flow token |

---

## SDK & Manifest

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/api/v1/sdk/manifest?org_id=:id` | Get organization manifest | Publishable Key |

---

## Health & Metrics

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| `GET` | `/health` | Health check endpoint | No |
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
| `/oauth/token` | 5 requests | per IP per 60s |
| `/auth-flow/init` | 10 requests | per IP per 60s |
| `/auth-flow/:id/identify` | 5 requests | per IP per 60s |
| `/auth-flow/:id/submit` | 5 requests | per (IP, flow_id) per 60s |

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

**Last Updated**: Auto-generated from backend source code analysis
**API Server Version**: See `Cargo.toml` in backend/crates/api_server
