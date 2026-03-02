# AuthStar — UX & Frontend Audit
**Principal Architect Review | March 2026 — Updated**

---

## Executive Summary

This document provides a complete cross-reference of every backend API capability against its frontend coverage, identifies gaps and broken wiring, and designs the canonical user journeys for both user personas who interact with the AuthStar IDaaS platform.

**Overall Assessment (Updated):** The frontend now covers ~88% of backend capabilities. All P0 blocking bugs and P1 major feature gaps from the initial audit have been resolved. Two new bugs were discovered during the re-audit. Remaining gaps are P2/P3 items: App Registry delete, billing portal wiring, risk score display, and re-execution trigger UI.

**Change from initial audit:** Coverage improved from ~72% → ~88%. All 8 original bugs fixed. 2 new bugs found.

---

## Part 1: Who Uses AuthStar?

AuthStar has **two distinct user personas** with completely different goals:

### Persona A — Tenant Admin (B2B Customer)
> "I run a SaaS company. I want to add enterprise-grade auth to my app without building it myself."

- **Who:** CTO, Lead Engineer, or IT Admin at a company using AuthStar
- **Goal:** Configure authentication for their application's users
- **Entry point:** `/admin` — the Admin Console
- **What they do:** Register apps, configure SSO, set auth policies, manage team, view audit logs, customize branding, manage custom domains

### Persona B — End User (B2C Customer of Tenant)
> "I'm logging into Acme Corp's app. AuthStar is the auth layer I never see."

- **Who:** A user of a tenant's application
- **Goal:** Sign in, manage their account, enable MFA
- **Entry point:** `/u/:slug` — the Hosted Auth Flow
- **What they do:** Sign up, log in, reset password, manage MFA, manage API keys

### Persona C — Platform Super Admin (AuthStar Internal)
> "I operate the AuthStar platform itself."

- **Who:** AuthStar engineering/ops team
- **Goal:** Manage tenants, monitor platform health
- **Entry point:** `/u/admin` → `/admin` (system org)
- **Note:** Currently shares the same Admin Console as Tenant Admins

---

## Part 2: Backend API Inventory

All routes verified against `backend/crates/api_server/src/router.rs` and individual route files.

### Auth & Session
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Password login |
| `/api/v1/auth/signup` | POST | User registration |
| `/api/v1/logout` | POST | Invalidate session + clear refresh cookie |
| `/api/v1/token/refresh` | POST | Silent token refresh via HttpOnly cookie |
| `/api/v1/user` | GET | Get current user profile |
| `/api/v1/user` | PATCH | Update user profile (firstName, lastName) |
| `/api/v1/user/change-password` | POST | Change password (validates history + complexity) |

### Hosted Auth Flow (EIAA-Compliant)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/flow/init` | POST | Initialize auth flow (login/signup/reset) |
| `/api/auth/flow/:id/identify` | POST | Submit email/identifier |
| `/api/auth/flow/:id/submit` | POST | Submit credential/factor |
| `/api/auth/flow/:id/complete` | POST | Complete flow, get JWT |
| `/api/auth/flow/:id` | GET | Get flow state |

### MFA
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mfa/totp/setup` | POST | Generate TOTP QR code + secret |
| `/api/mfa/totp/verify` | POST | Verify TOTP code and enable |
| `/api/mfa/totp/challenge` | POST | Challenge TOTP during auth flow |
| `/api/mfa/disable` | POST | Disable MFA |
| `/api/mfa/backup-codes` | POST | Get/generate backup codes (also regenerates when called again) |
| `/api/mfa/backup-codes/verify` | POST | Verify/consume a backup code during login |
| `/api/mfa/status` | GET | Get MFA status (totpEnabled, backupCodesEnabled, remaining) |

> **Note:** MFA routes are mounted at `/api/mfa/...` with **no `/v1/` segment**. This is intentional per `router.rs:147`. The original audit incorrectly flagged these as wrong — they are correct.
>
> **Note:** There is **no** `/api/mfa/backup-codes/regenerate` endpoint. Regeneration is done via `POST /api/mfa/backup-codes`. The `/backup-codes/verify` endpoint consumes a code during login — it does NOT regenerate.

### Passkeys (WebAuthn)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/passkeys/register/start` | POST | Start passkey registration |
| `/api/passkeys/register/finish` | POST | Complete passkey registration |
| `/api/passkeys/` | GET | List registered passkeys |
| `/api/passkeys/:credential_id` | DELETE | Remove a passkey |
| `/api/passkeys/authenticate/start` | POST | Start passkey authentication (public, no auth required) |
| `/api/passkeys/authenticate/finish` | POST | Complete passkey authentication (public, no auth required) |

> **Note:** Passkey routes use `start`/`finish` (not `begin`/`complete`). Frontend `MFAEnrollmentPage.tsx` correctly uses `start`/`finish`.

### Organizations & RBAC
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/organizations` | GET | List user's organizations |
| `/api/v1/organizations` | POST | Create organization |
| `/api/v1/organizations/:id/members` | GET | List members |
| `/api/v1/organizations/:id/members` | POST | Add member by email |
| `/api/v1/organizations/:id/members/:uid` | PATCH | Update member role |
| `/api/v1/organizations/:id/members/:uid` | DELETE | Remove member |
| `/api/v1/organizations/:id/roles` | GET | List roles |
| `/api/v1/organizations/:id/roles` | POST | Create custom role |
| `/api/v1/organizations/:id/roles/:rid` | DELETE | Delete custom role |

### API Keys
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/api-keys` | GET | List API keys (prefix only, no secret) |
| `/api/v1/api-keys` | POST | Create API key (returns full key once) |
| `/api/v1/api-keys/:id` | DELETE | Revoke API key |

### SSO (Admin)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/v1/sso/` | GET | List SSO connections |
| `/api/admin/v1/sso/` | POST | Create SSO connection |
| `/api/admin/v1/sso/:id` | PUT | Update SSO connection |
| `/api/admin/v1/sso/:id` | DELETE | Delete SSO connection |
| `/api/admin/v1/sso/:id/test` | POST | Test SSO connection |

### Policy Builder (EIAA)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/policies/configs` | GET | List policy configs |
| `/api/v1/policies/configs` | POST | Create policy config |
| `/api/v1/policies/configs/:id` | GET | Get policy config detail |
| `/api/v1/policies/configs/:id` | PATCH | Update policy config |
| `/api/v1/policies/configs/:id/activate` | POST | Activate policy version |
| `/api/v1/policies/actions` | GET | List available actions |

### EIAA Decisions & Re-execution
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/eiaa/v1/execute` | POST | Execute EIAA policy |
| `/api/eiaa/v1/commit` | POST | Commit decision |
| `/api/eiaa/v1/runtime/keys` | GET | Get runtime signing keys |
| `/api/v1/audit/reexecution/trigger` | POST | Trigger policy re-execution |

### Billing
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/billing/v1/subscription` | GET | Get subscription details |
| `/api/billing/v1/portal` | POST | Create Stripe billing portal session |
| `/api/billing/v1/webhook` | POST | Stripe webhook handler |

### Org Config & Branding
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/org-config/api/organizations/:id` | GET | Get org config (branding, settings) |
| `/org-config/api/organizations/:id/branding` | PATCH | Update branding |
| `/api/org-config/login-methods` | GET | Get login methods config |
| `/api/org-config/login-methods` | PATCH | Update login methods config |

### Custom Domains
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/domains` | GET | List custom domains |
| `/api/domains` | POST | Add custom domain |
| `/api/domains/:id` | DELETE | Delete domain |
| `/api/domains/:id/verify` | POST | Trigger DNS verification |
| `/api/domains/:id/primary` | POST | Set as primary domain |

### App Registry (Admin)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/v1/apps` | GET | List registered apps |
| `/api/admin/v1/apps` | POST | Register new app |
| `/api/admin/v1/apps/:id` | PUT | Update app |
| `/api/admin/v1/apps/:id` | DELETE | Delete app |

### Audit Logs
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/v1/audit` | GET | List EIAA execution audit logs (filters + cursor pagination) |
| `/api/admin/v1/audit/stats` | GET | Aggregate stats (total, allowed, denied, last 24h, last 7d) |

### Risk Engine
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/risk/score` | GET | Get current risk score |
| `/api/v1/risk/signals` | POST | Submit risk signals |

### Metrics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus metrics (internal, network-protected) |

---

## Part 3: Frontend Coverage Matrix

### COVERED — Backend feature has working frontend UI

| Feature | Frontend Page | API Path Used | Status |
|---------|--------------|---------------|--------|
| Login (EIAA flow) | `AuthFlowPage` (`/u/:slug`) | `/api/auth/flow/*` | Full |
| Signup (EIAA flow) | `AuthFlowPage` (`/u/:slug/signup`) | `/api/auth/flow/*` | Full |
| Password Reset | `AuthFlowPage` (`/u/:slug/reset-password`) | `/api/auth/flow/*` | Full |
| Passkey auth (during flow) | `PasskeyChallengeStep` in `AuthFlowPage` | WebAuthn API | Full |
| Silent token refresh | `AuthContext` | `/api/v1/token/refresh` | Full |
| Logout | `AdminLayout` / `UserLayout` | `/api/v1/logout` | Full |
| User profile view/edit | `ProfilePage` (`/profile`) | `/api/v1/user` (GET + PATCH) | Full |
| Password change | `ProfilePage` → `ChangePasswordModal` | `/api/v1/user/change-password` | Full |
| MFA TOTP setup | `MFAEnrollmentPage` (`/security`) | `/api/mfa/totp/setup` | Full |
| MFA TOTP verify | `MFAEnrollmentPage` | `/api/mfa/totp/verify` | Full |
| MFA disable | `MFAEnrollmentPage` | `/api/mfa/disable` | Full |
| MFA status | `MFAEnrollmentPage` | `/api/mfa/status` | Full |
| MFA backup codes view/generate | `MFAEnrollmentPage` → `BackupCodesSection` | `/api/mfa/backup-codes` (POST) | Full |
| MFA backup codes regenerate | `MFAEnrollmentPage` → `BackupCodesSection` | `/api/mfa/backup-codes/verify` | BUG-9: Wrong endpoint |
| Passkey registration | `MFAEnrollmentPage` → `PasskeysSection` | `/api/passkeys/register/start` + `/finish` | Full |
| Passkey list | `MFAEnrollmentPage` → `PasskeysSection` | `/api/passkeys/` | Full |
| Passkey delete | `MFAEnrollmentPage` → `PasskeysSection` | `/api/passkeys/:id` | Full |
| Team members list | `TeamManagementPage` (`/team`) | `/api/v1/organizations/:id/members` | Full |
| Add team member | `TeamManagementPage` | `/api/v1/organizations/:id/members` | Full |
| Remove team member | `TeamManagementPage` | `/api/v1/organizations/:id/members/:uid` | Full |
| Update member role | `TeamManagementPage` | `/api/v1/organizations/:id/members/:uid` | Full |
| Roles list | `RolesPage` (`/settings/roles`) | `/api/v1/organizations/:id/roles` | Full |
| Create custom role | `RoleEditor` (`/settings/roles/new`) | `/api/v1/organizations/:id/roles` | Full |
| Delete custom role | `RolesPage` | `/api/v1/organizations/:id/roles/:rid` | Full |
| API Keys list | `APIKeysPage` (`/api-keys`) | `/api/v1/api-keys` | Full |
| Create API key | `APIKeysPage` | `/api/v1/api-keys` | Full |
| Revoke API key | `APIKeysPage` | `/api/v1/api-keys/:id` | Full |
| SSO connections list | `SSOPage` (`/settings/sso`, `/admin/sso`) | `/api/admin/v1/sso/` | Full |
| Create SSO connection | `SSOPage` | `/api/admin/v1/sso/` | Full |
| Update SSO connection | `SSOPage` | `/api/admin/v1/sso/:id` | Full |
| Delete SSO connection | `SSOPage` | `/api/admin/v1/sso/:id` | Full |
| Test SSO connection | `SSOPage` | `/api/admin/v1/sso/:id/test` | Full |
| Policy builder list | `ConfigListPage` (`/admin/policies`) | `/api/v1/policies/configs` | Full |
| Create policy config | `ConfigListPage` | `/api/v1/policies/configs` | Full |
| Policy detail/edit | `ConfigDetailPage` (`/admin/policies/:id`) | `/api/v1/policies/configs/:id` | Full |
| Activate policy | `ConfigDetailPage` | `/api/v1/policies/configs/:id/activate` | Full |
| Audit logs (filters + pagination) | `AuditLogPage` (`/admin/audit`) | `/api/admin/v1/audit` | Full |
| Audit log stats | `AdminDashboardPage` | `/api/admin/v1/audit/stats` | Full |
| Admin dashboard (live data) | `AdminDashboardPage` (`/admin/dashboard`) | `/api/admin/v1/audit/stats` + `/api/admin/v1/audit` | Full |
| Branding config | `BrandingPage` | `/org-config/api/organizations/:id` | Full |
| Custom domains list | `DomainsPage` | `/api/domains` | Full |
| Add custom domain | `DomainsPage` | `/api/domains` | Full |
| Verify domain | `DomainsPage` | `/api/domains/:id/verify` | Full |
| Set primary domain | `DomainsPage` | `/api/domains/:id/primary` | Full |
| Delete domain | `DomainsPage` | `/api/domains/:id` | Full |
| App registry list | `AppRegistryPage` (`/admin/apps`) | `/api/admin/v1/apps` | Full |
| Register new app | `AppRegistryPage` + `AppModal` | `/api/admin/v1/apps` | Full |
| Update app | `AppModal` (edit mode) | `/api/admin/v1/apps/:id` | Full |
| Login methods config | `LoginMethodsPage` | `/api/org-config/login-methods` | Full |
| Login Methods in admin sidebar | `AdminLayout` nav | `/admin/auth/login-methods` | Full |
| Admin auth guard (in-memory token) | `AdminLayout` | `useAuth()` hook | Full |
| Admin logout (clears in-memory token) | `AdminLayout` | `useAuth().logout()` | Full |

---

### NOT COVERED — Backend feature exists, no frontend UI

| Feature | Backend Route | Gap Severity | Notes |
|---------|--------------|--------------|-------|
| **App registry delete** | `DELETE /api/admin/v1/apps/:id` | MEDIUM | `AppModal` has no delete button. Edit modal only has Save/Cancel. See BUG-10. |
| **Risk score display** | `GET /api/v1/risk/score` | MEDIUM | No UI to show current risk score to user or admin. |
| **Re-execution trigger** | `POST /api/v1/audit/reexecution/trigger` | MEDIUM | No admin UI to manually trigger policy re-execution. |
| **Billing portal redirect** | `POST /api/billing/v1/portal` | MEDIUM | `BillingPage` exists but unclear if it calls the Stripe portal endpoint. |
| **Organization switcher (full)** | `GET /api/v1/organizations` | LOW | `OrganizationSwitcher` component exists but needs verification it calls the API. |

---

## Part 4: Bugs Found During Audit

### RESOLVED BUGS (Fixed in previous sprint)

| ID | Bug | File | Status |
|----|-----|------|--------|
| BUG-1 | MFA API paths missing `/v1/` | `MFAEnrollmentPage.tsx` | **RETRACTED** — `/api/mfa/...` is correct per `router.rs:147`. No `/v1/` segment. Original audit was wrong. |
| BUG-2 | App Registry API path missing `/api` prefix | `AppRegistryPage.tsx`, `AppModal.tsx` | Fixed — now uses `/api/admin/v1/apps` |
| BUG-3 | Audit Log API path missing `/api` prefix | `AuditLogPage.tsx` | Fixed — now uses `/api/admin/v1/audit` |
| BUG-4 | AdminLayout auth guard reads `sessionStorage` | `AdminLayout.tsx` | Fixed — uses `useAuth()` hook |
| BUG-5 | AdminLayout logout doesn't clear in-memory token | `AdminLayout.tsx` | Fixed — uses `useAuth().logout()` |
| BUG-6 | LoginMethodsPage uses `localStorage` token | `LoginMethodsPage.tsx` | Fixed — uses `api` client singleton |
| BUG-7 | AdminDashboardPage shows hardcoded mock data | `AdminDashboardPage.tsx` | Fixed — real API calls to `/api/admin/v1/audit/stats` and `/api/admin/v1/audit` |
| BUG-8 | ProfilePage redirects to wrong login path | `ProfilePage.tsx` | Fixed — uses `useAuth().logout()` |

---

### NEW BUGS (Found in re-audit)

### BUG-9: Backup Codes Regenerate Calls Wrong Endpoint
**Severity:** MEDIUM
**File:** `frontend/src/pages/MFAEnrollmentPage.tsx` — `BackupCodesSection.regenerateCodes()`, line 264

```typescript
// WRONG — /backup-codes/verify is for CONSUMING a backup code during login
const res = await api.post<BackupCodesResponse>('/api/mfa/backup-codes/verify', { regenerate: true });
```

**Backend reality** (from `mfa.rs`):
- `POST /api/mfa/backup-codes` — generates/returns backup codes. Calling this again regenerates them (invalidates old ones).
- `POST /api/mfa/backup-codes/verify` — verifies/consumes a single backup code during login. Expects `{ code: "XXXX-XXXX" }`, not `{ regenerate: true }`.

**Correct fix:**
```typescript
// CORRECT — POST /api/mfa/backup-codes generates new codes (invalidates old ones)
const res = await api.post<BackupCodesResponse>('/api/mfa/backup-codes');
```

**Impact:** Clicking "Regenerate" sends `{ regenerate: true }` to the verify endpoint, which expects a `{ code: "..." }` field. The backend returns a validation error. Backup code regeneration is completely broken.

---

### BUG-10: AppModal Missing Delete Button
**Severity:** MEDIUM
**File:** `frontend/src/features/apps/AppModal.tsx`

The `AppModal` component (used for both create and edit) has no delete functionality. When editing an existing app, the modal shows only "Save Changes" and "Cancel". The backend `DELETE /api/admin/v1/apps/:id` endpoint exists but is unreachable from the UI.

**Fix:** Add a "Delete Application" danger button in the edit modal footer:
```typescript
const handleDelete = async () => {
    if (!confirm(`Delete "${app!.name}"? This cannot be undone.`)) return;
    setLoading(true);
    try {
        await api.delete(`/api/admin/v1/apps/${app!.id}`);
        toast.success('Application deleted');
        onSuccess();
        onClose();
    } catch (err: any) {
        toast.error(err?.response?.data?.message || 'Failed to delete application');
    } finally {
        setLoading(false);
    }
};
```

**Impact:** Tenant admins cannot delete registered applications from the UI. They must use the API directly.

---

## Part 5: User Journey Designs

### Journey 1: Tenant Admin Onboarding (New Customer)

```
[Landing Page / Marketing Site]
         |
         v
[Sign Up] -> /u/admin/signup
  |- Enter email
  |- Enter password (strength check)
  |- EIAA policy executes: CreateTenant capsule
  |     |- Email verified? -> Send verification email
  |     |- Password strong enough?
  |     +- Risk acceptable?
  |- Enter organization name
  +- Account created -> Redirect to /admin/dashboard
         |
         v
[Admin Dashboard] -> /admin/dashboard
  |- Live stats: total executions, allowed, denied, last 7d
  |- Recent activity feed (real EIAA execution events)
  +- Quick actions: Configure SSO, Manage Apps, Login Methods, View Audit Log
         |
         |-> [Register First App] -> /admin/apps
         |      |- Click "Create New App"
         |      |- Enter app name, redirect URIs
         |      |- Get Client ID + Client Secret (shown once)
         |      +- Copy integration snippet
         |
         |-> [Configure Auth Policy] -> /admin/policies
         |      |- Click "New Policy"
         |      |- Select action (e.g., auth:login)
         |      |- Add rule groups (risk-based, MFA requirements)
         |      |- Compile -> Activate
         |      +- Policy is now live for all logins
         |
         |-> [Set Up SSO] -> /admin/sso
         |      |- Click "Add Connection"
         |      |- Choose type: SAML / OIDC / OAuth
         |      |- Enter credentials (Client ID, Secret, Discovery URL)
         |      |- Copy SP Metadata to IdP
         |      +- Test connection -> Enable
         |
         |-> [Customize Branding] -> /admin/branding
         |      |- Set primary color, background, text color
         |      |- Upload logo URL
         |      |- Live preview of login/signup pages
         |      +- Save -> Hosted pages update immediately
         |
         |-> [Add Custom Domain] -> /admin/domains
         |      |- Enter domain (e.g., auth.mycompany.com)
         |      |- Get DNS TXT verification token
         |      |- Add TXT record to DNS
         |      |- Click "Verify Records"
         |      +- Set as primary domain
         |
         |-> [Configure Login Methods] -> /admin/auth/login-methods
         |      |- Toggle Email/Password, Passkey, SSO
         |      |- Configure MFA requirements
         |      |- Preview auth flow
         |      +- Save & Compile Policy
         |
         +-> [View Audit Logs] -> /admin/audit
                |- See all EIAA policy executions
                |- Filter by decision (allowed/denied)
                |- Filter by action string
                |- Load more (cursor pagination)
                +- View capsule hash for cryptographic proof
```

---

### Journey 2: End User — First Login

```
[Tenant App] -> Redirects to /u/:slug (tenant's hosted login page)
         |
         v
[AuthFlowPage] — Branded with tenant's colors/logo
  |
  |- Step 1: Enter email
  |     +- EIAA: identify_user -> check if user exists
  |
  |- Step 2: Enter password (or choose passkey/SSO)
  |     +- EIAA: submit_credential -> verify password
  |
  |- [If MFA required by policy]
  |     |- Step 3a: Choose factor (TOTP / Passkey)
  |     +- Step 3b: Enter 6-digit code or use passkey
  |
  |- [If risk is HIGH]
  |     +- Step-up required -> additional factor
  |
  +- Flow complete -> JWT issued -> Redirect to app
         |
         v
[User Dashboard] -> /dashboard
  |- Welcome message with user name
  |- Quick access cards: Team, Security, Billing, API Keys, Profile
  +- Status cards: Account Active, MFA Status, Email Verified, Plan
```

---

### Journey 3: End User — Security Setup

```
[Dashboard] -> Click "Security & MFA" -> /security
         |
         v
[MFAEnrollmentPage]
  |
  |- Security Score Bar (Basic / Moderate / Strong)
  |
  |- [TOTP Section]
  |     |- [MFA Not Enabled]
  |     |     |- Click "Set up authenticator"
  |     |     |- POST /api/mfa/totp/setup -> Get QR code + secret
  |     |     |- Show manual entry key (copy button)
  |     |     |- Link to open in authenticator app
  |     |     |- Enter 6-digit verification code
  |     |     |- POST /api/mfa/totp/verify -> Enable MFA
  |     |     +- MFA enabled
  |     |
  |     +- [MFA Enabled]
  |           +- "Disable TOTP" button (with confirmation)
  |
  |- [Backup Codes Section]
  |     |- Shows remaining code count
  |     |- Warning if <= 2 codes remaining
  |     |- "View codes" / "Generate codes" button
  |     |     +- POST /api/mfa/backup-codes -> Show codes grid
  |     |- Copy all / Download buttons
  |     +- "Regenerate" button (BUG-9: calls wrong endpoint)
  |
  +- [Passkeys Section]
        |- List of registered passkeys (name, created, last used)
        |     +- Remove button per passkey
        |           +- DELETE /api/passkeys/:id
        +- "+ Add passkey" button
              |- Optional name input
              |- POST /api/passkeys/register/start -> Get challenge
              |- Browser WebAuthn prompt (Face ID / Touch ID / hardware key)
              +- POST /api/passkeys/register/finish -> Register
```

---

### Journey 4: End User — Password Reset (Unauthenticated)

```
[Login Page] -> /u/:slug
  |
  +- Click "Forgot password?" link
         |
         v
[AuthFlowPage intent="resetpassword"] -> /u/:slug/reset-password
  |
  |- Step 1: Enter email
  |     +- POST /api/auth/flow/init { intent: "resetpassword" }
  |
  |- Step 2: Enter reset code (sent to email)
  |     +- POST /api/auth/flow/:id/submit { code: "..." }
  |
  |- Step 3: Enter new password (with strength indicator)
  |     +- POST /api/auth/flow/:id/submit { new_password: "..." }
  |
  +- Password reset complete -> Redirect to login
```

---

### Journey 5: End User — Password Change (Authenticated)

```
[Profile Page] -> /profile
  |
  +- Click "Change Password" quick action
         |
         v
[ChangePasswordModal] (inline modal)
  |- Enter current password
  |- Enter new password (min 8 chars)
  |- Confirm new password (inline mismatch validation)
  +- Click "Change password"
        +- POST /api/v1/user/change-password
              |- Backend validates: current password correct?
              |- Backend validates: new password meets complexity?
              |- Backend validates: not in password history?
              |- Backend: atomic tx — update hash + write history
              +- Success -> modal closes
```

---

### Journey 6: End User — API Key Management

```
[Dashboard] -> Click "API Keys" -> /api-keys
         |
         v
[APIKeysPage]
  |- List of active keys (prefix only, never full key)
  |     |- Key name
  |     |- ask_<prefix>_<redacted>
  |     |- Created date, last used date, expiry
  |     |- Scopes (badges)
  |     +- [Revoke] button -> DELETE /api/v1/api-keys/:id
  |
  |- Click "+ Create Key"
  |     |- Enter key name (required, max 100 chars)
  |     |- Enter scopes (optional, comma-separated)
  |     |- Set expiry (optional datetime)
  |     +- Click "Create Key" -> POST /api/v1/api-keys
  |
  +- One-time reveal banner
        |- "Save your API key — it won't be shown again"
        |- Full key displayed: ask_<prefix>_<48-char-base64url>
        |- [Copy] button
        +- [Done] button -> banner dismissed
```

---

### Journey 7: Tenant Admin — Team Management

```
[Dashboard] -> Click "Team Management" -> /team
         |
         v
[TeamManagementPage]
  |- Invite section
  |     |- Enter email address
  |     |- Select role (Member / Admin / custom roles)
  |     +- Click "Invite"
  |           +- POST /api/v1/organizations/:id/members
  |
  +- Members list
        |- Avatar + name + email
        |- Role dropdown (inline edit)
        |     +- PATCH /api/v1/organizations/:id/members/:uid
        +- Remove button
              +- DELETE /api/v1/organizations/:id/members/:uid
```

---

### Journey 8: Tenant Admin — Policy Configuration

```
[Admin Console] -> /admin/policies
         |
         v
[ConfigListPage]
  |- Grid of policy configs (sorted: active -> compiled -> draft -> archived)
  |     |- Config card: action key, display name, state badge
  |     +- Click card -> /admin/policies/:id
  |
  +- Click "+ New Policy"
        |- Select action (e.g., auth:login, auth:signup)
        |- Enter display name + description
        +- Create -> Navigate to ConfigDetailPage
               |
               v
        [ConfigDetailPage] -> /admin/policies/:id
          |- Visual rule builder
          |     |- Add rule groups
          |     |- Add rules per group (condition -> action)
          |     +- Drag to reorder
          |- JSON preview (read-only)
          |- [Compile] -> Validate policy AST
          +- [Activate] -> POST /api/v1/policies/configs/:id/activate
                +- Policy is now live for all auth flows
```

---

## Part 6: Navigation Architecture

### User Area (`/dashboard`, `/profile`, etc.)

```
UserLayout (nav bar)
|- Logo: "IDaaS Platform"
|- Nav links: Dashboard | Team | Security | Billing
|- OrganizationSwitcher (top right)
+- User menu (avatar dropdown)
      |- Profile Settings -> /profile
      |- Security & MFA -> /security
      |- API Keys -> /api-keys
      |- Billing -> /billing
      +- Sign Out

Pages under UserLayout:
|- /dashboard        -> DashboardPage (quick access grid)
|- /profile          -> ProfilePage (name, email, status, change password)
|- /security         -> MFAEnrollmentPage (TOTP + backup codes + passkeys)
|- /team             -> TeamManagementPage (members + roles)
|- /billing          -> BillingPage (subscription)
|- /api-keys         -> APIKeysPage (key management)
|- /settings/roles   -> RolesPage (custom roles)
|- /settings/roles/new -> RoleEditor
|- /settings/branding -> BrandingPage
|- /settings/domains  -> DomainsPage
|- /settings/sso      -> SSOPage
+- /settings/auth/login-methods -> LoginMethodsPage
```

### Admin Area (`/admin/*`)

```
AdminLayout (sidebar)
|- Logo: "IDaaS Admin"
|- Sidebar nav:
|     |- Dashboard -> /admin/dashboard
|     |- App Registry -> /admin/apps
|     |- Policies -> /admin/policies
|     |- Audit Logs -> /admin/audit
|     |- Branding -> /admin/branding
|     |- Custom Domains -> /admin/domains
|     |- SSO Connections -> /admin/sso
|     +- Login Methods -> /admin/auth/login-methods  (Added in sprint)
+- Logout button (bottom, uses useAuth().logout())

Pages under AdminLayout:
|- /admin/dashboard  -> AdminDashboardPage (live data: stats + activity feed)
|- /admin/apps       -> AppRegistryPage (correct API path)
|- /admin/policies   -> ConfigListPage
|- /admin/policies/:id -> ConfigDetailPage
|- /admin/audit      -> AuditLogPage (correct API path, filters, pagination)
|- /admin/branding   -> BrandingPage
|- /admin/domains    -> DomainsPage
|- /admin/sso        -> SSOPage
+- /admin/auth/login-methods -> LoginMethodsPage
```

---

## Part 7: Prioritized Fix List

### P0 — Breaks Core Functionality (All Resolved)

| ID | Issue | File | Status |
|----|-------|------|--------|
| P0-1 | AdminLayout auth guard reads sessionStorage | `AdminLayout.tsx` | Fixed |
| P0-2 | MFA API paths missing `/v1/` | `MFAEnrollmentPage.tsx` | Retracted — paths were correct all along |
| P0-3 | App Registry API path missing `/api` prefix | `AppRegistryPage.tsx` | Fixed |
| P0-4 | Audit Log API path missing `/api` prefix | `AuditLogPage.tsx` | Fixed |

### P1 — Major Feature Gaps (All Resolved)

| ID | Issue | Status |
|----|-------|--------|
| P1-1 | Admin Dashboard shows mock data | Fixed — real API calls to stats + audit endpoints |
| P1-2 | No passkey enrollment UI | Fixed — `PasskeysSection` in `MFAEnrollmentPage` |
| P1-3 | No passkey management (list/delete) | Fixed — `PasskeysSection` with list + delete |
| P1-4 | AdminLayout logout doesn't clear in-memory token | Fixed — uses `useAuth().logout()` |
| P1-5 | LoginMethodsPage uses localStorage token | Fixed — uses `api` client singleton |

### P2 — UX Improvements (All Resolved)

| ID | Issue | Status |
|----|-------|--------|
| P2-1 | Audit log filters are non-functional | Fixed — decision filter + action search wired to API |
| P2-2 | Audit log has no pagination | Fixed — cursor-based load-more implemented |
| P2-3 | No MFA backup codes management | Fixed — `BackupCodesSection` with view/generate/regenerate |
| P2-4 | No password change in ProfilePage | Fixed — `ChangePasswordModal` added |
| P2-5 | Admin sidebar missing Login Methods link | Fixed — added to `AdminLayout` nav |
| P2-6 | Dashboard "Coming Soon" placeholder | Fixed — real stats + activity feed |
| P2-7 | ProfilePage redirects to wrong login path | Fixed — uses `useAuth().logout()` |

### Active Bugs (Found in Re-audit)

| ID | Issue | Effort | File | Fix |
|----|-------|--------|------|-----|
| BUG-9 | Backup codes regenerate calls wrong endpoint | S | `MFAEnrollmentPage.tsx:264` | Change `POST /api/mfa/backup-codes/verify` to `POST /api/mfa/backup-codes` |
| BUG-10 | AppModal missing delete button | S | `AppModal.tsx` | Add delete button + `DELETE /api/admin/v1/apps/:id` call in edit mode |

### P3 — Nice to Have (Backlog)

| ID | Issue | Effort | Notes |
|----|-------|--------|-------|
| P3-1 | Risk score display for users | L | Show risk level in security page from `GET /api/v1/risk/score` |
| P3-2 | Re-execution trigger UI for admins | M | Add to admin policy page, calls `POST /api/v1/audit/reexecution/trigger` |
| P3-3 | Billing portal integration | M | Wire `BillingPage` to `POST /api/billing/v1/portal` for Stripe redirect |
| P3-4 | Organization switcher verification | S | Confirm `OrganizationSwitcher` calls `GET /api/v1/organizations` |

---

## Part 8: API Path Consistency Reference

The backend has intentionally inconsistent versioning by design. This is the canonical reference:

| Pattern | Used By | Correct? |
|---------|---------|----------|
| `/api/v1/...` | Most user-facing routes | Correct |
| `/api/admin/v1/...` | Admin routes (SSO, apps, audit) | Correct |
| `/api/mfa/...` | MFA routes (NO `/v1/`) | Correct — mounted at `/api/mfa` per `router.rs:147` |
| `/api/passkeys/...` | Passkey routes (NO `/v1/`) | Correct — mounted at `/api/passkeys` per `router.rs:151` |
| `/api/domains/...` | Domain routes (NO `/v1/`) | Correct — mounted at `/api/domains` per `router.rs:155` |
| `/api/billing/v1/...` | Billing routes | Correct |
| `/api/auth/flow/...` | Auth flow routes | Correct |
| `/org-config/api/...` | Branding/org config | Correct |
| `/api/org-config/...` | Login methods | Correct |

**Key insight:** The original audit incorrectly flagged MFA paths as wrong. The backend mounts MFA at `/api/mfa` (no `/v1/`), which is exactly what the frontend uses. Confirmed by reading `router.rs:147`: `.nest("/api/mfa", mfa_routes::router()...)`.

---

## Part 9: Summary Scorecard

| Category | Coverage | Quality | Notes |
|----------|----------|---------|-------|
| Auth Flow (EIAA) | 100% | Excellent | Full multi-step flow with passkey support |
| User Profile | 100% | Excellent | View, edit, change password all wired |
| MFA | 95% | Good | TOTP + backup codes + passkeys. BUG-9: regenerate endpoint wrong |
| Team Management | 95% | Good | Full CRUD |
| API Keys | 100% | Excellent | Full lifecycle with one-time reveal |
| SSO | 100% | Excellent | SAML + OIDC + OAuth |
| Policy Builder | 95% | Good | Full visual builder |
| Audit Logs | 100% | Excellent | Filters, cursor pagination, stats |
| App Registry | 85% | Partial | List/create/edit work. BUG-10: delete missing |
| Admin Dashboard | 100% | Excellent | Live stats + activity feed |
| Branding | 90% | Good | Live preview works |
| Domains | 100% | Good | Full DNS verification flow |
| Billing | 50% | Partial | Page exists, portal integration unverified |
| Passkeys | 100% | Excellent | Registration, list, delete all implemented |
| Risk Engine | 0% | Missing | No UI at all |
| Login Methods | 100% | Excellent | Full config + EIAA policy compilation |

**Overall Frontend Coverage: ~88%**
**Blocking Bugs (P0): 0** (all resolved)
**Active Bugs: 2** (BUG-9, BUG-10)
**Major Feature Gaps (P1): 0** (all resolved)

---

## Part 10: Audit Change Log

| Date | Change |
|------|--------|
| March 2026 (initial) | First audit — 72% coverage, 8 bugs, 5 P1 gaps |
| March 2026 (updated) | Re-audit after sprint — 88% coverage, 8 bugs fixed, 2 new bugs found |

### Key Corrections from Initial Audit

1. **BUG-1 retracted:** MFA paths `/api/mfa/...` are correct. The original audit claimed they needed `/v1/` — this was wrong. Backend mounts MFA at `/api/mfa` (no version segment) per `router.rs:147`.

2. **Passkey endpoint names corrected:** Backend uses `start`/`finish` (not `begin`/`complete`). Frontend `MFAEnrollmentPage.tsx` correctly uses `start`/`finish`. Original audit listed `begin`/`complete` in the backend inventory — incorrect.

3. **Backup codes regenerate clarified:** There is no `/api/mfa/backup-codes/regenerate` endpoint. Regeneration is done by calling `POST /api/mfa/backup-codes` again. The frontend incorrectly calls `/backup-codes/verify` with `{ regenerate: true }` — this is BUG-9.

4. **Audit log path corrected:** Original audit listed `/admin/v1/audit` as the backend path. Actual path is `/api/admin/v1/audit`. Frontend was fixed (BUG-3).

5. **App Registry path corrected:** Original audit listed `/admin/v1/apps`. Actual path is `/api/admin/v1/apps`. Frontend was fixed (BUG-2).

6. **New endpoints added to inventory:** `/api/admin/v1/audit/stats`, `/api/v1/user/change-password`, `/api/mfa/status` — all built and wired during the sprint.

---

*Generated by Principal Architect Review — AuthStar Platform — March 2026*