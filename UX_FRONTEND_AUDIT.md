# AuthStar — UX & Frontend Audit
**Principal Architect Review | March 2026 — Updated**

---

## Executive Summary

This document provides a complete cross-reference of every backend API capability against its frontend coverage, identifies gaps and broken wiring, and designs the canonical user journeys for both user personas who interact with the AuthStar IDaaS platform.

**Overall Assessment (Updated):** The frontend has significant coverage of backend functionality, but a severe disconnect has been identified between the frontend authentication flow (`AuthFlowPage`) and the recently secured backend EIAA auth flows (`auth_flow.rs`). Three new P0 blocking bugs (BUG-11, BUG-12, BUG-13) have been discovered regarding API pathing, ephemeral tokens, and identify endpoints. BUG-9 and BUG-10 remain active. Remaining gaps are P2/P3 items: App Registry delete, billing portal wiring, risk score display, and re-execution trigger UI.

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
- **Entry point:** `/u/admin` -> `/admin` (system org)
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
| `/api/auth/flow/init` | POST | Initialize auth flow (login/signup/reset). Returns `flow_token`. |
| `/api/auth/flow/:id/identify` | POST | Submit email/identifier. Requires `flow_token` bearer token. |
| `/api/auth/flow/:id/submit` | POST | Submit credential/factor. Requires `flow_token` bearer token. |
| `/api/auth/flow/:id/complete` | POST | Complete flow, get JWT. Requires `flow_token` bearer token. |
| `/api/auth/flow/:id` | GET | Get flow state. Requires `flow_token` bearer token. |

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

### Passkeys (WebAuthn)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/passkeys/register/start` | POST | Start passkey registration |
| `/api/passkeys/register/finish` | POST | Complete passkey registration |
| `/api/passkeys/` | GET | List registered passkeys |
| `/api/passkeys/:credential_id` | DELETE | Remove a passkey |
| `/api/passkeys/authenticate/start` | POST | Start passkey authentication (public, no auth required) |
| `/api/passkeys/authenticate/finish` | POST | Complete passkey authentication (public, no auth required) |

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

---

## Part 3: Frontend Coverage Matrix

### COVERED — Backend feature has working frontend UI

| Feature | Frontend Page | API Path Used | Status |
|---------|--------------|---------------|--------|
| Passkey auth (during flow) | `PasskeyChallengeStep` in `AuthFlowPage` | WebAuthn API | Full |
| Silent token refresh | `AuthContext` | `/api/v1/token/refresh` | Full |
| Logout | `AdminLayout` / `UserLayout` | `/api/v1/logout` | Full |
| User profile view/edit | `ProfilePage` (`/profile`) | `/api/v1/user` (GET + PATCH) | Full |
| Password change | `ProfilePage` -> `ChangePasswordModal` | `/api/v1/user/change-password` | Full |
| MFA TOTP setup | `MFAEnrollmentPage` (`/security`) | `/api/mfa/totp/setup` | Full |
| MFA TOTP verify | `MFAEnrollmentPage` | `/api/mfa/totp/verify` | Full |
| MFA disable | `MFAEnrollmentPage` | `/api/mfa/disable` | Full |
| MFA status | `MFAEnrollmentPage` | `/api/mfa/status` | Full |
| MFA backup codes view/generate | `MFAEnrollmentPage` -> `BackupCodesSection` | `/api/mfa/backup-codes` (POST) | Full |
| Passkey registration | `MFAEnrollmentPage` -> `PasskeysSection` | `/api/passkeys/register/start` + `/finish` | Full |
| Passkey list | `MFAEnrollmentPage` -> `PasskeysSection` | `/api/passkeys/` | Full |
| Passkey delete | `MFAEnrollmentPage` -> `PasskeysSection` | `/api/passkeys/:id` | Full |
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
| Organization Switcher | `OrganizationSwitcher` component | `/api/v1/organizations` | Full |

---

### NOT COVERED — Broken or Missing UIs

| Feature | Backend Route | Gap Severity | Notes |
|---------|--------------|--------------|-------|
| **Hosted Auth Flow** | `/api/auth/flow/*` | HIGH | `AuthFlowPage` relies on deprecated `/api/hosted/...` API endpoints, misses ephemeral `flow_token` integration, and erroneously calls `/submit` for identification instead of `/identify`. (See BUG-11, 12, 13) |
| **App registry delete** | `DELETE /api/admin/v1/apps/:id` | MEDIUM | `AppModal` has no delete button. Edit modal only has Save/Cancel. See BUG-10. |
| **Risk score display** | `GET /api/v1/risk/score` | MEDIUM | No UI to show current risk score to user or admin. |
| **Re-execution trigger** | `POST /api/v1/audit/reexecution/trigger` | MEDIUM | No admin UI to manually trigger policy re-execution. |
| **Billing portal redirect** | `POST /api/billing/v1/portal` | MEDIUM | `BillingPage` exists but unclear if it calls the Stripe portal endpoint. |

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

### ACTIVE BUGS (Found in re-audit)

### BUG-9: Backup Codes Regenerate Calls Wrong Endpoint
**Severity:** MEDIUM
**File:** `frontend/src/pages/MFAEnrollmentPage.tsx` — `BackupCodesSection.regenerateCodes()`, line 264

**Impact:** Clicking "Regenerate" sends `{ regenerate: true }` to the verify endpoint, which expects a `{ code: "..." }` field. The backend returns a validation error. Backup code regeneration is completely broken.

---

### BUG-10: AppModal Missing Delete Button
**Severity:** MEDIUM
**File:** `frontend/src/features/apps/AppModal.tsx`

**Impact:** Tenant admins cannot delete registered applications from the UI. They must use the API directly.

---

### BUG-11: Hosted APIs Out-of-Sync with Secured Backend Endpoints
**Severity:** CRITICAL
**File:** `frontend/src/lib/api/hosted.ts` 

**Details:** The `hostedApi` client defines the API base for flows as `/api/hosted/auth/flows` instead of the secured EIAA endpoint `/api/auth/flow`. 
**Impact:** `AuthFlowPage` is making requests to legacy or non-existent endpoints.

---

### BUG-12: Complete Lack of Ephemeral flow_token Integration
**Severity:** CRITICAL
**File:** `frontend/src/features/auth/AuthFlowPage.tsx`, `frontend/src/lib/api/hosted.ts`

**Details:** The backend requires a `flow_token` (returned from `init_flow`) to be present in the `Authorization: Bearer <token>` header for all subsequent auth flow requests (`identify`, `submit`, `complete`, `get`). The frontend state machine completely ignores this token.
**Impact:** All requests past `init` will return `401 Unauthorized`. The entire frontend authentication flow is blocked.

---

### BUG-13: Incorrect /submit Call for User Identification
**Severity:** CRITICAL
**File:** `frontend/src/lib/api/hosted.ts`

**Details:** The `AuthFlowPage` uses `hostedApi.submitStep` (which hits `/submit`) with `{ type: "email", value: "..." }` when the user submits an email layout constraint. This violates the backend's explicit `/api/auth/flow/:id/identify` endpoint, which expects an `IdentifyReq` structure `{ identifier: "..." }`.
**Impact:** Email submissions are routed to the wrong endpoint, further permanently blocking the entire auth flow.

---

## Part 5: User Journey Designs
*(Omitted for brevity - No changes from previous architecture)*

## Part 6: Navigation Architecture
*(Omitted for brevity - No changes from previous architecture)*

---

## Part 7: Prioritized Fix List

### P0 — Breaks Core Functionality

| ID | Issue | Effort | File | Fix |
|----|-------|--------|------|-----|
| BUG-11 | Out-of-sync flow API endpoints | S | `hosted.ts` | Change base route to `/api/auth/flow` |
| BUG-12 | Missing ephemeral `flow_token` handler | M | `AuthFlowPage.tsx`, `hosted.ts` | Extract `flow_token` from init response, attach as Bearer to all future flow requests. |
| BUG-13 | `/submit` used instead of `/identify` | M | `AuthFlowPage.tsx`, `hosted.ts` | Wire email extraction to call a new `identify` API method instead of `submitStep` |

### P2 — UX Improvements

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

---

## Part 8: API Path Consistency Reference
*(Omitted for brevity - No changes from previous architecture)*

---

## Part 9: Summary Scorecard

| Category | Coverage | Quality | Notes |
|----------|----------|---------|-------|
| **Auth Flow (EIAA)** | 0% | Broken | Needs total rewrite to match new backend security API |
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

**Overall Frontend Coverage: ~80%**
**Blocking Bugs (P0): 3** (BUG-11, 12, 13)
**Active Bugs: 5** (All of the above + BUG-9, 10)

---

## Part 10: Audit Change Log

| Date | Change |
|------|--------|
| March 2026 (initial) | First audit — 72% coverage, 8 bugs, 5 P1 gaps |
| March 2026 (updated) | Re-audit after sprint — Discovered severe regression in frontend auth flows. 3 new P0 bugs added regarding API paths and tokens. |

*Generated by Principal Architect Review — AuthStar Platform — March 2026*