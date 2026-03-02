# Sprint Closure Report — UX & Frontend Sprint

**Sprint**: UX & Frontend Completeness  
**Closed**: 2026-03-02  
**Engineer**: Bob (Principal Software Engineer / Architect)

---

## Executive Summary

This sprint closed the gap between the backend's rich feature set and the frontend's coverage of those features. The admin dashboard, audit log, MFA/passkey security page, and user profile page were all rebuilt with real API integration, replacing placeholder mocks and non-functional UI elements.

---

## Deliverables

### 1. UX_FRONTEND_AUDIT.md
Full gap analysis document covering:
- All frontend pages and their current state
- All backend API endpoints and their frontend coverage
- User journey flows for both Tenant Admin and End User personas
- Prioritised list of gaps with severity ratings

### 2. AdminDashboardPage.tsx — Complete Rewrite
**Before**: Hardcoded mock data, `setTimeout(() => setLoading(false), 500)`, no real API calls.  
**After**:
- `GET /api/admin/v1/audit/stats` → real stats (total executions, allow/deny counts, 24h/7d activity)
- `GET /api/admin/v1/audit?limit=8` → real recent activity feed with relative timestamps
- Skeleton loading states during fetch
- Error states with retry button
- Allow/deny rate visualisation bars
- Quick action buttons wired to `navigate()`

### 3. AuditLogPage.tsx — Complete Rewrite
**Before**: Filter buttons with no state, no API params, no pagination.  
**After**:
- Decision filter buttons (All / Allowed / Denied) wired to `?decision=` query param
- Action search input with debounce wired to `?action=` query param
- Cursor-based "Load More" pagination using `created_at` as cursor
- AbortController for in-flight request cancellation on filter change
- Handles both legacy array response and new paginated `{ items, nextCursor }` shape

### 4. MFAEnrollmentPage.tsx — Complete Rewrite
**Before**: Basic TOTP setup only, no passkeys, no backup codes.  
**After**:
- **Security Score bar** at top (computed from enabled factors)
- **TotpSection**: setup → QR code + manual key display → verify → enable; disable with confirmation
- **BackupCodesSection**: view codes, copy all to clipboard, download as `.txt`, regenerate with confirmation modal
- **PasskeysSection**: list registered passkeys with creation date, WebAuthn registration (begin/complete), delete passkey
- Fixed `base64urlToUint8Array` to return `ArrayBuffer` (not `Uint8Array`) — TypeScript strict mode compatibility with `PublicKeyCredentialCreationOptions`
- Correct API paths: `/api/mfa/...` and `/api/passkeys/...` (not `/api/v1/mfa/...`)

### 5. ProfilePage.tsx — ChangePasswordModal Added
**Before**: No way to change password from the UI.  
**After**:
- Inline `ChangePasswordModal` component with current/new/confirm password fields
- Client-side validation (min 8 chars, confirm match)
- Calls `POST /api/v1/user/change-password`
- "Change Password" and "Security Settings" quick action buttons

### 6. Backend: GET /api/admin/v1/audit/stats (NEW)
Single-query conditional aggregation endpoint:
```sql
SELECT
  COUNT(*) AS total_executions,
  COUNT(*) FILTER (WHERE decision = 'allow') AS allowed_count,
  COUNT(*) FILTER (WHERE decision = 'deny') AS denied_count,
  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS executions_last_24h,
  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS executions_last_7d,
  COUNT(DISTINCT action) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS unique_actions_last_7d
FROM eiaa_executions e
JOIN capsules c ON c.id = e.capsule_id
WHERE c.tenant_id = $1
```

### 7. Backend: GET /api/admin/v1/audit — Filter + Cursor Pagination
**Before**: No filtering, no pagination.  
**After**:
- `?decision=allowed|denied` filter
- `?action=<string>` filter (ILIKE)
- `?cursor=<ISO timestamp>` cursor-based pagination (`WHERE created_at < cursor`)
- `?limit=N` (default 20, max 100)
- Returns `{ items: [...], nextCursor: "..." | null }`

### 8. Backend: PATCH /api/v1/user (NEW)
Update authenticated user's display name and/or profile image.  
Delegates to `UserService::update_user()` which uses `COALESCE` for partial updates.

### 9. Backend: POST /api/v1/user/change-password (NEW)
Change authenticated user's password.  
Delegates to `UserService::change_password()` which:
1. Validates new password complexity (`shared_types::validation::validate_password`)
2. Verifies current password (re-authentication guard, account lockout aware)
3. Checks password history (last 10 passwords cannot be reused — migration 030)
4. Atomically updates `passwords` table + inserts into `password_history`

After successful change: invalidates all other sessions (`UPDATE sessions SET expires_at = NOW() WHERE user_id = $1 AND id != $2`).

---

## Architecture Decisions

### Service Layer Delegation
`profile.rs` initially duplicated raw SQL for password hashing and history. Corrected to delegate entirely to `UserService::change_password()` and `UserService::update_user()` — the canonical service layer methods that already handle all edge cases (account lockout, password history, atomic transactions).

### EIAA Action for Profile Routes
Profile routes use `"user:manage_factors"` EIAA action (same as user factors) rather than a new `"user:manage_profile"` action. This avoids requiring a new capsule deployment for a low-risk operation. A dedicated `"user:profile:write"` action can be introduced in a future sprint if finer-grained control is needed.

### Cursor Pagination over Offset
Audit log uses `created_at` timestamp as cursor rather than `OFFSET`. This is correct for high-volume append-only tables — `OFFSET N` requires scanning N rows on every page, while cursor pagination is O(log N) via the existing `created_at` index.

---

## Known Limitations / Future Work

| Item | Priority | Notes |
|------|----------|-------|
| AppRegistryPage — create/edit app modal | High | `AppModal.tsx` exists but `POST /api/v1/apps` not wired in frontend |
| LoginMethodsPage — save button | High | UI exists but `PATCH /api/v1/org/auth-config` not called |
| Org Settings — domain verification UI | Medium | Backend `/api/domains` exists, no frontend page |
| Admin user management page | Medium | No frontend page for listing/managing tenant users |
| Profile image upload | Low | `profile_image_url` field exists in DB and API, no upload UI |
| TypeScript strict null checks | Low | Several pages use `!` non-null assertions that should be guarded |

---

## Files Changed

### Backend
| File | Change |
|------|--------|
| `routes/admin/audit.rs` | Added `get_stats` handler, rewrote `list_executions` with filters + cursor pagination |
| `routes/user/profile.rs` | **NEW** — `update_profile` + `change_password` handlers |
| `routes/user/mod.rs` | Added `pub mod profile` |
| `router.rs` | Added `user_profile_routes` Router, merged into final router |

### Frontend
| File | Change |
|------|--------|
| `features/dashboard/AdminDashboardPage.tsx` | Complete rewrite — real API calls, skeleton loading, error states |
| `features/audit/AuditLogPage.tsx` | Complete rewrite — decision filter, action search, cursor pagination |
| `pages/MFAEnrollmentPage.tsx` | Complete rewrite — TOTP + backup codes + passkeys sections |
| `pages/ProfilePage.tsx` | Added `ChangePasswordModal`, wired quick actions |

### Documentation
| File | Change |
|------|--------|
| `UX_FRONTEND_AUDIT.md` | **NEW** — full gap analysis |
| `SPRINT_CLOSURE_REPORT.md` | **NEW** — this document |