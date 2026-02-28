/**
 * STRUCT-1 FIX: This file is a compatibility shim.
 *
 * The old `api.ts` created an axios instance that read tokens from
 * `localStorage` / `sessionStorage`, which is a security vulnerability
 * (XSS can steal tokens from Web Storage).
 *
 * The new `api/client.ts` creates an `APIClient` that:
 *   - Reads the JWT from the in-memory `AuthContext` store (not Web Storage)
 *   - Sends the HttpOnly refresh cookie automatically via `withCredentials: true`
 *   - Verifies EIAA attestation signatures on every response
 *   - Handles 401 → silent token refresh automatically
 *
 * All imports of `{ api } from '../../lib/api'` now receive the secure client.
 * No other files need to be changed.
 *
 * The step-up interceptor (403 → StepUpModal) that was in the old api.ts is
 * now handled by the global `StepUpModal` component listening to the
 * `AUTH_STEP_UP_REQUIRED` custom event dispatched by the response interceptor
 * in `api/client.ts`.
 */
export { api } from './api/client';

// Re-export the ApiError type for backward compatibility
export type { ApiError } from './api/client';

// Made with Bob
