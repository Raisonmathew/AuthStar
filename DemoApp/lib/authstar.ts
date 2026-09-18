/**
 * Server-side AuthStar IDaaSClient singleton.
 *
 * Used in Next.js API route handlers and Server Components.
 * Operates in 'server' mode: Bearer token auth, no cookies/CSRF.
 *
 * Usage:
 *   import { serverClient } from '@/lib/authstar';
 *   serverClient.setToken(jwt);
 *   const user = await serverClient.getCurrentUser();
 */
import { IDaaSServerClient } from '@idaas/core';

const apiUrl = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

// A single client instance per Node.js process.
// In Vercel/Edge deployments each request is isolated, so this is effectively
// request-scoped. In a long-lived Node.js process you must call setToken() before
// each request.
export const serverClient = new IDaaSServerClient({
  apiUrl,
  apiKey: process.env.AUTHSTAR_SERVICE_API_KEY || '',
});
