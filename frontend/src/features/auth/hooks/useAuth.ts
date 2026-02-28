/**
 * CRITICAL-10+11 FIX: useAuth now reads from React Context (in-memory),
 * NOT from localStorage or sessionStorage.
 *
 * This file is kept for backward compatibility — all existing imports of
 * `useAuth` from this path continue to work without changes.
 *
 * The actual implementation lives in AuthContext.tsx.
 */
export { useAuth } from '../AuthContext';
