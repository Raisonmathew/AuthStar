/**
 * CRITICAL-10+11 FIX: In-memory auth token store.
 *
 * Previously, JWTs were stored in sessionStorage and admin tokens in localStorage.
 * Both are accessible to any JavaScript running on the page (XSS attack surface).
 *
 * Fix:
 * - Access tokens (JWTs) are stored ONLY in memory (React Context / module-level variable).
 *   They are never written to Web Storage.
 * - The refresh token is stored in an HttpOnly cookie set by the backend — it is
 *   never accessible to JavaScript at all.
 * - On page reload, the client calls /api/v1/token/refresh (which sends the HttpOnly
 *   cookie automatically) to silently re-issue a new access token.
 * - The AuthContext provides reactive state so all components re-render on auth changes.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { User } from './types';
import { getInMemoryToken, setInMemoryToken } from '../../lib/auth-storage';
import { api } from '../../lib/api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthState {
  user: User | null;
  /** In-memory access token — NEVER stored in Web Storage */
  token: string | null;
  isAuthenticated: boolean;
  organizationId: string | null;
  /** True while the initial silent refresh is in progress */
  isLoading: boolean;
}

export interface AuthContextValue extends AuthState {
  /** Call after a successful login to store the token in memory */
  setAuth: (token: string, user: User) => void;
  /** Clear auth state, invalidate refresh cookie, and redirect to login */
  logout: () => Promise<void>;
  /** Attempt a silent token refresh using the HttpOnly refresh cookie */
  silentRefresh: () => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const AuthContext = createContext<AuthContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface AuthProviderProps {
  children: React.ReactNode;
  /** Override the login redirect path (default: '/sign-in') */
  loginPath?: string;
}

export function AuthProvider({ children, loginPath = '/sign-in' }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    token: null,
    isAuthenticated: false,
    organizationId: null,
    isLoading: true, // Start loading until silent refresh completes
  });

  // Keep a ref so the refresh interval closure always sees the latest token
  const tokenRef = useRef<string | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // -------------------------------------------------------------------------
  // setAuth — called after successful login
  // -------------------------------------------------------------------------
  const setAuth = useCallback((token: string, user: User) => {
    tokenRef.current = token;
    // Sync to module-level variable so Axios interceptor can read it
    setInMemoryToken(token);
    // Persist user for HMR restoration (dev-only)
    if (import.meta.hot) {
      import.meta.hot.data.user = user;
    }
    setState({
      user,
      token,
      isAuthenticated: true,
      organizationId: user.organization_id || null,
      isLoading: false,
    });
    scheduleRefresh();
  }, []); // intentionally empty — runs once on mount
  // -------------------------------------------------------------------------
  const logout = useCallback(async () => {
    // Capture redirect destination BEFORE clearing state, because React
    // re-renders may trigger route guards that change window.location.pathname
    const dest = window.location.pathname.startsWith('/admin') ? '/u/admin' : loginPath;

    tokenRef.current = null;
    // Clear module-level token so Axios interceptor stops sending it
    setInMemoryToken(null);
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }

    // Invalidate the HttpOnly refresh cookie BEFORE clearing React state.
    // The old code fired api.post() then immediately set window.location.href,
    // which aborted the inflight request and left the cookie alive.
    try {
      await api.post('/api/v1/logout', {});
    } catch {
      // Best-effort — cookie may already be expired
    }

    // Hard-navigate BEFORE updating React state to avoid route-guard races.
    // Setting window.location.href triggers a full page load, so the
    // setState below never actually renders.
    window.location.href = dest;
  }, [loginPath]);

  // -------------------------------------------------------------------------
  // silentRefresh — exchange HttpOnly refresh cookie for a new access token
  // -------------------------------------------------------------------------
  const silentRefresh = useCallback(async (): Promise<boolean> => {
    try {
      const response = await api.post(
        '/api/v1/token/refresh',
        {}
      );
      const { jwt, user } = response.data as { jwt: string; user: User };
      setAuth(jwt, user);
      return true;
    } catch {
      // Refresh cookie expired or invalid — user must log in again
      tokenRef.current = null;
      setState({
        user: null,
        token: null,
        isAuthenticated: false,
        organizationId: null,
        isLoading: false,
      });
      return false;
    }
  }, [setAuth]);

  // -------------------------------------------------------------------------
  // scheduleRefresh — proactive token refresh every 14 minutes
  // (access tokens expire in 15 minutes)
  // -------------------------------------------------------------------------
  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
    }
    refreshTimerRef.current = setInterval(async () => {
      if (tokenRef.current) {
        const ok = await silentRefresh();
        if (!ok) {
          // Refresh failed — session expired, redirect to login
          logout();
        }
      }
    }, 14 * 60 * 1000);
  }, [silentRefresh, logout]);

  // -------------------------------------------------------------------------
  // On mount: restore session. If HMR preserved the token, skip the network
  // call and hydrate from the in-memory store directly.
  // -------------------------------------------------------------------------
  useEffect(() => {
    const existingToken = getInMemoryToken();
    if (existingToken) {
      // HMR preserved the token — restore session instantly, no network call
      const hmrUser = import.meta.hot?.data?.user as User | undefined;
      if (hmrUser) {
        setAuth(existingToken, hmrUser);
        return;
      }
      // Fallback: decode minimal user from JWT payload
      try {
        const payload = JSON.parse(atob(existingToken.split('.')[1]));
        const restoredUser: User = {
          id: payload.sub,
          email: payload.email ?? '',
          first_name: payload.first_name ?? '',
          last_name: payload.last_name ?? '',
          organization_id: payload.org_id ?? payload.tenant_id ?? undefined,
          created_at: '',
          profile_image_url: null,
          email_verified: false,
          phone: null,
          phone_verified: false,
          mfa_enabled: false,
        };
        setAuth(existingToken, restoredUser);
        return;
      } catch {
        // Token is malformed — fall through to silent refresh
      }
    }

    silentRefresh().then((ok: boolean) => {
      if (!ok) {
        setState((prev: AuthState) => ({ ...prev, isLoading: false }));
      }
    });

    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, []); // intentionally empty — runs once on mount

  const value: AuthContextValue = {
    ...state,
    setAuth,
    logout,
    silentRefresh,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useAuth — returns the current auth state and actions.
 *
 * CRITICAL-10+11 FIX: This hook now reads from React Context (in-memory),
 * NOT from localStorage or sessionStorage. The token is never persisted to
 * Web Storage and is therefore not accessible to XSS attacks.
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return ctx;
}

// ---------------------------------------------------------------------------

// getInMemoryToken and setInMemoryToken have moved to lib/auth-storage.tsx
// to break circular dependencies. They are re-exported here for backward
// compatibility.
export { getInMemoryToken, setInMemoryToken } from '../../lib/auth-storage';

