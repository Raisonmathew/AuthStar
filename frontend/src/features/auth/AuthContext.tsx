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
import axios from 'axios';
import { User } from './types';

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
  /** Clear auth state and redirect to login */
  logout: () => void;
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
  const logout = useCallback(() => {
    tokenRef.current = null;
    // Clear module-level token so Axios interceptor stops sending it
    setInMemoryToken(null);
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    setState({
      user: null,
      token: null,
      isAuthenticated: false,
      organizationId: null,
      isLoading: false,
    });
    // FIX-FUNC-2: Correct logout URL. Backend mounts logout at /api/v1/logout
    // (logout_router nested under /api/v1 in router.rs), NOT /api/v1/auth/logout.
    // Previously this returned 404 so the HttpOnly refresh cookie was never cleared.
    axios.post('/api/v1/logout', {}, { withCredentials: true }).catch(() => {});
    window.location.href = loginPath;
  }, [loginPath]);

  // -------------------------------------------------------------------------
  // silentRefresh — exchange HttpOnly refresh cookie for a new access token
  // -------------------------------------------------------------------------
  const silentRefresh = useCallback(async (): Promise<boolean> => {
    try {
      const response = await axios.post(
        '/api/v1/token/refresh',
        {},
        { withCredentials: true }
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
  // On mount: attempt silent refresh to restore session after page reload.
  // The HttpOnly refresh cookie is sent automatically by the browser.
  // -------------------------------------------------------------------------
  useEffect(() => {
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
// getInMemoryToken — for use in the API client interceptor
// ---------------------------------------------------------------------------

/**
 * Returns the current in-memory access token without going through React.
 * Used by the Axios request interceptor to attach the Bearer token.
 *
 * CRITICAL-10+11 FIX: This replaces `sessionStorage.getItem('jwt')` in the
 * Axios interceptor. The token is stored in a module-level variable that is
 * only writable through setInMemoryToken() which is called by setAuth().
 *
 * This is intentionally a module-level variable (not React state) so that
 * the Axios interceptor — which runs outside React's render cycle — can
 * read the current token synchronously without hooks.
 */
let _inMemoryToken: string | null = null;

export function getInMemoryToken(): string | null {
  return _inMemoryToken;
}

/** Internal: called by AuthProvider.setAuth and AuthProvider.logout */
export function setInMemoryToken(token: string | null): void {
  _inMemoryToken = token;
}

// Made with Bob
