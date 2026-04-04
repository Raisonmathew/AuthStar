import { render, waitFor, act } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { AuthProvider, useAuth, getInMemoryToken, setInMemoryToken } from './AuthContext';

// Mock axios
vi.mock('axios', () => ({
  default: {
    post: vi.fn(),
  },
}));

// Helper component that exposes auth context
function AuthConsumer({ onAuth }: { onAuth: (ctx: ReturnType<typeof useAuth>) => void }) {
  const ctx = useAuth();
  onAuth(ctx);
  return <div data-testid="consumer">{ctx.isAuthenticated ? 'authed' : 'guest'}</div>;
}

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setInMemoryToken(null);
  });

  afterEach(() => {
    // no-op
  });

  describe('getInMemoryToken / setInMemoryToken', () => {
    it('starts null', () => {
      expect(getInMemoryToken()).toBeNull();
    });

    it('stores and retrieves a token', () => {
      setInMemoryToken('test-jwt');
      expect(getInMemoryToken()).toBe('test-jwt');
    });

    it('clears token when set to null', () => {
      setInMemoryToken('token');
      setInMemoryToken(null);
      expect(getInMemoryToken()).toBeNull();
    });
  });

  describe('AuthProvider', () => {
    it('starts loading and attempts silent refresh on mount', async () => {
      (axios.post as any).mockRejectedValue(new Error('no cookie'));

      let captured: any;
      render(
        <AuthProvider>
          <AuthConsumer onAuth={(ctx) => { captured = ctx; }} />
        </AuthProvider>
      );

      // Should start in loading state
      await waitFor(() => {
        expect(captured.isLoading).toBe(false);
      });
      expect(captured.isAuthenticated).toBe(false);
    });

    it('authenticates after successful silent refresh', async () => {
      const mockUser = { id: 'u1', email: 'a@b.com', organization_id: 'org1' };
      (axios.post as any).mockResolvedValue({
        data: { jwt: 'fresh-token', user: mockUser },
      });

      let captured: any;
      render(
        <AuthProvider>
          <AuthConsumer onAuth={(ctx) => { captured = ctx; }} />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(captured.isAuthenticated).toBe(true);
      });
      expect(captured.token).toBe('fresh-token');
      expect(captured.user).toEqual(mockUser);
      expect(captured.organizationId).toBe('org1');
      expect(getInMemoryToken()).toBe('fresh-token');
    });

    it('setAuth stores token in memory and updates state', async () => {
      (axios.post as any).mockRejectedValue(new Error('no cookie'));

      let captured: any;
      render(
        <AuthProvider>
          <AuthConsumer onAuth={(ctx) => { captured = ctx; }} />
        </AuthProvider>
      );

      await waitFor(() => expect(captured.isLoading).toBe(false));

      const user = { id: 'u2', email: 'b@c.com', organization_id: null };
      act(() => {
        captured.setAuth('new-jwt', user);
      });

      expect(captured.isAuthenticated).toBe(true);
      expect(captured.token).toBe('new-jwt');
      expect(getInMemoryToken()).toBe('new-jwt');
    });

    it('logout clears token and posts to /api/v1/logout', async () => {
      const mockUser = { id: 'u1', email: 'a@b.com', organization_id: 'org1' };
      (axios.post as any).mockResolvedValue({
        data: { jwt: 'tok', user: mockUser },
      });

      // Mock location
      const originalLocation = window.location;
      Object.defineProperty(window, 'location', {
        writable: true,
        value: { ...originalLocation, href: '' },
      });

      let captured: any;
      render(
        <AuthProvider loginPath="/sign-in">
          <AuthConsumer onAuth={(ctx) => { captured = ctx; }} />
        </AuthProvider>
      );

      await waitFor(() => expect(captured.isAuthenticated).toBe(true));

      act(() => {
        captured.logout();
      });

      expect(captured.isAuthenticated).toBe(false);
      expect(captured.token).toBeNull();
      expect(getInMemoryToken()).toBeNull();
      // Should call backend logout endpoint
      expect(axios.post).toHaveBeenCalledWith('/api/v1/logout', {}, { withCredentials: true });
      expect(window.location.href).toBe('/sign-in');

      // Restore
      Object.defineProperty(window, 'location', {
        writable: true,
        value: originalLocation,
      });
    });

    it('useAuth throws outside AuthProvider', () => {
      expect(() => {
        function Orphan() {
          useAuth();
          return null;
        }
        render(<Orphan />);
      }).toThrow('useAuth must be used within an <AuthProvider>');
    });
  });
});
