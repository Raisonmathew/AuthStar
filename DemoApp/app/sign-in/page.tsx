'use client';

import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

/**
 * Sign-in page.
 *
 * Walks the EIAA auth flow via the AuthStar backend:
 *   1. GET  /api/csrf-token
 *   2. POST /api/auth/flow/init          → flow_id, flow_token
 *   3. POST /api/auth/flow/:id/identify  → identify user by email
 *   4. POST /api/auth/flow/:id/submit    → submit password (capability=password)
 *   5. POST /api/auth/flow/:id/complete  → issue JWT, set refresh cookie
 *
 * On success the JWT is stored in sessionStorage['demo_jwt'] and the user
 * is redirected to /dashboard.
 *
 * Playwright tests exercise both the happy path and the invalid-password path.
 */
export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const apiBase = process.env.NEXT_PUBLIC_AUTHSTAR_API_URL!;

      // Step 1: CSRF token
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      if (!csrfRes.ok) throw new Error('Failed to fetch CSRF token');
      const { csrf_token: csrfToken } = await csrfRes.json();
      const baseHeaders = {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        Origin: window.location.origin,
      };

      // Step 2: Init flow
      const initRes = await fetch(`${apiBase}/api/auth/flow/init`, {
        method: 'POST',
        credentials: 'include',
        headers: baseHeaders,
        body: JSON.stringify({ org_id: 'system' }),
      });
      if (!initRes.ok) throw new Error('Flow init failed');
      const { flow_id, flow_token } = await initRes.json();
      const flowHeaders = { ...baseHeaders, Authorization: `Bearer ${flow_token}` };

      // Step 3: Identify
      await fetch(`${apiBase}/api/auth/flow/${flow_id}/identify`, {
        method: 'POST',
        credentials: 'include',
        headers: flowHeaders,
        body: JSON.stringify({ identifier: email }),
      });

      // Step 4: Submit password
      const submitRes = await fetch(`${apiBase}/api/auth/flow/${flow_id}/submit`, {
        method: 'POST',
        credentials: 'include',
        headers: flowHeaders,
        body: JSON.stringify({ capability: 'password', value: password }),
      });
      if (!submitRes.ok) {
        const body = await submitRes.json().catch(() => ({}));
        throw new Error(body.message || 'Invalid credentials');
      }
      const submitBody = await submitRes.json();
      if (!submitBody.success) throw new Error('Password verification failed');

      // Step 5: Complete flow
      const completeRes = await fetch(`${apiBase}/api/auth/flow/${flow_id}/complete`, {
        method: 'POST',
        credentials: 'include',
        headers: flowHeaders,
      });
      if (!completeRes.ok) throw new Error('Flow completion failed');
      const completeBody = await completeRes.json();
      const jwt = completeBody.jwt || completeBody.token;
      if (!jwt) throw new Error('No JWT in response');

      // Store JWT in sessionStorage (demo convenience — NOT the same as AuthContext
      // which keeps the JWT in memory only; sessionStorage is used here purely
      // for demo-app state so Playwright can read it from page.evaluate).
      sessionStorage.setItem('demo_jwt', jwt);
      sessionStorage.setItem('active_org_id', completeBody.tenant_id || 'system');

      router.push('/dashboard');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Sign in failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 24px' }}>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Sign in</h1>
      <p style={{ color: '#57606a', fontSize: 14, marginBottom: 24 }}>
        Sign in to your AuthStar demo account
      </p>

      <form onSubmit={handleSubmit} data-testid="sign-in-form">
        <div style={{ marginBottom: 16 }}>
          <label htmlFor="email" style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>
            Email
          </label>
          <input
            id="email"
            type="email"
            data-testid="input-email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: 6,
              fontSize: 14,
            }}
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label htmlFor="password" style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>
            Password
          </label>
          <input
            id="password"
            type="password"
            data-testid="input-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: 6,
              fontSize: 14,
            }}
          />
        </div>

        {error && (
          <p
            data-testid="sign-in-error"
            style={{ color: '#dc2626', fontSize: 13, marginBottom: 12 }}
          >
            {error}
          </p>
        )}

        <button
          type="submit"
          data-testid="btn-submit"
          disabled={loading}
          style={{
            width: '100%',
            padding: '10px',
            background: '#3b82d4',
            color: '#fff',
            border: 'none',
            borderRadius: 8,
            fontWeight: 600,
            fontSize: 15,
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p style={{ marginTop: 16, fontSize: 13, textAlign: 'center' }}>
        No account? <Link href="/sign-up">Sign up</Link>
      </p>
    </main>
  );
}
