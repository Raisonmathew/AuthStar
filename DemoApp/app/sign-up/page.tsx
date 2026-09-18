'use client';

import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

/**
 * Sign-up page.
 *
 * Calls POST /api/v1/auth/signup directly via IDaaSClient.signUp().
 * On success stores demo_jwt in sessionStorage and redirects to /dashboard.
 * Playwright tests verify field validation and successful registration.
 */
export default function SignUpPage() {
  const router = useRouter();
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
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

      // Fetch CSRF token first (signup is a state-mutating POST)
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      const { csrf_token: csrfToken } = await csrfRes.json();

      const res = await fetch(`${apiBase}/api/v1/auth/signup`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          Origin: window.location.origin,
        },
        body: JSON.stringify({ email, password, first_name: firstName, last_name: lastName }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message || `Signup failed (${res.status})`);
      }

      const body = await res.json();
      if (body.jwt) {
        sessionStorage.setItem('demo_jwt', body.jwt);
      }

      router.push('/dashboard');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Sign up failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 24px' }}>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Create account</h1>
      <p style={{ color: '#57606a', fontSize: 14, marginBottom: 24 }}>
        Sign up for the AuthStar demo app
      </p>

      <form onSubmit={handleSubmit} data-testid="sign-up-form">
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <div style={{ flex: 1 }}>
            <label htmlFor="firstName" style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>
              First name
            </label>
            <input
              id="firstName"
              type="text"
              data-testid="input-first-name"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14 }}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label htmlFor="lastName" style={{ display: 'block', fontSize: 14, fontWeight: 500, marginBottom: 4 }}>
              Last name
            </label>
            <input
              id="lastName"
              type="text"
              data-testid="input-last-name"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14 }}
            />
          </div>
        </div>

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
            style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14 }}
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
            style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14 }}
          />
        </div>

        {error && (
          <p data-testid="sign-up-error" style={{ color: '#dc2626', fontSize: 13, marginBottom: 12 }}>
            {error}
          </p>
        )}

        <button
          type="submit"
          data-testid="btn-submit"
          disabled={loading}
          style={{
            width: '100%', padding: '10px', background: '#3b82d4', color: '#fff',
            border: 'none', borderRadius: 8, fontWeight: 600, fontSize: 15,
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <p style={{ marginTop: 16, fontSize: 13, textAlign: 'center' }}>
        Already have an account? <Link href="/sign-in">Sign in</Link>
      </p>
    </main>
  );
}
