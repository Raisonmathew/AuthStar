'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import AgentPanel from '@/components/AgentPanel';

/**
 * Protected dashboard page.
 *
 * Verifies the demo_jwt in sessionStorage is present before rendering.
 * Playwright tests:
 *   - Accessing /dashboard without a JWT redirects to /sign-in
 *   - After successful sign-in, dashboard renders user info + agent panel
 */
export default function DashboardPage() {
  const router = useRouter();
  const [jwt, setJwt] = useState<string | null>(null);
  const [user, setUser] = useState<{ email?: string; firstName?: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const stored = sessionStorage.getItem('demo_jwt');
    if (!stored) {
      router.replace('/sign-in');
      return;
    }
    setJwt(stored);

    // Fetch current user from backend using the stored JWT
    const apiBase = process.env.NEXT_PUBLIC_AUTHSTAR_API_URL!;
    fetch(`${apiBase}/api/v1/user`, {
      headers: { Authorization: `Bearer ${stored}` },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((u) => {
        if (u) setUser(u);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [router]);

  function handleSignOut() {
    sessionStorage.removeItem('demo_jwt');
    sessionStorage.removeItem('active_org_id');
    router.push('/');
  }

  if (loading) {
    return (
      <main style={{ maxWidth: 800, margin: '80px auto', padding: '0 24px', textAlign: 'center' }}>
        <p data-testid="dashboard-loading">Loading…</p>
      </main>
    );
  }

  if (!jwt) return null; // redirect in progress

  return (
    <main style={{ maxWidth: 800, margin: '40px auto', padding: '0 24px' }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 32,
          paddingBottom: 16,
          borderBottom: '1px solid #e5e7eb',
        }}
      >
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>Dashboard</h1>
          {user && (
            <p data-testid="user-email" style={{ color: '#57606a', fontSize: 14 }}>
              {user.firstName ?? ''} · {user.email}
            </p>
          )}
        </div>
        <button
          data-testid="btn-sign-out"
          onClick={handleSignOut}
          style={{
            padding: '8px 16px',
            background: '#fff',
            border: '1px solid #d1d5db',
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 500,
          }}
        >
          Sign out
        </button>
      </div>

      {/* Agent authorization panel */}
      <section>
        <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>AI Agent Authorization Panel</h2>
        <AgentPanel jwt={jwt} />
      </section>
    </main>
  );
}
