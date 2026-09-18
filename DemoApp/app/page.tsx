'use client';

import Link from 'next/link';

/**
 * Landing page — visible to unauthenticated visitors.
 * Playwright tests verify this page is reachable without a JWT.
 */
export default function HomePage() {
  return (
    <main
      style={{
        maxWidth: 640,
        margin: '80px auto',
        padding: '0 24px',
        textAlign: 'center',
      }}
    >
      <h1 style={{ fontSize: 32, fontWeight: 800, marginBottom: 12 }}>
        AuthStar Demo App
      </h1>
      <p style={{ color: '#57606a', marginBottom: 32, fontSize: 16 }}>
        A reference client application powered by AuthStar IDaaS SDKs. Sign in
        as a human user or explore the AI agent authorization panel.
      </p>

      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
        <Link
          href="/sign-in"
          data-testid="btn-sign-in"
          style={{
            padding: '10px 24px',
            background: '#3b82d4',
            color: '#fff',
            borderRadius: 8,
            fontWeight: 600,
          }}
        >
          Sign In
        </Link>
        <Link
          href="/sign-up"
          data-testid="btn-sign-up"
          style={{
            padding: '10px 24px',
            background: '#fff',
            color: '#1f2328',
            border: '1px solid #d1d5db',
            borderRadius: 8,
            fontWeight: 600,
          }}
        >
          Sign Up
        </Link>
      </div>

      <p style={{ marginTop: 40, fontSize: 13, color: '#57606a' }}>
        Backend: <code data-testid="api-url">{process.env.NEXT_PUBLIC_AUTHSTAR_API_URL}</code>
      </p>
    </main>
  );
}
