import type { Metadata } from 'next';
import { IDaaSProvider } from '@idaas/react';
import './globals.css';

export const metadata: Metadata = {
  title: 'AuthStar Demo App',
  description: 'Client application demonstrating AuthStar IDaaS SDK integration',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const publishableKey = process.env.NEXT_PUBLIC_AUTHSTAR_PUBLISHABLE_KEY!;
  const apiUrl = process.env.NEXT_PUBLIC_AUTHSTAR_API_URL!;

  return (
    <html lang="en">
      <body>
        {/*
          IDaaSProvider wraps the entire app.
          apiUrl override points to local Docker stack for dev/test.
        */}
        <IDaaSProvider publishableKey={publishableKey} apiUrl={apiUrl}>
          {children}
        </IDaaSProvider>
      </body>
    </html>
  );
}
