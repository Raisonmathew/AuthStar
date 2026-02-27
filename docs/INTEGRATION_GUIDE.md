# Integration Guide: Adding IDaaS to Your React Application

Complete guide for integrating the IDaaS Platform into your React application.

## 🚀 Quick Start (5 Minutes)

### 1. Copy the API Client

Copy the `src/lib/api.ts` file provided in the repository to your project. This file contains the Axios instance configured for the IDaaS backend.

### 2. Configure Environment Variables

Create `.env` file:
```env
VITE_API_URL=http://localhost:3000
```

### 3. Initialize the Client

The API client is automatically initialized when imported.

```typescript
// src/lib/api.ts
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
});

// Add auth interceptor
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('jwt');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

---

## 📚 Complete Integration Steps

### Step 1: Create Authentication Context

```typescript
// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../lib/api';

interface User {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string, firstName?: string, lastName?: string) => Promise<void>;
  signOut: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    const checkAuth = async () => {
      const token = sessionStorage.getItem('jwt');
      if (token) {
        try {
          // Verify token and get user (implementation depends on your backend route)
          const { data } = await api.get('/api/v1/user');
          setUser(data);
        } catch (error) {
          sessionStorage.removeItem('jwt');
        }
      }
      setLoading(false);
    };

    checkAuth();
  }, []);

  const signIn = async (email: string, password: string) => {
    // See backend/crates/api_server/src/routes/auth.rs for payload structure
    const { data } = await api.post('/api/v1/sign-in', { 
        identifier: email, 
        password 
    });
    
    sessionStorage.setItem('jwt', data.jwt);
    setUser(data.user);
  };

  const signUp = async (email: string, password: string, firstName?: string, lastName?: string) => {
    await api.post('/api/v1/sign-up', { 
        email, 
        password, 
        firstName, 
        lastName 
    });
  };

  const signOut = async () => {
    // Optional: Call backend to revoke session
    sessionStorage.removeItem('jwt');
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        signIn,
        signUp,
        signOut,
        isAuthenticated: !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
```

### Step 2: Wrap Your App with AuthProvider

```typescript
// src/main.tsx or src/App.tsx
import { AuthProvider } from './contexts/AuthContext';

function App() {
  return (
    <AuthProvider>
      <YourAppRoutes />
    </AuthProvider>
  );
}
```

### Step 3: Create Protected Route Component

```typescript
// src/components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/sign-in" replace />;
  }

  return <>{children}</>;
}
```

### Step 4: Create Sign In Component

```typescript
// src/pages/SignIn.tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function SignIn() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { signIn } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await signIn(email, password);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Sign in failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required
      />
      {error && <p className="error">{error}</p>}
      <button type="submit">Sign In</button>
    </form>
  );
}
```

### Step 5: Set Up Routes

```typescript
// src/App.tsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from './components/ProtectedRoute';
import { SignIn } from './pages/SignIn';
import { SignUp } from './pages/SignUp';
import { Dashboard } from './pages/Dashboard';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/sign-in" element={<SignIn />} />
          <Route path="/sign-up" element={<SignUp />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
```

---

## 🏢 Organization Support (Multi-Tenant)

### Organization Context

```typescript
// src/contexts/OrganizationContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../lib/api';

interface Organization {
  id: string;
  name: string;
  slug: string;
}

interface OrgContextType {
  organizations: Organization[];
  activeOrg: Organization | null;
  switchOrganization: (orgId: string) => void;
  createOrganization: (name: string) => Promise<void>;
}

const OrganizationContext = createContext<OrgContextType | undefined>(undefined);

export function OrganizationProvider({ children }: { children: React.ReactNode }) {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);

  useEffect(() => {
    loadOrganizations();
  }, []);

  const loadOrganizations = async () => {
    const { data: orgs } = await api.get('/api/v1/organizations');
    setOrganizations(orgs);
    
    const savedOrgId = sessionStorage.getItem('active_org_id');
    if (savedOrgId) {
      const org = orgs.find((o: Organization) => o.id === savedOrgId);
      if (org) setActiveOrg(org);
    } else if (orgs.length > 0) {
      setActiveOrg(orgs[0]);
    }
  };

  const switchOrganization = (orgId: string) => {
    const org = organizations.find(o => o.id === orgId);
    if (org) {
      setActiveOrg(org);
      sessionStorage.setItem('active_org_id', orgId);
    }
  };

  const createOrganization = async (name: string) => {
    const { data: newOrg } = await api.post('/api/v1/organizations', { name });
    setOrganizations([...organizations, newOrg]);
    switchOrganization(newOrg.id);
  };

  return (
    <OrganizationContext.Provider
      value={{
        organizations,
        activeOrg,
        switchOrganization,
        createOrganization,
      }}
    >
      {children}
    </OrganizationContext.Provider>
  );
}

export function useOrganization() {
  const context = useContext(OrganizationContext);
  if (!context) {
    throw new Error('useOrganization must be used within OrganizationProvider');
  }
  return context;
}
```

---

## 🔐 Advanced Features

### MFA Enrollment

```typescript
import { api } from '../lib/api';

// Setup MFA
const setupMFA = async () => {
    // defined in backend/crates/api_server/src/routes/mfa.rs
    const { data } = await api.post('/api/v1/mfa/totp/setup');
    setQrCode(data.qrCodeUri);
    setSecret(data.secret);
    setBackupCodes(data.manualEntryKey); // or fetch backup codes separately
};

// Verify and enable
const verifyMFA = async (code: string) => {
    await api.post('/api/v1/mfa/totp/verify', { code });
    // MFA now enabled
};
```

### Permission-Based Access Control

```typescript
// src/hooks/usePermissions.ts
import { useState, useEffect } from 'react';
import { useOrganization } from '../contexts/OrganizationContext';

export function usePermissions() {
  const { activeOrg } = useOrganization();
  const [permissions, setPermissions] = useState<string[]>([]);

  useEffect(() => {
    // Permissions are included in JWT claims
    const token = sessionStorage.getItem('jwt');
    if (token) {
      const payload = JSON.parse(atob(token.split('.')[1]));
      setPermissions(payload.org_permissions || []);
    }
  }, [activeOrg]);

  const hasPermission = (permission: string) => {
    return permissions.includes(permission) || permissions.includes('*');
  };

  return { permissions, hasPermission };
}

// Usage in component
function TeamSettings() {
  const { hasPermission } = usePermissions();

  if (!hasPermission('team:manage')) {
    return <p>Access denied</p>;
  }

  return <TeamManagementUI />;
}
```

### Subscription & Billing

```typescript
// Check subscription status
const { hasPermission } = usePermissions();

// Check subscription status
const checkFeatureAccess = async (feature: string) => {
  try {
      const { data: subscription } = await api.get('/api/v1/billing/subscription', {
          params: { org_id: activeOrg.id }
      });
      
      if (!subscription || subscription.status !== 'active') {
        return false;
      }
      
      // Check plan tier
      const plan = subscription.plan.name;
      return plan === 'Pro' || plan === 'Enterprise';
  } catch (e) {
      return false;
  }
};

// Subscribe to a plan
const subscribe = async (priceId: string) => {
  const { data } = await api.post('/api/v1/billing/checkout', {
      org_id: activeOrg.id,
      price_id: priceId,
      success_url: window.location.origin + '/dashboard?success=true',
      cancel_url: window.location.origin + '/billing?canceled=true',
  });
  
  if (data.url) {
    // Redirect to Stripe checkout
    window.location.href = data.url;
  }
};
```

---



```typescript

```

---

## 🔧 Configuration Options

### Custom API Client Configuration

```typescript
// Configuration is handled directly in src/lib/api.ts
// You can customize the Axios instance there.
```

---

### EIAA Verification (Security)

Secure your application by verifying attestation signatures returned by the EIAA runtime.

1. **Copy `src/lib/attestation.ts`** to your project.
2. **Add Interceptor** to verify attestations automatically.

```typescript
import { verifyAttestation } from './lib/attestation';

api.interceptors.response.use(async (response) => {
  if (response.data.attestation) {
    const result = await verifyAttestation(response.data.attestation);
    if (!result.valid) {
      throw new Error('Security Alert: Invalid attestation signature!');
    }
  }
  return response;
});
```

---

## 📈 SaaS Improvement Suggestions

To take your IDaaS platform to the next level, consider implementing these features:

### 1. Developer Experience (DX)
- **NPM Package**: Convert the local `api.ts` and `attestation.ts` into a real `@idaas/client` package.
- **CLI Tool**: Create an `idaas` CLI for managing policies and tenants from the terminal.

### 2. Security & Compliance
- **Enforce MFA**: Add a tenant-level setting to force MFA for all admins.
- **Session Revocation**: Add a UI to view active sessions and revoke them (backend support exists).

### 3. Business Logic
- **Usage-Based Billing**: Track active users (MAU) and report to Stripe for metered billing.
- **Audit Logs API**: Expose the `eiaa_executions` table via API so tenants can audit their own security.

---

---

## 🚀 Deployment Checklist

- [ ] Set production API URL in environment variables
- [ ] Configure CORS on IDaaS backend for your domain
- [ ] Set up proper error boundaries
- [ ] Implement loading states
- [ ] Add retry logic for network failures
- [ ] Test token refresh flow
- [ ] Verify logout clears all state
- [ ] Test protected routes
- [ ] Implement session timeout handling

---

## 🔍 Troubleshooting

### Issue: "401 Unauthorized" errors

**Solution**: Check if JWT is being sent in Authorization header

```typescript
// Verify token exists
const token = sessionStorage.getItem('jwt');
console.log('Token:', token);

// Check if axios is configured correctly
import { api } from '../lib/api';

api.interceptors.request.use(config => {
  console.log('Request headers:', config.headers);
  return config;
});
```

### Issue: CORS errors

**Solution**: Configure backend CORS

```rust
// backend: Allow your frontend domain
CorsLayer::new()
    .allow_origin("https://your-app.com".parse::<HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST])
    .allow_credentials(true)
```

---

## 📚 Complete Example

See `examples/react-integration` for a complete working example with:
- TypeScript
- Tailwind CSS  
- Protected routes
- Organization switching
- MFA enrollment
- Billing integration

---

## 🎯 Next Steps

1. ✅ Install SDK
2. ✅ Set up AuthProvider
3. ✅ Create sign-in/sign-up pages
4. ✅ Add protected routes
5. ✅ Implement organization switching (optional)
6. ✅ Add MFA support (optional)
7. ✅ Integrate billing (optional)

**Your app now has enterprise-grade authentication! 🎉**
