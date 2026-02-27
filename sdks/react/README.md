# @idaas/react

Pre-built React components for instant IDaaS integration.

## Installation

```bash
npm install @idaas/react
```

## Quick Start (1 Minute!)

### Step 1: Wrap Your App with IDaaSProvider

```tsx
import { IDaaSProvider } from '@idaas/react';

function App() {
  return (
    <IDaaSProvider publishableKey={process.env.REACT_APP_IDAAS_KEY}>
      {/* Your app components */}
    </IDaaSProvider>
  );
}
```

**Publishable Key Format:**
- Test environment: `pk_test_yourinstance`
- Production: `pk_live_yourinstance`

The SDK automatically maps your key to the correct API endpoint!
```

### Step 2: Use Components (No Config Needed!)

```tsx
import { SignIn, SignUp, UserButton } from '@idaas/react';

// Sign-in page - apiUrl comes from Provider
function SignInPage() {
  return (
    <SignIn
      onSuccess={(user, jwt) => {
        window.location.href = '/dashboard';
      }}
    />
  );
}

// User menu - apiUrl comes from Provider
function Header() {
  return (
    <nav>
      <Logo />
      <UserButton />
    </nav>
  );
}
```

**That's it! Just one publishable key needed!** 🎉

---

## Self-Hosted Option

For self-hosted deployments, you can override the API URL:

```tsx
<IDaaSProvider 
  publishableKey="pk_live_yourinstance"
  apiUrl="https://auth.your-company.com"  // Custom domain
>
  <App />
</IDaaSProvider>
```

---

## Components

### `<IDaaSProvider />`

Global configuration provider for IDaaS. Wrap your app with this to configure authentication.

**Props:**

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `publishableKey` | string | ✅ | Your IDaaS publishable key (pk_test_* or pk_live_*) |
| `apiUrl` | string | - | Optional API URL override for self-hosted deployments |
| `children` | ReactNode | ✅ | Your app |

**Example:**

```tsx
<IDaaSProvider publishableKey="pk_live_acme123">
  <App />
</IDaaSProvider>
```

**Publishable Key Format:**
- `pk_test_{instanceId}` - Test environment, maps to `https://{instanceId}.idaas-test.dev`
- `pk_live_{instanceId}` - Production, maps to `https://{instanceId}.idaas.app`

## Components

### `<SignIn />`

Pre-built sign-in form with beautiful UI.

**Props:**

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `apiUrl` | string | `http://localhost:3000` | Your IDaaS API URL |
| `onSuccess` | `(user, jwt) => void` | - | Called after successful sign-in |
| `onError` | `(error) => void` | - | Called on error |
| `redirectUrl` | string | - | Auto-redirect after sign-in |
| `theme` | `'light' \| 'dark'` | `'light'` | UI theme |
| `className` | string | - | Additional CSS classes |

**Example:**

```tsx
<SignIn
  apiUrl="https://api.example.com"
  onSuccess={(user, jwt) => {
    sessionStorage.setItem('jwt', jwt);
    navigate('/dashboard');
  }}
  theme="dark"
/>
```

### `<SignUp />`

Pre-built sign-up form with email verification.

**Props:**

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `apiUrl` | string | `http://localhost:3000` | Your IDaaS API URL |
| `onSuccess` | `(data) => void` | - | Called after successful sign-up |
| `onError` | `(error) => void` | - | Called on error |
| `requireEmailVerification` | boolean | `true` | Show verification step |
| `theme` | `'light' \| 'dark'` | `'light'` | UI theme |
| `className` | string | - | Additional CSS classes |

**Example:**

```tsx
<SignUp
  apiUrl="https://api.example.com"
  onSuccess={() => {
    alert('Account created! Please check your email.');
    navigate('/sign-in');
  }}
  requireEmailVerification={true}
/>
```

### `<UserButton />`

Pre-built user menu button with avatar and dropdown.

**Props:**

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `apiUrl` | string | `http://localhost:3000` | Your IDaaS API URL |
| `onSignOut` | `() => void` | - | Called after sign-out |
| `showEmail` | boolean | `true` | Show email in button |
| `showName` | boolean | `true` | Show name in button |
| `menuItems` | `MenuItem[]` | `[]` | Custom menu items |
| `theme` | `'light' \| 'dark'` | `'light'` | UI theme |
| `className` | string | - | Additional CSS classes |

**Example:**

```tsx
// Simple usage
<UserButton apiUrl="https://api.example.com" />

// With custom menu items
<UserButton
  apiUrl="https://api.example.com"
  menuItems={[
    {
      label: 'Settings',
      icon: <SettingsIcon />,
      onClick: () => navigate('/settings'),
    },
    {
      label: 'Billing',
      icon: <BillingIcon />,
      onClick: () => navigate('/billing'),
      divider: true, // Add divider before this item
    },
  ]}
  onSignOut={() => {
    // Custom sign-out logic
    sessionStorage.clear();
    navigate('/');
  }}
/>
```

## Styling

Components use Tailwind CSS classes. You can:

1. **Use default styling** (included)
2. **Override with className**
3. **Customize theme** (light/dark)

### Custom Styling

```tsx
<SignIn
  className="my-custom-container"
  theme="dark"
/>
```

## Complete Example

```tsx
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SignIn, SignUp } from '@idaas/react';

function App() {
  const handleSignInSuccess = (user: any, jwt: string) => {
    // Store JWT
    sessionStorage.setItem('jwt', jwt);
    
    // Store user
    localStorage.setItem('user', JSON.stringify(user));
    
    // Redirect
    window.location.href = '/dashboard';
  };

  const handleSignUpSuccess = () => {
    alert('Account created! Please check your email to verify.');
    window.location.href = '/sign-in';
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/sign-in" />} />
        
        <Route
          path="/sign-in"
          element={
            <SignIn
              apiUrl={process.env.REACT_APP_IDAAS_API!}
              onSuccess={handleSignInSuccess}
              theme="light"
            />
          }
        />
        
        <Route
          path="/sign-up"
          element={
            <SignUp
              apiUrl={process.env.REACT_APP_IDAAS_API!}
              onSuccess={handleSignUpSuccess}
              theme="light"
            />
          }
        />
        
        {/* Your protected routes */}
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
```

## Features

✅ **Beautiful UI** - Professional gradient designs  
✅ **Dark mode** - Built-in theme support  
✅ **Error handling** - Displays errors beautifully  
✅ **Loading states** - Built-in spinners  
✅ **Type-safe** - Full TypeScript support  
✅ **Customizable** - Props for everything  
✅ **Zero config** - Works out of the box  

## Need More Control?

For advanced use cases, use the low-level SDK:

```tsx
import IDaaSClient from '@idaas/client';

const client = new IDaaSClient({ apiUrl: '...' });
await client.signIn({ identifier, password });
```

See the [Integration Guide](../docs/INTEGRATION_GUIDE.md) for details.

## License

MIT
