# Environment Configuration

## Getting Your Publishable Key

Your publishable key is safe to use in client-side code and determines which IDaaS instance your app connects to.

### Key Format

```
pk_{environment}_{instanceId}
```

**Examples:**
- `pk_test_acme` - Test environment for "acme" instance
- `pk_live_acme` - Production environment for "acme" instance

### Finding Your Keys

1. **SaaS Deployment:**
   - Log into your IDaaS dashboard at `https://dashboard.idaas.app`
   - Navigate to Settings → API Keys
   - Copy your publishable key

2. **Self-Hosted:**
   - Keys are generated during instance setup
   - Check your deployment configuration or admin panel

## Environment Variables

### React / Vite

```env
# .env.local
REACT_APP_IDAAS_KEY=pk_test_yourinstance
```

```tsx
<IDaaSProvider publishableKey={process.env.REACT_APP_IDAAS_KEY}>
```

### Next.js

```env
# .env.local
NEXT_PUBLIC_IDAAS_KEY=pk_live_yourinstance
```

```tsx
<IDaaSProvider publishableKey={process.env.NEXT_PUBLIC_IDAAS_KEY}>
```

### Vite

```env
# .env
VITE_IDAAS_KEY=pk_test_yourinstance
```

```tsx
<IDaaSProvider publishableKey={import.meta.env.VITE_IDAAS_KEY}>
```

## URL Mapping

The SDK automatically maps publishable keys to API endpoints:

| Key Format | Mapped URL |
|------------|------------|
| `pk_test_*` | `https://*.idaas-test.dev` |
| `pk_live_*` | `https://*.idaas.app` |

## Self-Hosted Override

For custom deployments, override the API URL:

```tsx
<IDaaSProvider 
  publishableKey="pk_live_yourinstance"
  apiUrl="https://auth.your-company.com"
>
  <App />
</IDaaSProvider>
```

## Security Notes

✅ **Publishable keys are safe** for client-side use  
✅ They only allow read operations and user sign-in/sign-up  
✅ Secret keys (for server-side) are never exposed  
❌ **Never** commit secret keys to git  
❌ **Never** use secret keys in client-side code
