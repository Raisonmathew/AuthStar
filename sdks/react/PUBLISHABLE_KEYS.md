# Publishable Key System

The IDaaS SDK now uses **publishable keys** as the primary configuration method, providing a cleaner developer experience similar to Clerk and Auth0.

## ✅ Completed Changes

### 1. **IDaaSProvider Updated**
- Primary prop is now `publishableKey` (required)
- `apiUrl` is optional (for self-hosted overrides)
- Automatic URL mapping from key format

### 2. **Key Format**
```
pk_{environment}_{instanceId}
```

**Examples:**
- `pk_test_acme` → `https://acme.idaas-test.dev`
- `pk_live_acme` → `https://acme.idaas.app`

### 3. **URL Mapping Logic**
File: `sdks/react/src/IDaaSProvider.tsx`

```typescript
function parsePublishableKey(key: string) {
  const [prefix, env, ...instanceParts] = key.split('_');
  const instanceId = instanceParts.join('_');
  
  const apiUrl = env === 'test'
    ? `https://${instanceId}.idaas-test.dev`
    : `https://${instanceId}.idaas.app`;
  
  return { env, instanceId, apiUrl };
}
```

### 4. **Updated Documentation**
- `sdks/react/README.md` - Updated all examples
- `sdks/react/ENVIRONMENT.md` - New file with env var guide  
- `docs/INTEGRATION_GUIDE.md` - Updated quick start

## 🔄 Migration from Old Approach

**Before:**
``tsx
<IDaaSProvider apiUrl="https://api.your-domain.com">
  <App />
</IDaaSProvider>
```

**After:**
```tsx
<IDaaSProvider publishableKey="pk_live_yourinstance">
  <App />
</IDaaSProvider>
```

## 🏗️ Self-Hosted Deployments

For custom domains, override the URL:

```tsx
<IDaaSProvider 
  publishableKey="pk_live_yourinstance"
  apiUrl="https://auth.custom-domain.com"
>
  <App />
</IDaaSProvider>
```

## 🔐 Security Notes

- ✅ Publishable keys are **safe** for client-side use
- ✅ Only allow read operations and user auth
- ❌ **Never** expose secret keys in frontend code
- ✅ Backend/server-side operations use secret keys separately

## 📝 TODO: Backend Integration

To fully support this, the backend needs:

1. **Key Generation System**
   - Generate pk_test_* and pk_live_* keys
   - Map keys to instance IDs in database

2. **Key Validation Endpoint**
   - Verify publishable keys
   - Return instance configuration

3. **Admin Dashboard**
   - Display keys to users
   - Allow key rotation
   - Separate secret keys for server-side

## 🎯 Benefits

✅ **Single configuration value** - Just the publishable key  
✅ **Environment-aware** - test vs live keys  
✅ **Automatic routing** - No manual URL configuration  
✅ **Matches industry standards** - Same pattern as Clerk/Auth0  
✅ **Flexibility maintained** - Can override URL if needed
