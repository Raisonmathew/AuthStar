# IDaaS JavaScript/TypeScript SDK

Official SDK for integrating with the IDaaS Platform.

## Installation

```bash
npm install @idaas/client
```

## Quick Start

```typescript
import IDaaSClient from '@idaas/client';

const client = new IDaaSClient({
  apiUrl: 'https://api.idaas.example.com',
});

// Sign up
await client.signUp({
  email: 'user@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe',
});

// Sign in
const { user, jwt } = await client.signIn({
  identifier: 'user@example.com',
  password: 'SecurePass123!',
});

// Get current user
const user = await client.getCurrentUser();

// Create organization
const org = await client.createOrganization('My Company');

// List organizations
const orgs = await client.listOrganizations();
```

## API Reference

### Authentication

- `signUp(data)` - Create a new account
- `signIn(data)` - Authenticate user
- `signOut()` - Sign out current user
- `refreshToken()` - Refresh JWT token

### Users

- `getCurrentUser()` - Get current user profile
- `updateUser(data)` - Update user profile

### Organizations

- `createOrganization(name, slug?)` - Create organization
- `listOrganizations()` - List user's organizations
- `getOrganization(id)` - Get organization by ID

### MFA

- `setupTotp()` - Setup TOTP MFA
- `verifyTotp(code)` - Verify TOTP code

### Billing

- `createSubscription(priceId)` - Create subscription
- `getSubscription()` - Get current subscription

## License

MIT
