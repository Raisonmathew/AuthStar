# IDaaS Python SDK

Official Python SDK for integrating with the IDaaS Platform.

## Installation

```bash
pip install idaas-client
```

## Quick Start

```python
from idaas import IDaaSClient

# Initialize client
client = IDaaSClient(api_url='https://api.idaas.example.com')

# Sign up
client.sign_up(
    email='user@example.com',
    password='SecurePass123!',
    first_name='John',
    last_name='Doe'
)

# Sign in
result = client.sign_in(
    identifier='user@example.com',
    password='SecurePass123!'
)

# Get current user
user = client.get_current_user()
print(f"Welcome {user.first_name}!")

# Create organization
org = client.create_organization('My Company')

# List organizations
orgs = client.list_organizations()
```

## API Reference

### Authentication

- `sign_up(email, password, first_name=None, last_name=None)` - Create account
- `sign_in(identifier, password)` - Authenticate user
- `sign_out()` - Sign out current user
- `refresh_token()` - Refresh JWT token

### Users

- `get_current_user()` - Get current user profile (returns `User` object)
- `update_user(**kwargs)` - Update user profile

### Organizations

- `create_organization(name, slug=None)` - Create organization
- `list_organizations()` - List user's organizations
- `get_organization(org_id)` - Get organization by ID

### MFA

- `setup_totp()` - Setup TOTP MFA (returns QR code and secret)
- `verify_totp(code)` - Verify TOTP code

### Billing

- `create_subscription(price_id)` - Create subscription
- `get_subscription()` - Get current subscription

## Data Classes

### User

```python
@dataclass
class User:
    id: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    email_verified: bool
    mfa_enabled: bool
```

### Organization

```python
@dataclass
class Organization:
    id: str
    name: str
    slug: str
    created_at: str
```

## License

MIT
