"""
IDaaS Python SDK - Official Python client for IDaaS Platform
"""

import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class User:
    id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email_verified: bool = False
    mfa_enabled: bool = False


@dataclass
class Organization:
    id: str
    name: str
    slug: str
    created_at: str


class IDaaSClient:
    """IDaaS Platform Python SDK"""
    
    def __init__(self, api_url: str, api_key: Optional[str] = None):
        """
        Initialize the IDaaS client.
        
        Args:
            api_url: Base URL of the IDaaS API
            api_key: Optional API key for authentication
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.jwt: Optional[str] = None
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request to API"""
        url = f"{self.api_url}{endpoint}"
        headers = kwargs.pop('headers', {})
        
        if self.jwt:
            headers['Authorization'] = f'Bearer {self.jwt}'
        
        response = self.session.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json()
    
    # Authentication
    def sign_up(self, email: str, password: str, 
                first_name: Optional[str] = None,
                last_name: Optional[str] = None) -> Dict[str, Any]:
        """Create a new user account"""
        data = {
            'email': email,
            'password': password,
            'firstName': first_name,
            'lastName': last_name
        }
        return self._request('POST', '/api/v1/auth/signup', json=data)
    
    def sign_in(self, identifier: str, password: str) -> Dict[str, Any]:
        """Sign in with email/password"""
        data = {'identifier': identifier, 'password': password}
        result = self._request('POST', '/api/v1/auth/login', json=data)
        self.jwt = result.get('jwt')
        return result
    
    def sign_out(self) -> None:
        """Sign out current user"""
        self._request('POST', '/api/v1/auth/logout')
        self.jwt = None
    
    def refresh_token(self) -> Dict[str, Any]:
        """Refresh JWT token"""
        result = self._request('POST', '/api/v1/token/refresh')
        self.jwt = result.get('jwt')
        return result
    
    # User Management
    def get_current_user(self) -> User:
        """Get current authenticated user"""
        data = self._request('GET', '/api/v1/user')
        return User(**data)
    
    def update_user(self, **kwargs) -> User:
        """Update user profile"""
        data = self._request('PATCH', '/api/v1/user', json=kwargs)
        return User(**data)
    
    # Organizations
    def create_organization(self, name: str, slug: Optional[str] = None) -> Organization:
        """Create a new organization"""
        data = {'name': name, 'slug': slug}
        result = self._request('POST', '/api/v1/organizations', json=data)
        return Organization(**result)
    
    def list_organizations(self) -> List[Organization]:
        """List user's organizations"""
        data = self._request('GET', '/api/v1/organizations')
        return [Organization(**org) for org in data]
    
    def get_organization(self, org_id: str) -> Organization:
        """Get organization by ID"""
        data = self._request('GET', f'/api/v1/organizations/{org_id}')
        return Organization(**data)
    
    # MFA
    def setup_totp(self) -> Dict[str, Any]:
        """Setup TOTP MFA"""
        return self._request('POST', '/api/mfa/totp/setup')
    
    def verify_totp(self, code: str) -> Dict[str, Any]:
        """Verify TOTP code"""
        return self._request('POST', '/api/mfa/totp/verify', json={'code': code})
    
    # Billing
    def create_subscription(self, price_id: str) -> Dict[str, Any]:
        """Create a subscription"""
        return self._request('POST', '/api/billing/v1/checkout', json={'priceId': price_id})
    
    def get_subscription(self) -> Dict[str, Any]:
        """Get current subscription"""
        return self._request('GET', '/api/billing/v1/subscription')
    
    # Manifest
    def get_manifest(self, org_id: str) -> Dict[str, Any]:
        """
        GET /api/v1/sdk/manifest?org_id=<org_id>
        
        Fetch the tenant manifest for the given organisation.
        Returns branding, enabled OAuth providers, and sign-up field definitions —
        everything needed to render auth UI dynamically, with no secrets included.
        
        Note: uses /api/v1/ prefix (correct path) regardless of other endpoints.
        """
        url = f"{self.api_url}/api/v1/sdk/manifest"
        headers: Dict[str, str] = {}
        if self.jwt:
            headers['Authorization'] = f'Bearer {self.jwt}'
        response = self.session.get(url, params={'org_id': org_id}, headers=headers)
        response.raise_for_status()
        return response.json()
    
    # Token Management
    def set_token(self, jwt: str) -> None:
        """Set JWT token manually"""
        self.jwt = jwt
    
    def get_token(self) -> Optional[str]:
        """Get current JWT token"""
        return self.jwt
