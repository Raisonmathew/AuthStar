"""
IDaaS Python SDK - Official Python client for IDaaS Platform
"""

import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Agent management data classes (G-2)
# ---------------------------------------------------------------------------

@dataclass
class AgentPrincipal:
    """A registered AI agent principal."""

    id: str
    agent_id: str
    name: str
    allowed_tools: str
    max_delegation_depth: int
    token_ttl_seconds: int
    principal_source: str
    active: bool
    created_at: str
    updated_at: str
    model_id: Optional[str] = None
    cimd_metadata_url: Optional[str] = None


@dataclass
class RegisterAgentResponse:
    """Response from POST /api/v1/agents/register."""

    agent_id: str
    name: str
    allowed_tools: str
    max_delegation_depth: int
    token_ttl_seconds: int
    principal_source: str
    created_at: str
    model_id: Optional[str] = None


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
    
    # Agent Management (G-2)
    def register_agent(
        self,
        name: str,
        model_id: Optional[str] = None,
        allowed_tools: Optional[str] = None,
        max_delegation_depth: Optional[int] = None,
        token_ttl_seconds: Optional[int] = None,
        cimd_metadata_url: Optional[str] = None,
    ) -> RegisterAgentResponse:
        """
        Register or update a pre-registered agent principal.

        POST /api/v1/agents/register
        """
        payload: Dict[str, Any] = {"name": name}
        if model_id is not None:
            payload["model_id"] = model_id
        if allowed_tools is not None:
            payload["allowed_tools"] = allowed_tools
        if max_delegation_depth is not None:
            payload["max_delegation_depth"] = max_delegation_depth
        if token_ttl_seconds is not None:
            payload["token_ttl_seconds"] = token_ttl_seconds
        if cimd_metadata_url is not None:
            payload["cimd_metadata_url"] = cimd_metadata_url

        data = self._request("POST", "/api/v1/agents/register", json=payload)
        return RegisterAgentResponse(
            agent_id=data["agent_id"],
            name=data["name"],
            model_id=data.get("model_id"),
            allowed_tools=data["allowed_tools"],
            max_delegation_depth=data["max_delegation_depth"],
            token_ttl_seconds=data["token_ttl_seconds"],
            principal_source=data["principal_source"],
            created_at=data["created_at"],
        )

    def list_agents(self) -> List[AgentPrincipal]:
        """
        List all active agent principals for the tenant.

        GET /api/v1/agents
        """
        data = self._request("GET", "/api/v1/agents")
        return [self._parse_agent_principal(a) for a in data]

    def get_agent(self, agent_id: str) -> AgentPrincipal:
        """
        Retrieve a single agent principal by ID.

        GET /api/v1/agents/{agent_id}
        """
        data = self._request("GET", f"/api/v1/agents/{agent_id}")
        return self._parse_agent_principal(data)

    def deactivate_agent(self, agent_id: str) -> None:
        """
        Soft-deactivate an agent principal (sets active=false).

        DELETE /api/v1/agents/{agent_id}
        """
        self._request("DELETE", f"/api/v1/agents/{agent_id}")

    def revoke_agent_tokens(self, agent_id: str) -> None:
        """
        Immediately invalidate all active tokens for an agent.

        POST /api/v1/agents/{agent_id}/revoke
        """
        self._request("POST", f"/api/v1/agents/{agent_id}/revoke")

    @staticmethod
    def _parse_agent_principal(data: Dict[str, Any]) -> AgentPrincipal:
        return AgentPrincipal(
            id=data["id"],
            agent_id=data["agent_id"],
            name=data["name"],
            model_id=data.get("model_id"),
            allowed_tools=data["allowed_tools"],
            max_delegation_depth=data["max_delegation_depth"],
            token_ttl_seconds=data["token_ttl_seconds"],
            principal_source=data["principal_source"],
            cimd_metadata_url=data.get("cimd_metadata_url"),
            active=data["active"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    # Token Management
    def set_token(self, jwt: str) -> None:
        """Set JWT token manually"""
        self.jwt = jwt

    def get_token(self) -> Optional[str]:
        """Get current JWT token"""
        return self.jwt
