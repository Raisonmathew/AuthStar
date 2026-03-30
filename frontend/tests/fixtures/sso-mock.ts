/**
 * SSO Protocol Mocking for OAuth and SAML Tests
 * 
 * Provides mock implementations of OAuth 2.0 and SAML 2.0 flows
 * for testing SSO connections without requiring actual identity providers.
 */

import { Page, Route } from '@playwright/test';

/**
 * OAuth 2.0 Mock Configuration
 */
export interface OAuthMockConfig {
    provider: 'google' | 'microsoft' | 'github' | 'okta' | 'custom';
    clientId: string;
    redirectUri: string;
    scope?: string;
    state?: string;
    shouldSucceed?: boolean;
    shouldCancel?: boolean;
    shouldError?: boolean;
    errorCode?: string;
    errorDescription?: string;
    mockUser?: {
        id: string;
        email: string;
        name: string;
        picture?: string;
    };
}

/**
 * SAML 2.0 Mock Configuration
 */
export interface SAMLMockConfig {
    entityId: string;
    ssoUrl: string;
    acsUrl: string;
    shouldSucceed?: boolean;
    shouldError?: boolean;
    errorMessage?: string;
    mockUser?: {
        nameId: string;
        email: string;
        firstName?: string;
        lastName?: string;
        attributes?: Record<string, string[]>;
    };
}

/**
 * Default mock users for different providers
 */
const DEFAULT_MOCK_USERS = {
    google: {
        id: 'google-mock-user-123',
        email: 'test@example.com',
        name: 'Test User',
        picture: 'https://via.placeholder.com/150',
    },
    microsoft: {
        id: 'microsoft-mock-user-456',
        email: 'test@company.com',
        name: 'Test User',
        picture: 'https://via.placeholder.com/150',
    },
    github: {
        id: 'github-mock-user-789',
        email: 'test@github.com',
        name: 'Test User',
        picture: 'https://via.placeholder.com/150',
    },
    okta: {
        id: 'okta-mock-user-101',
        email: 'test@okta.com',
        name: 'Test User',
        picture: 'https://via.placeholder.com/150',
    },
    custom: {
        id: 'custom-mock-user-202',
        email: 'test@custom.com',
        name: 'Test User',
        picture: 'https://via.placeholder.com/150',
    },
};

/**
 * Generate a mock authorization code
 */
function generateAuthCode(): string {
    return 'mock_auth_code_' + Math.random().toString(36).substring(2, 15);
}

/**
 * Generate a mock access token
 */
function generateAccessToken(): string {
    return 'mock_access_token_' + Math.random().toString(36).substring(2, 15);
}

/**
 * Generate a mock ID token (JWT)
 */
function generateIdToken(user: any): string {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = btoa(JSON.stringify({
        sub: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
    }));
    const signature = 'mock_signature';
    return `${header}.${payload}.${signature}`;
}

/**
 * Generate a mock SAML response
 */
function generateSAMLResponse(config: SAMLMockConfig): string {
    const user = config.mockUser || {
        nameId: 'mock-saml-user',
        email: 'test@saml.com',
        firstName: 'Test',
        lastName: 'User',
    };

    const samlResponse = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_mock_response_${Date.now()}"
                Version="2.0"
                IssueInstant="${new Date().toISOString()}"
                Destination="${config.acsUrl}">
    <saml:Issuer>${config.entityId}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_mock_assertion_${Date.now()}"
                    Version="2.0"
                    IssueInstant="${new Date().toISOString()}">
        <saml:Issuer>${config.entityId}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                ${user.nameId}
            </saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>${user.email}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="firstName">
                <saml:AttributeValue>${user.firstName || ''}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="lastName">
                <saml:AttributeValue>${user.lastName || ''}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`;

    return btoa(samlResponse);
}

/**
 * Enable OAuth 2.0 mocking
 */
export async function enableOAuthMocking(page: Page, config: OAuthMockConfig) {
    const {
        provider,
        clientId,
        redirectUri,
        scope = 'openid email profile',
        state = 'mock_state',
        shouldSucceed = true,
        shouldCancel = false,
        shouldError = false,
        errorCode = 'access_denied',
        errorDescription = 'User denied access',
        mockUser = DEFAULT_MOCK_USERS[provider],
    } = config;

    // Mock authorization endpoint
    await page.route('**/oauth2/authorize*', async (route: Route) => {
        console.log('[OAuth Mock] Authorization request intercepted');

        if (shouldCancel) {
            // Redirect back with error
            const errorUrl = new URL(redirectUri);
            errorUrl.searchParams.set('error', 'access_denied');
            errorUrl.searchParams.set('error_description', 'User cancelled the request');
            errorUrl.searchParams.set('state', state);
            
            await route.fulfill({
                status: 302,
                headers: {
                    'Location': errorUrl.toString(),
                },
            });
            return;
        }

        if (shouldError) {
            // Redirect back with error
            const errorUrl = new URL(redirectUri);
            errorUrl.searchParams.set('error', errorCode);
            errorUrl.searchParams.set('error_description', errorDescription);
            errorUrl.searchParams.set('state', state);
            
            await route.fulfill({
                status: 302,
                headers: {
                    'Location': errorUrl.toString(),
                },
            });
            return;
        }

        if (shouldSucceed) {
            // Redirect back with authorization code
            const authCode = generateAuthCode();
            const successUrl = new URL(redirectUri);
            successUrl.searchParams.set('code', authCode);
            successUrl.searchParams.set('state', state);
            
            await route.fulfill({
                status: 302,
                headers: {
                    'Location': successUrl.toString(),
                },
            });
            return;
        }

        await route.continue();
    });

    // Mock token endpoint
    await page.route('**/oauth2/token*', async (route: Route) => {
        console.log('[OAuth Mock] Token request intercepted');

        if (shouldError) {
            await route.fulfill({
                status: 400,
                contentType: 'application/json',
                body: JSON.stringify({
                    error: errorCode,
                    error_description: errorDescription,
                }),
            });
            return;
        }

        if (shouldSucceed) {
            const accessToken = generateAccessToken();
            const idToken = generateIdToken(mockUser);
            
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    id_token: idToken,
                    scope,
                }),
            });
            return;
        }

        await route.continue();
    });

    // Mock userinfo endpoint
    await page.route('**/oauth2/userinfo*', async (route: Route) => {
        console.log('[OAuth Mock] Userinfo request intercepted');

        if (shouldSucceed) {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(mockUser),
            });
            return;
        }

        await route.continue();
    });

    console.log(`[OAuth Mock] ${provider} OAuth mocking enabled`);
}

/**
 * Enable SAML 2.0 mocking
 */
export async function enableSAMLMocking(page: Page, config: SAMLMockConfig) {
    const {
        entityId,
        ssoUrl,
        acsUrl,
        shouldSucceed = true,
        shouldError = false,
        errorMessage = 'SAML authentication failed',
        mockUser,
    } = config;

    // Mock SAML metadata endpoint
    await page.route('**/saml/metadata*', async (route: Route) => {
        console.log('[SAML Mock] Metadata request intercepted');

        const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="${entityId}">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${ssoUrl}"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="${ssoUrl}"/>
    </IDPSSODescriptor>
</EntityDescriptor>`;

        await route.fulfill({
            status: 200,
            contentType: 'application/xml',
            body: metadata,
        });
    });

    // Mock SAML SSO endpoint (AuthnRequest)
    await page.route('**/saml/sso*', async (route: Route) => {
        console.log('[SAML Mock] SSO request intercepted');

        if (shouldError) {
            const errorResponse = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
        <samlp:StatusMessage>${errorMessage}</samlp:StatusMessage>
    </samlp:Status>
</samlp:Response>`;

            await route.fulfill({
                status: 200,
                contentType: 'text/html',
                body: `
                    <html>
                        <body>
                            <form method="POST" action="${acsUrl}">
                                <input type="hidden" name="SAMLResponse" value="${btoa(errorResponse)}" />
                                <input type="submit" value="Continue" />
                            </form>
                            <script>document.forms[0].submit();</script>
                        </body>
                    </html>
                `,
            });
            return;
        }

        if (shouldSucceed) {
            const samlResponse = generateSAMLResponse(config);
            
            await route.fulfill({
                status: 200,
                contentType: 'text/html',
                body: `
                    <html>
                        <body>
                            <form method="POST" action="${acsUrl}">
                                <input type="hidden" name="SAMLResponse" value="${samlResponse}" />
                                <input type="submit" value="Continue" />
                            </form>
                            <script>document.forms[0].submit();</script>
                        </body>
                    </html>
                `,
            });
            return;
        }

        await route.continue();
    });

    console.log('[SAML Mock] SAML mocking enabled');
}

/**
 * Disable SSO mocking
 */
export async function disableSSOMocking(page: Page) {
    await page.unroute('**/oauth2/**');
    await page.unroute('**/saml/**');
    console.log('[SSO Mock] Mocking disabled');
}

/**
 * Preset configurations for common test scenarios
 */
export const SSOMockPresets = {
    /**
     * Successful Google OAuth login
     */
    googleSuccess: {
        provider: 'google' as const,
        clientId: 'mock-google-client-id',
        redirectUri: 'http://localhost:3000/auth/callback',
        shouldSucceed: true,
    },

    /**
     * Successful Microsoft OAuth login
     */
    microsoftSuccess: {
        provider: 'microsoft' as const,
        clientId: 'mock-microsoft-client-id',
        redirectUri: 'http://localhost:3000/auth/callback',
        shouldSucceed: true,
    },

    /**
     * User cancelled OAuth login
     */
    oauthCancelled: {
        provider: 'google' as const,
        clientId: 'mock-client-id',
        redirectUri: 'http://localhost:3000/auth/callback',
        shouldCancel: true,
    },

    /**
     * OAuth error
     */
    oauthError: {
        provider: 'google' as const,
        clientId: 'mock-client-id',
        redirectUri: 'http://localhost:3000/auth/callback',
        shouldError: true,
        errorCode: 'server_error',
        errorDescription: 'Internal server error',
    },

    /**
     * Successful SAML login
     */
    samlSuccess: {
        entityId: 'https://idp.example.com',
        ssoUrl: 'https://idp.example.com/saml/sso',
        acsUrl: 'http://localhost:3000/auth/saml/acs',
        shouldSucceed: true,
    },

    /**
     * SAML error
     */
    samlError: {
        entityId: 'https://idp.example.com',
        ssoUrl: 'https://idp.example.com/saml/sso',
        acsUrl: 'http://localhost:3000/auth/saml/acs',
        shouldError: true,
        errorMessage: 'Authentication failed',
    },
};

// Made with Bob
