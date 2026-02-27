import axios, { AxiosInstance } from 'axios';

export interface IDaaSConfig {
    apiUrl: string;
    apiKey?: string;
    /** 'browser' uses httpOnly cookies + CSRF, 'server' uses Bearer tokens */
    mode?: 'browser' | 'server';
}

export interface User {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    emailVerified: boolean;
    mfaEnabled: boolean;
}

export interface SignUpRequest {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
}

export interface SignInRequest {
    identifier: string;
    password: string;
}

export interface Organization {
    id: string;
    name: string;
    slug: string;
    createdAt: string;
}

export class IDaaSClient {
    protected client: AxiosInstance;
    protected jwt?: string;
    protected mode: 'browser' | 'server';
    private csrfToken?: string;

    constructor(config: IDaaSConfig) {
        this.mode = config.mode ?? 'browser';

        this.client = axios.create({
            baseURL: config.apiUrl,
            headers: {
                'Content-Type': 'application/json',
                ...(config.apiKey && { 'X-API-Key': config.apiKey }),
            },
            // Browser mode: send httpOnly cookies automatically
            withCredentials: this.mode === 'browser',
        });

        this.setupInterceptors();
    }

    private setupInterceptors() {
        this.client.interceptors.request.use((config) => {
            // Server mode: attach Bearer token
            if (this.mode === 'server' && this.jwt) {
                config.headers.Authorization = `Bearer ${this.jwt}`;
            }

            // Browser mode: attach CSRF token on mutating requests
            if (this.mode === 'browser' && this.csrfToken) {
                const method = config.method?.toUpperCase();
                if (method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
                    config.headers['X-CSRF-Token'] = this.csrfToken;
                }
            }

            return config;
        });

        // Auto-extract CSRF token from response cookies (browser mode)
        if (this.mode === 'browser') {
            this.client.interceptors.response.use((response) => {
                // Read __csrf from document.cookie (httpOnly=false for CSRF cookie)
                if (typeof document !== 'undefined') {
                    const match = document.cookie.match(/(?:^|;\s*)__csrf=([^;]*)/);
                    if (match) {
                        this.csrfToken = match[1];
                    }
                }
                return response;
            });
        }
    }

    // ─── Authentication ───

    /** POST /api/auth/sign-up — Start a signup flow */
    async signUp(data: SignUpRequest) {
        const response = await this.client.post('/api/auth/sign-up', data);
        // Server mode: store JWT from response
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
        }
        // Browser mode: session cookie set automatically by server
        return response.data;
    }

    /** POST /api/auth/sign-in — Start an authentication flow */
    async signIn(data: SignInRequest) {
        const response = await this.client.post('/api/auth/sign-in', data);
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
        }
        // Browser mode: httpOnly __session cookie set by server
        return response.data;
    }

    /** POST /api/auth/logout — End current session */
    async signOut() {
        await this.client.post('/api/auth/logout');
        this.jwt = undefined;
        this.csrfToken = undefined;
    }

    /** POST /api/auth/token/refresh — Refresh JWT token */
    async refreshToken() {
        const response = await this.client.post('/api/auth/token/refresh');
        if (this.mode === 'server') {
            this.jwt = response.data.jwt;
        }
        return response.data;
    }

    // ─── User ───

    /** GET /api/v1/user/factors — List enrolled factors */
    async getCurrentUser(): Promise<User> {
        const response = await this.client.get('/api/v1/user/factors');
        return response.data;
    }

    /** PATCH /api/v1/user — Update user profile */
    async updateUser(data: Partial<User>) {
        const response = await this.client.patch('/api/v1/user', data);
        return response.data;
    }

    // ─── Organizations ───

    /** POST /api/v1/organizations — Create an organization */
    async createOrganization(name: string, slug?: string) {
        const response = await this.client.post('/api/v1/organizations', { name, slug });
        return response.data;
    }

    /** GET /api/v1/organizations — List user's organizations */
    async listOrganizations(): Promise<Organization[]> {
        const response = await this.client.get('/api/v1/organizations');
        return response.data;
    }

    /** GET /api/v1/organizations/:id — Get organization details */
    async getOrganization(id: string): Promise<Organization> {
        const response = await this.client.get(`/api/v1/organizations/${id}`);
        return response.data;
    }

    // ─── MFA ───

    /** POST /api/mfa/totp/setup — Setup TOTP MFA */
    async setupTotp() {
        const response = await this.client.post('/api/mfa/totp/setup');
        return response.data;
    }

    /** POST /api/mfa/totp/verify — Verify TOTP code */
    async verifyTotp(code: string) {
        const response = await this.client.post('/api/mfa/totp/verify', { code });
        return response.data;
    }

    /** GET /api/mfa/status — Get MFA enrollment status */
    async getMfaStatus() {
        const response = await this.client.get('/api/mfa/status');
        return response.data;
    }

    // ─── Billing ───

    /** POST /api/billing/v1/checkout — Create a Stripe checkout session */
    async createSubscription(priceId: string) {
        const response = await this.client.post('/api/billing/v1/checkout', { priceId });
        return response.data;
    }

    /** GET /api/billing/v1/subscription — Get current subscription */
    async getSubscription() {
        const response = await this.client.get('/api/billing/v1/subscription');
        return response.data;
    }

    // ─── Token Management (server mode only) ───

    /** Set JWT manually (server mode only) */
    setToken(jwt: string) {
        if (this.mode !== 'server') {
            console.warn('setToken() is only available in server mode. Browser mode uses httpOnly cookies.');
            return;
        }
        this.jwt = jwt;
    }

    /** Get current JWT (server mode only — browser mode tokens are httpOnly) */
    getToken(): string | undefined {
        if (this.mode !== 'server') {
            return undefined; // Not accessible in browser mode by design
        }
        return this.jwt;
    }
}

/**
 * Server-side SDK client.
 * Uses API key authentication and Bearer tokens (no cookies/CSRF).
 */
export class IDaaSServerClient extends IDaaSClient {
    constructor(config: { apiUrl: string; apiKey: string }) {
        super({ ...config, mode: 'server' });
    }
}

export default IDaaSClient;
