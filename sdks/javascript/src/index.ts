import axios, { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse } from 'axios';

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
    // MEDIUM-13 FIX: Auto token refresh timer
    private refreshTimer?: ReturnType<typeof setInterval>;

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
        this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
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
            this.client.interceptors.response.use((response: AxiosResponse) => {
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

    /**
     * POST /api/v1/auth/signup — Start a signup flow.
     * MEDIUM-14 FIX: Corrected endpoint from /api/auth/sign-up to /api/v1/auth/signup
     */
    async signUp(data: SignUpRequest) {
        const response = await this.client.post('/api/v1/auth/signup', data);
        // Server mode: store JWT from response
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
            this.scheduleTokenRefresh();
        }
        // Browser mode: session cookie set automatically by server
        return response.data;
    }

    /**
     * POST /api/v1/auth/login — Start an authentication flow.
     * MEDIUM-14 FIX: Corrected endpoint from /api/auth/sign-in to /api/v1/auth/login
     */
    async signIn(data: SignInRequest) {
        const response = await this.client.post('/api/v1/auth/login', data);
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
            // MEDIUM-13 FIX: Start auto-refresh after successful login
            this.scheduleTokenRefresh();
        }
        // Browser mode: httpOnly __session cookie set by server
        return response.data;
    }

    /**
     * POST /api/v1/auth/logout — End current session.
     * MEDIUM-14 FIX: Corrected endpoint from /api/auth/logout to /api/v1/auth/logout
     */
    async signOut() {
        await this.client.post('/api/v1/auth/logout');
        this.jwt = undefined;
        this.csrfToken = undefined;
        // MEDIUM-13 FIX: Stop auto-refresh on logout
        this.stopTokenRefresh();
    }

    /**
     * POST /api/v1/token/refresh — Refresh JWT token.
     * MEDIUM-14 FIX: Corrected endpoint from /api/auth/token/refresh to /api/v1/token/refresh
     */
    async refreshToken() {
        const response = await this.client.post('/api/v1/token/refresh');
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
        }
        return response.data;
    }

    // ─── User ───

    /**
     * GET /api/v1/user — Get current authenticated user profile.
     * HIGH-18 FIX: Was incorrectly calling /api/v1/user/factors (the factors list endpoint).
     * The correct endpoint for the current user profile is /api/v1/user.
     */
    async getCurrentUser(): Promise<User> {
        const response = await this.client.get('/api/v1/user');
        return response.data;
    }

    /**
     * PATCH /api/v1/user — Update user profile.
     */
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

    /**
     * POST /api/mfa/totp/setup — Setup TOTP MFA.
     * MEDIUM-14 FIX: Endpoint is correct per router.rs (/api/mfa prefix).
     */
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

    /**
     * POST /api/billing/v1/checkout — Create a Stripe checkout session.
     * MEDIUM-14 FIX: Endpoint is correct per router.rs.
     */
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
        // MEDIUM-13 FIX: Start auto-refresh when token is set manually
        this.scheduleTokenRefresh();
    }

    /** Get current JWT (server mode only — browser mode tokens are httpOnly) */
    getToken(): string | undefined {
        if (this.mode !== 'server') {
            return undefined; // Not accessible in browser mode by design
        }
        return this.jwt;
    }

    /**
     * MEDIUM-13 FIX: Schedule proactive token refresh every 14 minutes.
     * Access tokens expire in 15 minutes; refreshing at 14 minutes ensures
     * the client always has a valid token without any request failures.
     */
    private scheduleTokenRefresh() {
        this.stopTokenRefresh();
        this.refreshTimer = setInterval(async () => {
            try {
                await this.refreshToken();
            } catch (err) {
                console.error('[IDaaS SDK] Token refresh failed:', err);
                this.stopTokenRefresh();
                // Emit an event so the application can redirect to login
                if (typeof window !== 'undefined') {
                    window.dispatchEvent(new CustomEvent('idaas:session-expired'));
                }
            }
        }, 14 * 60 * 1000);
    }

    /** Stop the auto-refresh timer */
    private stopTokenRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = undefined;
        }
    }

    /**
     * Dispose the client — stops the refresh timer.
     * Call this when the client is no longer needed (e.g., on logout or app unmount).
     */
    dispose() {
        this.stopTokenRefresh();
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
