import axios, { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import type {
    IDaaSConfig,
    User,
    SignUpRequest,
    SignInRequest,
    Organization,
    SdkManifest,
} from './types';

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
            withCredentials: this.mode === 'browser',
        });

        this.setupInterceptors();
    }

    private setupInterceptors() {
        this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
            if (this.mode === 'server' && this.jwt) {
                config.headers.Authorization = `Bearer ${this.jwt}`;
            }
            if (this.mode === 'browser' && this.csrfToken) {
                const method = config.method?.toUpperCase();
                if (method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
                    config.headers['X-CSRF-Token'] = this.csrfToken;
                }
            }
            return config;
        });

        if (this.mode === 'browser') {
            this.client.interceptors.response.use((response: AxiosResponse) => {
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

    async signUp(data: SignUpRequest) {
        const response = await this.client.post('/api/v1/auth/signup', data);
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
            this.scheduleTokenRefresh();
        }
        return response.data;
    }

    async signIn(data: SignInRequest) {
        const response = await this.client.post('/api/v1/auth/login', data);
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
            this.scheduleTokenRefresh();
        }
        return response.data;
    }

    async signOut() {
        await this.client.post('/api/v1/auth/logout');
        this.jwt = undefined;
        this.csrfToken = undefined;
        this.stopTokenRefresh();
    }

    async refreshToken() {
        const response = await this.client.post('/api/v1/token/refresh');
        if (this.mode === 'server' && response.data.jwt) {
            this.jwt = response.data.jwt;
        }
        return response.data;
    }

    // ─── User ───

    async getCurrentUser(): Promise<User> {
        const response = await this.client.get('/api/v1/user');
        return response.data;
    }

    async updateUser(data: Partial<User>) {
        const response = await this.client.patch('/api/v1/user', data);
        return response.data;
    }

    // ─── Organizations ───

    async createOrganization(name: string, slug?: string) {
        const response = await this.client.post('/api/v1/organizations', { name, slug });
        return response.data;
    }

    async listOrganizations(): Promise<Organization[]> {
        const response = await this.client.get('/api/v1/organizations');
        return response.data;
    }

    async getOrganization(id: string): Promise<Organization> {
        const response = await this.client.get(`/api/v1/organizations/${id}`);
        return response.data;
    }

    // ─── MFA ───

    async setupTotp() {
        const response = await this.client.post('/api/mfa/totp/setup');
        return response.data;
    }

    async verifyTotp(code: string) {
        const response = await this.client.post('/api/mfa/totp/verify', { code });
        return response.data;
    }

    async getMfaStatus() {
        const response = await this.client.get('/api/mfa/status');
        return response.data;
    }

    // ─── Billing ───

    async createSubscription(priceId: string) {
        const response = await this.client.post('/api/billing/v1/checkout', { priceId });
        return response.data;
    }

    async getSubscription() {
        const response = await this.client.get('/api/billing/v1/subscription');
        return response.data;
    }

    // ─── Manifest ─────────────────────────────────────────────────────────────

    /**
     * GET /api/v1/sdk/manifest?org_id=<orgId>
     *
     * Fetch the tenant manifest for the given organisation.
     * The manifest describes branding, enabled OAuth providers, and sign-up
     * field definitions — everything needed to render auth UI dynamically.
     *
     * The response is public and cached (max-age=60 s) by the server.
     */
    async getManifest(orgId: string): Promise<SdkManifest> {
        const response = await this.client.get('/api/v1/sdk/manifest', {
            params: { org_id: orgId },
        });
        return response.data as SdkManifest;
    }

    // ─── Token Management (server mode only) ─────────────────────────────────

    setToken(jwt: string) {
        if (this.mode !== 'server') {
            console.warn('setToken() is only available in server mode.');
            return;
        }
        this.jwt = jwt;
        this.scheduleTokenRefresh();
    }

    getToken(): string | undefined {
        if (this.mode !== 'server') {
            return undefined;
        }
        return this.jwt;
    }

    private scheduleTokenRefresh() {
        this.stopTokenRefresh();
        this.refreshTimer = setInterval(async () => {
            try {
                await this.refreshToken();
            } catch (err) {
                console.error('[IDaaS] Token refresh failed:', err);
                this.stopTokenRefresh();
                if (typeof window !== 'undefined') {
                    window.dispatchEvent(new CustomEvent('idaas:session-expired'));
                }
            }
        }, 14 * 60 * 1000);
    }

    private stopTokenRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = undefined;
        }
    }

    dispose() {
        this.stopTokenRefresh();
    }
}

/**
 * Server-side SDK client.
 * Uses API key authentication and Bearer tokens (no cookies / CSRF).
 */
export class IDaaSServerClient extends IDaaSClient {
    constructor(config: { apiUrl: string; apiKey: string }) {
        super({ ...config, mode: 'server' });
    }
}

export default IDaaSClient;
