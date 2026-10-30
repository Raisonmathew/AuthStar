import axios, { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import type {
    IDaaSConfig,
    User,
    SignUpRequest,
    SignInRequest,
    Organization,
    SdkManifest,
} from './types';
import { AttestationVerifier, EiaaAttestation, RuntimeKey } from './attestation';

export class IDaaSClient {
    protected client: AxiosInstance;
    protected jwt?: string;
    protected mode: 'browser' | 'server';
    private apiUrl: string;
    private verifyAttestations: boolean;
    private runtimeKeyTtlMs: number;
    private failOpenOnVerifierUnavailable: boolean;
    private runtimeKeyFetchMaxAttempts: number;
    private verifier = new AttestationVerifier();
    private verifierInit?: Promise<void>;
    private inflightReload?: Promise<void>;
    private lastRuntimeKeyFetch = 0;
    private csrfToken?: string;
    // MEDIUM-13 FIX: Auto token refresh timer
    private refreshTimer?: ReturnType<typeof setInterval>;

    constructor(config: IDaaSConfig) {
        this.mode = config.mode ?? 'browser';
        this.apiUrl = config.apiUrl.replace(/\/$/, '');
        this.verifyAttestations = config.verifyAttestations ?? true;
        this.runtimeKeyTtlMs = config.runtimeKeyTtlMs ?? 10 * 60 * 1000;
        this.failOpenOnVerifierUnavailable = config.failOpenOnVerifierUnavailable ?? false;
        this.runtimeKeyFetchMaxAttempts = Math.max(1, config.runtimeKeyFetchMaxAttempts ?? 3);

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

        this.client.interceptors.response.use(async (response: AxiosResponse) => {
            await this.verifyResponseAttestation(response);
            if (this.mode === 'browser' && typeof document !== 'undefined') {
                const match = document.cookie.match(/(?:^|;\s*)__csrf=([^;]*)/);
                if (match) {
                    this.csrfToken = match[1];
                }
            }
            return response;
        });

    }

    private async verifyResponseAttestation(response: AxiosResponse): Promise<void> {
        if (!this.verifyAttestations) return;
        const attestation = response.data?.attestation as EiaaAttestation | undefined;
        if (!attestation) return;

        try {
            await this.ensureAttestationVerifier();
        } catch (err) {
            if (this.failOpenOnVerifierUnavailable) {
                // Configured fail-open: log and continue without verification.
                // eslint-disable-next-line no-console
                console.warn('[IDaaS] Skipping attestation verification (verifier unavailable):', err);
                return;
            }
            throw new Error(
                `EIAA attestation verifier unavailable: ${(err as Error)?.message ?? 'unknown error'}`,
            );
        }
        let result = await this.verifier.verify(attestation);
        if (!result.valid && result.error?.startsWith('Unknown runtime key')) {
            try {
                await this.reloadRuntimeKeysOnce();
            } catch (err) {
                if (this.failOpenOnVerifierUnavailable) {
                    // eslint-disable-next-line no-console
                    console.warn('[IDaaS] Failed to refresh runtime keys (verifier unavailable):', err);
                    return;
                }
                throw err;
            }
            result = await this.verifier.verify(attestation);
        }
        if (!result.valid) {
            throw new Error(`Invalid EIAA attestation: ${result.error ?? 'signature verification failed'}`);
        }
    }

    private async ensureAttestationVerifier(): Promise<void> {
        const stale = Date.now() - this.lastRuntimeKeyFetch > this.runtimeKeyTtlMs;
        if (!this.verifierInit || stale) {
            // Single-flight: collapse concurrent stale-cache reloads onto one
            // promise so a burst of in-flight requests doesn't trigger N parallel
            // calls to /api/eiaa/v1/runtime/keys.
            this.verifierInit = this.reloadRuntimeKeysOnce();
        }
        await this.verifierInit;
    }

    /**
     * Reload runtime keys with retry/backoff. Concurrent callers share the
     * same in-flight promise so only one network request is made per stale
     * window.
     */
    private async reloadRuntimeKeysOnce(): Promise<void> {
        if (this.inflightReload) {
            return this.inflightReload;
        }
        this.inflightReload = (async () => {
            try {
                await this.reloadRuntimeKeysWithRetry();
            } finally {
                this.inflightReload = undefined;
            }
        })();
        return this.inflightReload;
    }

    private async reloadRuntimeKeysWithRetry(): Promise<void> {
        let lastError: unknown;
        for (let attempt = 1; attempt <= this.runtimeKeyFetchMaxAttempts; attempt++) {
            try {
                await this.reloadRuntimeKeys();
                return;
            } catch (err) {
                lastError = err;
                if (attempt === this.runtimeKeyFetchMaxAttempts) break;
                // Exponential backoff with jitter: 100ms, 200ms, 400ms, ...
                const base = 100 * Math.pow(2, attempt - 1);
                const jitter = Math.floor(Math.random() * 50);
                await new Promise((resolve) => setTimeout(resolve, base + jitter));
            }
        }
        throw lastError instanceof Error
            ? lastError
            : new Error('Failed to reload EIAA runtime keys');
    }

    private async reloadRuntimeKeys(): Promise<void> {
        const response = await axios.get<RuntimeKey[]>(`${this.apiUrl}/api/eiaa/v1/runtime/keys`, {
            withCredentials: this.mode === 'browser',
        });
        await this.verifier.initFromKeys(response.data);
        this.lastRuntimeKeyFetch = Date.now();
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
