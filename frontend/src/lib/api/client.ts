import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import {
    initAttestationVerifierFromKeys,
    initAttestationVerifierFromPem,
    verifyAttestation,
    RuntimeKey
} from '../attestation';
import { getInMemoryToken, setInMemoryToken } from '../auth-storage';

let verifierInit: Promise<void> | null = null;
let lastKeysFetch = 0;
const RUNTIME_KEY_TTL_MS = (() => {
    const raw = import.meta.env.VITE_RUNTIME_KEY_TTL_MS as string | undefined;
    const parsed = raw ? Number(raw) : NaN;
    if (!Number.isFinite(parsed) || parsed < 0) {
        return 10 * 60 * 1000;
    }
    return parsed;
})();

async function fetchRuntimeKeys(): Promise<RuntimeKey[]> {
    const baseUrl = import.meta.env.VITE_API_URL || '';
    const response = await fetch(`${baseUrl}/api/eiaa/v1/runtime/keys`, {
        method: 'GET',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
        throw new Error(`Failed to load runtime keys: ${response.status}`);
    }

    lastKeysFetch = Date.now();
    return response.json() as Promise<RuntimeKey[]>;
}

async function reloadRuntimeKeys(): Promise<void> {
    verifierInit = (async () => {
        const keys = await fetchRuntimeKeys();
        await initAttestationVerifierFromKeys(keys);
    })();
    await verifierInit;
}

async function ensureAttestationVerifier() {
    const stale = Date.now() - lastKeysFetch > RUNTIME_KEY_TTL_MS;
    if (!verifierInit || stale) {
        verifierInit = (async () => {
            try {
                const keys = await fetchRuntimeKeys();
                await initAttestationVerifierFromKeys(keys);
            } catch (err) {
                const pem = import.meta.env.VITE_RUNTIME_PUBKEY_PEM as string | undefined;
                if (!pem) {
                    throw err;
                }
                await initAttestationVerifierFromPem(pem);
            }
        })();
    }
    await verifierInit;
}

class APIClient {
    private client: AxiosInstance;
    private refreshing: Promise<void> | null = null;
    private csrfToken: string | null = null;
    private fetchingCsrf: Promise<string> | null = null;

    constructor() {
        this.client = axios.create({
            baseURL: import.meta.env.VITE_API_URL || '',
            withCredentials: true,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        this.setupInterceptors();
    }

    private setupInterceptors() {
        this.client.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
            const jwt = getInMemoryToken();
            if (jwt) {
                config.headers.Authorization = `Bearer ${jwt}`;
            }

            if (config.method && !['get', 'head', 'options'].includes(config.method.toLowerCase())) {
                const token = await this.ensureCsrfToken();
                if (token) {
                    config.headers['x-csrf-token'] = token;
                }
            }

            const orgId = sessionStorage.getItem('active_org_id');
            if (orgId) {
                config.headers['X-Organization-Id'] = orgId;
            }

            return config;
        });

        this.client.interceptors.response.use(
            async (response: AxiosResponse) => {
                const attestation = response?.data?.attestation;
                if (attestation) {
                    await ensureAttestationVerifier();
                    let result = await verifyAttestation(attestation);
                    if (!result.valid && result.error?.startsWith('Unknown runtime key')) {
                        await reloadRuntimeKeys();
                        result = await verifyAttestation(attestation);
                    }
                    if (!result.valid) {
                        throw new Error('Invalid attestation signature');
                    }
                }
                return response;
            },
            async (error: AxiosError) => {
                const originalRequest = error.config as any;

                if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
                    originalRequest._retry = true;

                    if (!this.refreshing) {
                        this.refreshing = this.refreshToken();
                    }

                    await this.refreshing;
                    this.refreshing = null;

                    return this.client(originalRequest);
                }

                return Promise.reject(error);
            }
        );
    }

    private async refreshToken() {
        if (!getInMemoryToken()) return;

        try {
            const response = await axios.post(
                '/api/v1/token/refresh',
                {},
                { withCredentials: true }
            );

            const newToken: string = response.data.jwt;
            setInMemoryToken(newToken);
        } catch (error) {
            console.error('Token refresh failed:', error);
            if (getInMemoryToken()) {
                setInMemoryToken(null);
                if (window.location.pathname.startsWith('/admin')) {
                    window.location.href = '/admin/login';
                } else {
                    window.location.href = '/sign-in';
                }
            }
        }
    }

    private async ensureCsrfToken(): Promise<string | null> {
        if (this.csrfToken) return this.csrfToken;
        if (this.fetchingCsrf) return this.fetchingCsrf;

        this.fetchingCsrf = (async () => {
            try {
                const baseUrl = import.meta.env.VITE_API_URL || '';
                const response = await axios.get(`${baseUrl}/api/csrf-token`, {
                    withCredentials: true,
                });
                this.csrfToken = response.data.csrf_token;
                return this.csrfToken!;
            } catch (err) {
                console.error('Failed to fetch CSRF token:', err);
                return '';
            } finally {
                this.fetchingCsrf = null;
            }
        })();

        return this.fetchingCsrf;
    }

    public startTokenRefresh() {
        setInterval(async () => {
            if (getInMemoryToken()) {
                await this.refreshToken();
            }
        }, 14 * 60 * 1000);
    }

    public async prefetchRuntimeKeys(): Promise<void> {
        await ensureAttestationVerifier();
    }

    public get<T>(url: string, config = {}) {
        return this.client.get<T>(url, config);
    }

    public post<T>(url: string, data?: any, config = {}) {
        return this.client.post<T>(url, data, config);
    }

    public put<T>(url: string, data?: any, config = {}) {
        return this.client.put<T>(url, data, config);
    }

    public patch<T>(url: string, data?: any, config = {}) {
        return this.client.patch<T>(url, data, config);
    }

    public delete<T>(url: string, config = {}) {
        return this.client.delete<T>(url, config);
    }
}

export const api = new APIClient();

export interface ApiError {
    message: string;
    code?: string;
}
