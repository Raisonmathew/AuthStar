import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig, AxiosResponse } from 'axios';
import {
    initAttestationVerifierFromKeys,
    initAttestationVerifierFromPem,
    verifyAttestation,
    RuntimeKey
} from '../attestation';
// CRITICAL-10+11 FIX: Import in-memory token accessor instead of reading from sessionStorage
import { getInMemoryToken, setInMemoryToken } from '../../features/auth/AuthContext';

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

    constructor() {
        this.client = axios.create({
            // Use relative path in development to go through Vite proxy, or explicit URL for production
            baseURL: import.meta.env.VITE_API_URL || '',
            withCredentials: true,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        this.setupInterceptors();
    }

    private setupInterceptors() {
        // Request interceptor
        // CRITICAL-10+11 FIX: Read token from in-memory store, NOT sessionStorage.
        this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
            const jwt = getInMemoryToken();
            if (jwt) {
                config.headers.Authorization = `Bearer ${jwt}`;
            }

            // org_id is not sensitive — it's already in the JWT claims and the
            // subdomain. Keeping it in sessionStorage for this header is acceptable.
            const orgId = sessionStorage.getItem('active_org_id');
            if (orgId) {
                config.headers['X-Organization-Id'] = orgId;
            }

            return config;
        });

        // Response interceptor
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

                    // Retry with the new token (interceptor will attach it)
                    return this.client(originalRequest);
                }

                return Promise.reject(error);
            }
        );
    }

    private async refreshToken() {
        // CRITICAL-10+11 FIX: Check in-memory token, not sessionStorage
        if (!getInMemoryToken()) return;

        try {
            // The HttpOnly refresh cookie is sent automatically by the browser
            const response = await axios.post(
                '/api/v1/token/refresh',
                {},
                { withCredentials: true }
            );

            // Store new access token in memory only — never in Web Storage
            const newToken: string = response.data.jwt;
            setInMemoryToken(newToken);
        } catch (error) {
            console.error('Token refresh failed:', error);
            // Clear in-memory token and redirect to login
            if (getInMemoryToken()) {
                setInMemoryToken(null);
                // Context-aware redirect
                if (window.location.pathname.startsWith('/admin')) {
                    window.location.href = '/admin/login';
                } else {
                    window.location.href = '/sign-in';
                }
            }
        }
    }

    public startTokenRefresh() {
        // CRITICAL-10+11 FIX: Check in-memory token, not sessionStorage
        // Note: AuthContext handles proactive refresh via its own interval.
        // This method is kept for backward compatibility but defers to the
        // in-memory check.
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

/** Structured API error type for consumers of this client. */
export interface ApiError {
    message: string;
    code?: string;
}
