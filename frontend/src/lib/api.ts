import axios from 'axios';
import {
  initAttestationVerifierFromKeys,
  initAttestationVerifierFromPem,
  verifyAttestation,
  RuntimeKey
} from './attestation';

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
  const response = await fetch(`${API_URL}/api/eiaa/v1/runtime/keys`, {
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

// Ensure this matches your backend URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth interceptor
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('admin_token') || sessionStorage.getItem('jwt');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Step-Up Authentication Logic
import {
  AUTH_STEP_UP_COMPLETE,
  AUTH_STEP_UP_CANCELLED,
  dispatchStepUpRequired
} from './events';

let isSteppingUp = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: any) => void;
  config: any;
}> = [];

const processQueue = (error: any = null, token: string | null = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      // Update token if provided (optional, usually session stays same but permission changes)
      if (token) {
        prom.config.headers['Authorization'] = `Bearer ${token}`; // Just in case
      }
      api(prom.config).then(prom.resolve).catch(prom.reject);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  async (response) => {
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
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 403 && !originalRequest._retry) {
      // Check if it's a step-up challenge (generic 403 might mean permission denied for other reasons)
      // But for now, we assume 403 on protected routes means "Provisional Session" if we are logged in.
      // Ideally backend sends a specific code e.g. "MFA_REQUIRED".

      if (isSteppingUp) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject, config: originalRequest });
        });
      }

      originalRequest._retry = true;
      isSteppingUp = true;

      // Extract requirement from response if available (assuming it's in data.requirement or just data)
      // Based on backend ReExecutionService, the error body might not be standard.
      // But usually 403 body is JSON. Let's assume `data.requirement` or `data` if it matches shape.
      // For now, let's look for `requirement` property.
      const requirement = error.response?.data?.requirement;
      dispatchStepUpRequired(originalRequest, requirement);

      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject, config: originalRequest });

        const onComplete = () => {
          window.removeEventListener(AUTH_STEP_UP_COMPLETE, onComplete);
          window.removeEventListener(AUTH_STEP_UP_CANCELLED, onCancel);
          isSteppingUp = false;
          processQueue();
        };

        const onCancel = () => {
          window.removeEventListener(AUTH_STEP_UP_COMPLETE, onComplete);
          window.removeEventListener(AUTH_STEP_UP_CANCELLED, onCancel);
          isSteppingUp = false;
          processQueue(error); // Reject all
        };

        window.addEventListener(AUTH_STEP_UP_COMPLETE, onComplete);
        window.addEventListener(AUTH_STEP_UP_CANCELLED, onCancel);
      });
    }

    return Promise.reject(error);
  }
);

// Generic Error Handler
export interface ApiError {
  message: string;
  code?: string;
}
