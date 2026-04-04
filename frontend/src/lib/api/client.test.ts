import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Mock modules BEFORE importing the client
const mockGetInMemoryToken = vi.fn<() => string | null>().mockReturnValue(null);
const mockSetInMemoryToken = vi.fn();

vi.mock('../../features/auth/AuthContext', () => ({
  getInMemoryToken: () => mockGetInMemoryToken(),
  setInMemoryToken: (...args: any[]) => mockSetInMemoryToken(...args),
}));

vi.mock('../attestation', () => ({
  initAttestationVerifierFromKeys: vi.fn(),
  initAttestationVerifierFromPem: vi.fn(),
  verifyAttestation: vi.fn().mockResolvedValue({ valid: true }),
  RuntimeKey: {},
}));

import { api } from './client';

// We use a custom axios adapter to capture the actual request config
// that reaches the network layer (after interceptors have run).
function installCaptureAdapter(client: any): { getCaptured: () => any } {
  let capturedConfig: any = null;
  // Access the internal axios instance
  const axiosInstance = (client as any).client;
  if (axiosInstance?.defaults) {
    axiosInstance.defaults.adapter = (config: any) => {
      capturedConfig = config;
      return Promise.resolve({
        data: {},
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        config,
      });
    };
  }
  return { getCaptured: () => capturedConfig };
}

describe('APIClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetInMemoryToken.mockReturnValue(null);
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('public methods exist', () => {
    it('has get, post, put, patch, delete methods', () => {
      expect(typeof api.get).toBe('function');
      expect(typeof api.post).toBe('function');
      expect(typeof api.put).toBe('function');
      expect(typeof api.patch).toBe('function');
      expect(typeof api.delete).toBe('function');
    });
  });

  describe('request interceptor', () => {
    it('attaches Bearer token when available', async () => {
      mockGetInMemoryToken.mockReturnValue('my-jwt');

      const { getCaptured } = installCaptureAdapter(api);

      await api.get('/test');

      const config = getCaptured();
      expect(config).not.toBeNull();
      expect(config.headers.Authorization).toBe('Bearer my-jwt');
    });

    it('attaches X-Organization-Id from sessionStorage', async () => {
      sessionStorage.setItem('active_org_id', 'org-123');

      const { getCaptured } = installCaptureAdapter(api);

      await api.get('/test');

      const config = getCaptured();
      expect(config).not.toBeNull();
      expect(config.headers['X-Organization-Id']).toBe('org-123');
    });

    it('omits Authorization header when no token', async () => {
      mockGetInMemoryToken.mockReturnValue(null);

      const { getCaptured } = installCaptureAdapter(api);

      await api.get('/test');

      const config = getCaptured();
      expect(config).not.toBeNull();
      // Authorization header should not be set
      expect(config.headers.Authorization).toBeUndefined();
    });
  });
});
