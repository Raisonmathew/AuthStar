/**
 * WebAuthn API Mocking for Passkey Tests
 * 
 * Provides mock implementations of navigator.credentials.create() and navigator.credentials.get()
 * for testing passkey registration and authentication flows without requiring actual hardware.
 */

import { Page } from '@playwright/test';

/**
 * Mock credential data structures
 */
export interface MockCredentialCreationOptions {
    challenge: string;
    rp: {
        name: string;
        id: string;
    };
    user: {
        id: string;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: Array<{
        type: string;
        alg: number;
    }>;
    authenticatorSelection?: {
        authenticatorAttachment?: 'platform' | 'cross-platform';
        requireResidentKey?: boolean;
        userVerification?: 'required' | 'preferred' | 'discouraged';
    };
    timeout?: number;
    attestation?: 'none' | 'indirect' | 'direct';
}

export interface MockCredentialRequestOptions {
    challenge: string;
    rpId?: string;
    allowCredentials?: Array<{
        type: string;
        id: ArrayBuffer;
    }>;
    userVerification?: 'required' | 'preferred' | 'discouraged';
    timeout?: number;
}

export interface MockPublicKeyCredential {
    id: string;
    rawId: ArrayBuffer;
    response: {
        clientDataJSON: ArrayBuffer;
        attestationObject?: ArrayBuffer;
        authenticatorData?: ArrayBuffer;
        signature?: ArrayBuffer;
        userHandle?: ArrayBuffer;
    };
    type: 'public-key';
    authenticatorAttachment?: 'platform' | 'cross-platform';
}

/**
 * Generate a mock credential ID
 */
function generateCredentialId(): string {
    return 'mock-credential-' + Math.random().toString(36).substring(2, 15);
}

/**
 * Convert base64url string to ArrayBuffer
 */
function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Convert ArrayBuffer to base64url string
 */
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Create a mock attestation object (simplified CBOR structure)
 */
function createMockAttestationObject(): ArrayBuffer {
    // Simplified mock - in reality this would be a proper CBOR-encoded structure
    const mockData = new Uint8Array(256);
    // Fill with some deterministic data
    for (let i = 0; i < mockData.length; i++) {
        mockData[i] = (i * 7) % 256;
    }
    return mockData.buffer;
}

/**
 * Create a mock authenticator data
 */
function createMockAuthenticatorData(): ArrayBuffer {
    const mockData = new Uint8Array(128);
    // Fill with some deterministic data
    for (let i = 0; i < mockData.length; i++) {
        mockData[i] = (i * 13) % 256;
    }
    return mockData.buffer;
}

/**
 * Create a mock signature
 */
function createMockSignature(): ArrayBuffer {
    const mockData = new Uint8Array(64);
    // Fill with some deterministic data
    for (let i = 0; i < mockData.length; i++) {
        mockData[i] = (i * 17) % 256;
    }
    return mockData.buffer;
}

/**
 * Create a mock client data JSON
 */
function createMockClientDataJSON(challenge: string, type: 'webauthn.create' | 'webauthn.get', origin: string): ArrayBuffer {
    const clientData = {
        type,
        challenge,
        origin,
        crossOrigin: false,
    };
    const json = JSON.stringify(clientData);
    const encoder = new TextEncoder();
    return encoder.encode(json).buffer;
}

/**
 * Enable WebAuthn mocking on a page
 * 
 * @param page - Playwright page object
 * @param options - Configuration options
 */
export async function enableWebAuthnMocking(
    page: Page,
    options: {
        shouldSucceed?: boolean;
        shouldCancel?: boolean;
        shouldTimeout?: boolean;
        credentialId?: string;
        userHandle?: string;
    } = {}
) {
    const {
        shouldSucceed = true,
        shouldCancel = false,
        shouldTimeout = false,
        credentialId = generateCredentialId(),
        userHandle = 'mock-user-handle',
    } = options;

    await page.addInitScript(
        ({ shouldSucceed, shouldCancel, shouldTimeout, credentialId, userHandle }) => {
            // Helper functions (must be redefined in browser context)
            const base64urlToArrayBuffer = (base64url: string): ArrayBuffer => {
                const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes.buffer;
            };

            const createMockData = (size: number, seed: number): ArrayBuffer => {
                const data = new Uint8Array(size);
                for (let i = 0; i < size; i++) {
                    data[i] = (i * seed) % 256;
                }
                return data.buffer;
            };

            const createMockClientDataJSON = (challenge: string, type: string, origin: string): ArrayBuffer => {
                const clientData = {
                    type,
                    challenge,
                    origin,
                    crossOrigin: false,
                };
                const json = JSON.stringify(clientData);
                const encoder = new TextEncoder();
                return encoder.encode(json).buffer;
            };

            // Mock navigator.credentials.create()
            const originalCreate = navigator.credentials.create.bind(navigator.credentials);
            navigator.credentials.create = async (options: any): Promise<any> => {
                console.log('[WebAuthn Mock] create() called with options:', options);

                if (!options?.publicKey) {
                    return originalCreate(options);
                }

                if (shouldCancel) {
                    throw new DOMException('The operation was cancelled by the user.', 'NotAllowedError');
                }

                if (shouldTimeout) {
                    throw new DOMException('The operation timed out.', 'NotAllowedError');
                }

                if (!shouldSucceed) {
                    throw new DOMException('An unknown error occurred.', 'UnknownError');
                }

                const challenge = options.publicKey.challenge;
                const challengeStr = typeof challenge === 'string' 
                    ? challenge 
                    : btoa(String.fromCharCode(...new Uint8Array(challenge)));

                const mockCredential: any = {
                    id: credentialId,
                    rawId: new TextEncoder().encode(credentialId).buffer,
                    response: {
                        clientDataJSON: createMockClientDataJSON(challengeStr, 'webauthn.create', window.location.origin),
                        attestationObject: createMockData(256, 7),
                        getPublicKey: () => createMockData(65, 11),
                        getPublicKeyAlgorithm: () => -7, // ES256
                        getAuthenticatorData: () => createMockData(128, 13),
                        getTransports: () => ['internal', 'hybrid'],
                    },
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    getClientExtensionResults: () => ({}),
                };

                console.log('[WebAuthn Mock] Returning mock credential:', mockCredential);
                return mockCredential;
            };

            // Mock navigator.credentials.get()
            const originalGet = navigator.credentials.get.bind(navigator.credentials);
            navigator.credentials.get = async (options: any): Promise<any> => {
                console.log('[WebAuthn Mock] get() called with options:', options);

                if (!options?.publicKey) {
                    return originalGet(options);
                }

                if (shouldCancel) {
                    throw new DOMException('The operation was cancelled by the user.', 'NotAllowedError');
                }

                if (shouldTimeout) {
                    throw new DOMException('The operation timed out.', 'NotAllowedError');
                }

                if (!shouldSucceed) {
                    throw new DOMException('An unknown error occurred.', 'UnknownError');
                }

                const challenge = options.publicKey.challenge;
                const challengeStr = typeof challenge === 'string'
                    ? challenge
                    : btoa(String.fromCharCode(...new Uint8Array(challenge)));

                const mockCredential: any = {
                    id: credentialId,
                    rawId: new TextEncoder().encode(credentialId).buffer,
                    response: {
                        clientDataJSON: createMockClientDataJSON(challengeStr, 'webauthn.get', window.location.origin),
                        authenticatorData: createMockData(128, 13),
                        signature: createMockData(64, 17),
                        userHandle: new TextEncoder().encode(userHandle).buffer,
                    },
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    getClientExtensionResults: () => ({}),
                };

                console.log('[WebAuthn Mock] Returning mock credential:', mockCredential);
                return mockCredential;
            };

            console.log('[WebAuthn Mock] Mocking enabled');
        },
        { shouldSucceed, shouldCancel, shouldTimeout, credentialId, userHandle }
    );
}

/**
 * Disable WebAuthn mocking (restore original behavior)
 */
export async function disableWebAuthnMocking(page: Page) {
    await page.addInitScript(() => {
        // This will be overridden on next page load
        console.log('[WebAuthn Mock] Mocking disabled (will restore on next navigation)');
    });
}

/**
 * Mock WebAuthn not supported
 */
export async function mockWebAuthnNotSupported(page: Page) {
    await page.addInitScript(() => {
        // Remove credentials API
        Object.defineProperty(navigator, 'credentials', {
            value: undefined,
            writable: false,
            configurable: false,
        });
        console.log('[WebAuthn Mock] WebAuthn API removed (not supported)');
    });
}

/**
 * Check if WebAuthn is available in the page
 */
export async function isWebAuthnAvailable(page: Page): Promise<boolean> {
    return await page.evaluate(() => {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    });
}

/**
 * Preset configurations for common test scenarios
 */
export const WebAuthnMockPresets = {
    /**
     * Successful registration
     */
    successfulRegistration: {
        shouldSucceed: true,
        shouldCancel: false,
        shouldTimeout: false,
    },

    /**
     * Successful authentication
     */
    successfulAuthentication: {
        shouldSucceed: true,
        shouldCancel: false,
        shouldTimeout: false,
    },

    /**
     * User cancelled the operation
     */
    userCancelled: {
        shouldSucceed: false,
        shouldCancel: true,
        shouldTimeout: false,
    },

    /**
     * Operation timed out
     */
    timeout: {
        shouldSucceed: false,
        shouldCancel: false,
        shouldTimeout: true,
    },

    /**
     * Unknown error
     */
    error: {
        shouldSucceed: false,
        shouldCancel: false,
        shouldTimeout: false,
    },
};

// Made with Bob
