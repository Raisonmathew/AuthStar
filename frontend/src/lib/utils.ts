/**
 * Utility functions for EIAA attestation handling
 */

/**
 * Convert base64 string to ArrayBuffer
 */
function normalizeBase64(input: string): string {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    if (padding === 2) return `${base64}==`;
    if (padding === 3) return `${base64}=`;
    if (padding === 1) return `${base64}===`;
    return base64;
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(normalizeBase64(base64));
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Convert ArrayBuffer to base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Generate a random nonce for attestation requests
 */
export function generateNonce(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return arrayBufferToBase64(array.buffer);
}
