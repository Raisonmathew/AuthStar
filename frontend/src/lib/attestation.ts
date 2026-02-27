/**
 * EIAA Attestation Verification Module
 * 
 * Provides client-side verification of EIAA attestation signatures
 * for security-sensitive operations.
 */

import { base64ToArrayBuffer } from './utils';

/**
 * EIAA Attestation structure returned by API
 */
export interface EiaaAttestation {
    /** Ed25519 signature in base64 */
    signature_b64: string;
    /** Attestation body */
    body: AttestationBody;
}

export interface AttestationBody {
    /** SHA-256 hash of the capsule that made the decision */
    capsule_hash_b64: string;
    /** BLAKE3 hash of the decision output */
    decision_hash_b64: string;
    /** Unix timestamp when executed */
    executed_at_unix: number;
    /** Unix timestamp when attestation expires */
    expires_at_unix: number;
    /** Unique nonce to prevent replay attacks */
    nonce_b64: string;
    /** Key ID of the signing runtime */
    runtime_kid: string;
    /** AST hash for EIAA compliance */
    ast_hash_b64: string;
    /** Lowering version */
    lowering_version: string;
    /** WASM hash */
    wasm_hash_b64: string;
}

export interface RuntimeKey {
    kid: string;
    pk_b64: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
    valid: boolean;
    error?: string;
    /** Attestation has expired */
    expired?: boolean;
    /** Nonce mismatch (replay attack) */
    replayDetected?: boolean;
}

/**
 * EIAA Attestation Verifier
 * 
 * Verifies Ed25519 signatures on attestations using the Web Crypto API.
 */
export class AttestationVerifier {
    private publicKeys: Map<string, CryptoKey> = new Map();

    /**
     * Initialize the verifier by importing the public key
     */
    async initFromPem(publicKeyPem: string): Promise<void> {
        const pemContents = publicKeyPem
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s/g, '');

        const keyBytes = base64ToArrayBuffer(pemContents);
        const key = await crypto.subtle.importKey(
            'spki',
            keyBytes,
            { name: 'Ed25519' },
            true,
            ['verify']
        );

        this.publicKeys.clear();
        this.publicKeys.set('default', key);
    }

    async initFromKeys(keys: RuntimeKey[]): Promise<void> {
        this.publicKeys.clear();
        for (const key of keys) {
            const keyBytes = base64ToArrayBuffer(key.pk_b64);
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'Ed25519' },
                true,
                ['verify']
            );
            this.publicKeys.set(key.kid, cryptoKey);
        }
    }

    /**
     * Verify an attestation signature
     * 
     * @param attestation The attestation to verify
     * @param expectedNonce Optional nonce to check for replay protection
     * @returns Verification result
     */
    async verify(
        attestation: EiaaAttestation,
        expectedNonce?: string
    ): Promise<VerificationResult> {
        if (this.publicKeys.size === 0) {
            return { valid: false, error: 'Attestation verifier not initialized' };
        }

        try {
            // Check expiry
            const now = Math.floor(Date.now() / 1000);
            if (attestation.body.expires_at_unix < now) {
                return { valid: false, expired: true, error: 'Attestation expired' };
            }

            // Check nonce if provided
            if (expectedNonce && attestation.body.nonce_b64 !== expectedNonce) {
                return { valid: false, replayDetected: true, error: 'Nonce mismatch - possible replay attack' };
            }

            // Serialize body canonically (must match backend)
            const bodyBytes = this.serializeBody(attestation.body);

            // Decode signature
            const signature = base64ToArrayBuffer(attestation.signature_b64);

            const key = this.publicKeys.get(attestation.body.runtime_kid)
                ?? this.publicKeys.get('default');
            if (!key) {
                return { valid: false, error: `Unknown runtime key: ${attestation.body.runtime_kid}` };
            }

            const valid = await crypto.subtle.verify(
                'Ed25519',
                key,
                signature,
                bodyBytes as BufferSource
            );

            return { valid };
        } catch (error) {
            return {
                valid: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Serialize attestation body for signature verification
     * Must match backend bincode serialization
     */
    private serializeBody(body: AttestationBody): Uint8Array {
        // Simple JSON serialization - in production, use bincode-compatible format
        const json = JSON.stringify({
            capsule_hash_b64: body.capsule_hash_b64,
            decision_hash_b64: body.decision_hash_b64,
            executed_at_unix: body.executed_at_unix,
            expires_at_unix: body.expires_at_unix,
            nonce_b64: body.nonce_b64,
            runtime_kid: body.runtime_kid,
            ast_hash_b64: body.ast_hash_b64,
            lowering_version: body.lowering_version,
            wasm_hash_b64: body.wasm_hash_b64,
        });
        return new TextEncoder().encode(json);
    }
}

/**
 * Global verifier instance (lazy initialized)
 */
let globalVerifier: AttestationVerifier | null = null;

/**
 * Initialize the global attestation verifier
 * 
 * @param publicKeyPem Ed25519 public key in PEM format
 */
export async function initAttestationVerifierFromKeys(keys: RuntimeKey[]): Promise<void> {
    globalVerifier = new AttestationVerifier();
    await globalVerifier.initFromKeys(keys);
}

export async function initAttestationVerifierFromPem(publicKeyPem: string): Promise<void> {
    globalVerifier = new AttestationVerifier();
    await globalVerifier.initFromPem(publicKeyPem);
}

/**
 * Verify an attestation using the global verifier
 * 
 * @param attestation The attestation to verify
 * @param expectedNonce Optional nonce for replay protection
 */
export async function verifyAttestation(
    attestation: EiaaAttestation,
    expectedNonce?: string
): Promise<VerificationResult> {
    if (!globalVerifier) {
        throw new Error('Attestation verifier not initialized. Call initAttestationVerifierFromKeys first.');
    }
    return globalVerifier.verify(attestation, expectedNonce);
}

/**
 * React hook for attestation verification
 */
export function useAttestationVerifier() {
    return {
        verify: verifyAttestation,
        init: initAttestationVerifierFromKeys,
    };
}
