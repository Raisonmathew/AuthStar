export interface EiaaAttestation {
    signature_b64: string;
    body: AttestationBody;
}

export interface AttestationBody {
    capsule_hash_b64: string;
    decision_hash_b64: string;
    executed_at_unix: number;
    expires_at_unix: number;
    nonce_b64: string;
    runtime_kid: string;
    ast_hash_b64?: string;
    lowering_version?: string;
    wasm_hash_b64?: string;
}

export interface RuntimeKey {
    kid: string;
    pk_b64: string;
}

export interface VerificationResult {
    valid: boolean;
    error?: string;
    expired?: boolean;
}

export class AttestationVerifier {
    private publicKeys = new Map<string, CryptoKey>();

    async initFromKeys(keys: RuntimeKey[]): Promise<void> {
        this.publicKeys.clear();
        for (const key of keys) {
            const keyBytes = base64UrlToBytes(key.pk_b64);
            const cryptoKey = await getCrypto().subtle.importKey(
                'raw',
                toArrayBuffer(keyBytes),
                { name: 'Ed25519' },
                true,
                ['verify']
            );
            this.publicKeys.set(key.kid, cryptoKey);
        }
    }

    async verify(attestation: EiaaAttestation): Promise<VerificationResult> {
        try {
            if (this.publicKeys.size === 0) {
                return { valid: false, error: 'Attestation verifier not initialized' };
            }
            const now = Math.floor(Date.now() / 1000);
            if (attestation.body.expires_at_unix < now) {
                return { valid: false, expired: true, error: 'Attestation expired' };
            }
            const key = this.publicKeys.get(attestation.body.runtime_kid);
            if (!key) {
                return { valid: false, error: `Unknown runtime key: ${attestation.body.runtime_kid}` };
            }
            const valid = await getCrypto().subtle.verify(
                'Ed25519',
                key,
                toArrayBuffer(base64UrlToBytes(attestation.signature_b64)),
                toArrayBuffer(serializeBody(attestation.body))
            );
            return { valid };
        } catch (error) {
            return { valid: false, error: error instanceof Error ? error.message : 'Unknown error' };
        }
    }
}

function serializeBody(body: AttestationBody): Uint8Array {
    const record = body as unknown as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
        if (record[key] !== undefined) {
            sorted[key] = record[key];
        }
    }
    return new TextEncoder().encode(JSON.stringify(sorted));
}

function base64UrlToBytes(value: string): Uint8Array {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    if (typeof atob === 'function') {
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    const BufferCtor = (globalThis as unknown as { Buffer?: { from(input: string, encoding: string): Uint8Array } }).Buffer;
    if (BufferCtor) {
        return new Uint8Array(BufferCtor.from(padded, 'base64'));
    }
    throw new Error('No base64 decoder available');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function getCrypto(): Crypto {
    if (globalThis.crypto?.subtle) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not available');
}
