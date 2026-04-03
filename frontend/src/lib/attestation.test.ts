import { vi, describe, it, expect, beforeEach } from 'vitest';
import {
  AttestationVerifier,
  initAttestationVerifierFromKeys,
  verifyAttestation,
  EiaaAttestation,
  AttestationBody,
} from './attestation';

// The Web Crypto API may not be fully available in jsdom, so we test
// the serialization and structural checks rather than real Ed25519 verification.

function makeBody(overrides: Partial<AttestationBody> = {}): AttestationBody {
  return {
    capsule_hash_b64: 'abc=',
    decision_hash_b64: 'def=',
    executed_at_unix: Math.floor(Date.now() / 1000) - 10,
    expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
    nonce_b64: 'nonce123=',
    runtime_kid: 'key-1',
    ast_hash_b64: 'ast=',
    lowering_version: 'v1',
    wasm_hash_b64: 'wasm=',
    ...overrides,
  };
}

function makeAttestation(overrides: Partial<AttestationBody> = {}): EiaaAttestation {
  return {
    signature_b64: 'AAAA', // Dummy — won't verify but exercises code paths
    body: makeBody(overrides),
  };
}

describe('AttestationVerifier', () => {
  let verifier: AttestationVerifier;

  beforeEach(() => {
    verifier = new AttestationVerifier();
  });

  it('returns error when not initialized', async () => {
    const result = await verifier.verify(makeAttestation());
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Attestation verifier not initialized');
  });

  it('detects expired attestations', async () => {
    // We need to init with a key first to bypass the "not initialized" check.
    // Since jsdom may not support Ed25519, we mock crypto.subtle.importKey
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);
    vi.spyOn(crypto.subtle, 'verify').mockResolvedValue(false);

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);

    const result = await verifier.verify(
      makeAttestation({
        expires_at_unix: Math.floor(Date.now() / 1000) - 100, // expired
      })
    );

    expect(result.valid).toBe(false);
    expect(result.expired).toBe(true);
    expect(result.error).toBe('Attestation expired');
  });

  it('detects nonce mismatch (replay attack)', async () => {
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);
    vi.spyOn(crypto.subtle, 'verify').mockResolvedValue(true);

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);

    const result = await verifier.verify(
      makeAttestation({ nonce_b64: 'actual-nonce' }),
      'expected-nonce'
    );

    expect(result.valid).toBe(false);
    expect(result.replayDetected).toBe(true);
    expect(result.error).toContain('Nonce mismatch');
  });

  it('returns unknown key error for unrecognized runtime_kid', async () => {
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);

    const result = await verifier.verify(
      makeAttestation({ runtime_kid: 'unknown-key' })
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Unknown runtime key');
  });

  it('serializes body with keys in lexicographic order', async () => {
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);

    let capturedBody: ArrayBuffer | null = null;
    vi.spyOn(crypto.subtle, 'verify').mockImplementation(
      async (_algo: any, _key: any, _sig: any, data: any) => {
        capturedBody = data;
        return true;
      }
    );

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);
    await verifier.verify(makeAttestation());

    expect(capturedBody).not.toBeNull();
    const json = new TextDecoder().decode(capturedBody!);
    const keys = Object.keys(JSON.parse(json));
    // Verify keys are sorted lexicographically
    const sorted = [...keys].sort();
    expect(keys).toEqual(sorted);
  });

  it('verify returns valid:true when signature matches', async () => {
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);
    vi.spyOn(crypto.subtle, 'verify').mockResolvedValue(true);

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);

    const result = await verifier.verify(makeAttestation());
    expect(result.valid).toBe(true);
  });

  it('verify returns valid:false when signature does not match', async () => {
    const mockKey = {} as CryptoKey;
    vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockKey);
    vi.spyOn(crypto.subtle, 'verify').mockResolvedValue(false);

    await verifier.initFromKeys([{ kid: 'key-1', pk_b64: 'AAAA' }]);

    const result = await verifier.verify(makeAttestation());
    expect(result.valid).toBe(false);
  });
});

describe('global verifier functions', () => {
  it('verifyAttestation throws if not initialized', async () => {
    // Reset global state by re-importing — in practice it throws
    await expect(verifyAttestation(makeAttestation())).rejects.toThrow(
      'Attestation verifier not initialized'
    );
  });
});
