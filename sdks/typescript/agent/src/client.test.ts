import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AgentAuthzClient } from '../src/client.js';
import { AgentAuthzDenied } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeClient(overrides: Partial<Parameters<typeof AgentAuthzClient>[0]> = {}) {
  return new AgentAuthzClient({
    baseUrl: 'https://api.authstar.com',
    tenantId: 'acme',
    apiKey: 'test-api-key-unit-tests-only',
    agentId: 'agt_abc123',
    taskId: 'task_xyz789',
    agentToken: 'pre_minted_jwt', // skip token issuance in unit tests
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// hashToolArgs
// ---------------------------------------------------------------------------

describe('AgentAuthzClient.hashToolArgs', () => {
  it('returns a 64-char hex string', () => {
    const hash = AgentAuthzClient.hashToolArgs({ to: 'user@example.com', body: 'hi' });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic regardless of key insertion order', () => {
    const h1 = AgentAuthzClient.hashToolArgs({ b: 2, a: 1 });
    const h2 = AgentAuthzClient.hashToolArgs({ a: 1, b: 2 });
    expect(h1).toBe(h2);
  });

  it('produces different hashes for different args', () => {
    const h1 = AgentAuthzClient.hashToolArgs({ to: 'a@b.com' });
    const h2 = AgentAuthzClient.hashToolArgs({ to: 'c@d.com' });
    expect(h1).not.toBe(h2);
  });
});

// ---------------------------------------------------------------------------
// Token caching (G-6)
// ---------------------------------------------------------------------------

describe('AgentAuthzClient token caching', () => {
  it('reuses a pre-minted token that has not expired', async () => {
    const client = makeClient({ agentToken: 'valid_token', tokenTtlSeconds: 3600 });
    // Access private field for test inspection
    const token = await (client as any)._ensureToken();
    expect(token).toBe('valid_token');
  });

  it('re-mints when the pre-minted token is within the 60 s refresh margin', async () => {
    const client = makeClient({ agentToken: 'old_token', tokenTtlSeconds: 3600 });
    // Force expiry to be within the 60-second refresh margin
    (client as any)._tokenExpiresAt = Date.now() + 30_000; // 30 s remaining

    // Mock the HTTP post
    const postSpy = vi.spyOn((client as any).http, 'post').mockResolvedValueOnce({
      data: { token: 'new_token', expires_in: 3600 },
    });

    const token = await (client as any)._ensureToken();
    expect(token).toBe('new_token');
    expect(postSpy).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// AgentAuthzDenied
// ---------------------------------------------------------------------------

describe('AgentAuthzDenied', () => {
  it('sets message from reason', () => {
    const err = new AgentAuthzDenied({
      allowed: false,
      reason: 'risk score too high',
      decision_ref: 'dec_001',
    });
    expect(err.message).toBe('risk score too high');
    expect(err.decision_ref).toBe('dec_001');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AgentAuthzDenied);
  });

  it('uses default message when reason is absent', () => {
    const err = new AgentAuthzDenied({ allowed: false, decision_ref: 'dec_002' });
    expect(err.message).toBe('Agent tool call denied by EIAA capsule');
  });
});
