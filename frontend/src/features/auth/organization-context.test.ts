import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { User } from './types';
import { resolvePreferredOrganizationContext } from './organization-context';

const { mockedGet } = vi.hoisted(() => ({
  mockedGet: vi.fn(),
}));

vi.mock('../../lib/api', () => ({
  api: {
    get: mockedGet,
  },
}));

function createToken(payload: Record<string, unknown>): string {
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `header.${encodedPayload}.signature`;
}

function createUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-1',
    created_at: '2026-04-21T00:00:00.000Z',
    email: 'admin@example.com',
    first_name: 'Admin',
    last_name: 'User',
    profile_image_url: null,
    email_verified: true,
    phone: null,
    phone_verified: false,
    mfa_enabled: false,
    ...overrides,
  };
}

describe('resolvePreferredOrganizationContext', () => {
  beforeEach(() => {
    mockedGet.mockReset();
    sessionStorage.clear();
  });

  it('keeps a non-system organization from the JWT without loading memberships', async () => {
    const token = createToken({ tenant_id: 'default' });

    const resolvedUser = await resolvePreferredOrganizationContext(token, createUser());

    expect(resolvedUser.organization_id).toBe('default');
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('selects a non-system admin organization when the session tenant is system', async () => {
    const token = createToken({ tenant_id: 'system' });
    mockedGet.mockResolvedValue({
      data: [
        { id: 'system', name: 'IDaaS Provider', slug: 'admin', role: 'member' },
        { id: 'default', name: 'Default Organization', slug: 'default', role: 'admin' },
      ],
    });

    const resolvedUser = await resolvePreferredOrganizationContext(token, createUser());

    expect(resolvedUser.organization_id).toBe('default');
    expect(mockedGet).toHaveBeenCalledWith('/api/v1/organizations', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  });
});