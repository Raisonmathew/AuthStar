import { api } from '../../lib/api';
import type { User } from './types';

interface OrganizationMembership {
  id: string;
  name: string;
  slug: string;
  role?: string;
}

function decodeOrganizationId(token: string): string | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1] ?? ''));
    const organizationId = payload.org_id ?? payload.tenant_id;
    return typeof organizationId === 'string' && organizationId.length > 0
      ? organizationId
      : null;
  } catch {
    return null;
  }
}

function isAdminRole(role?: string): boolean {
  return role === 'owner' || role === 'admin';
}

function choosePreferredOrganization(
  organizations: OrganizationMembership[],
  currentOrganizationId: string | null,
  storedOrganizationId: string | null,
): OrganizationMembership | null {
  const eligibleOrganizations = organizations.filter(
    (organization) => organization.id !== 'system',
  );

  if (eligibleOrganizations.length === 0) {
    return organizations[0] ?? null;
  }

  if (storedOrganizationId) {
    const storedOrganization = eligibleOrganizations.find(
      (organization) => organization.id === storedOrganizationId,
    );
    if (storedOrganization) {
      return storedOrganization;
    }
  }

  const adminOrganization = eligibleOrganizations.find((organization) =>
    isAdminRole(organization.role),
  );
  if (adminOrganization) {
    return adminOrganization;
  }

  if (currentOrganizationId) {
    const currentOrganization = eligibleOrganizations.find(
      (organization) => organization.id === currentOrganizationId,
    );
    if (currentOrganization) {
      return currentOrganization;
    }
  }

  const defaultOrganization = eligibleOrganizations.find(
    (organization) => organization.slug === 'default',
  );
  if (defaultOrganization) {
    return defaultOrganization;
  }

  return eligibleOrganizations[0];
}

export async function resolvePreferredOrganizationContext(
  token: string,
  user: User,
): Promise<User> {
  const currentOrganizationId = user.organization_id ?? decodeOrganizationId(token);

  if (currentOrganizationId && currentOrganizationId !== 'system') {
    return {
      ...user,
      organization_id: currentOrganizationId,
    };
  }

  try {
    const storedOrganizationId = sessionStorage.getItem('active_org_id');
    const response = await api.get<OrganizationMembership[]>('/api/v1/organizations', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const preferredOrganization = choosePreferredOrganization(
      Array.isArray(response.data) ? response.data : [],
      currentOrganizationId,
      storedOrganizationId,
    );

    if (preferredOrganization) {
      return {
        ...user,
        organization_id: preferredOrganization.id,
      };
    }
  } catch {
    // Fall back to the current token context if memberships cannot be loaded.
  }

  return currentOrganizationId
    ? {
        ...user,
        organization_id: currentOrganizationId,
      }
    : user;
}