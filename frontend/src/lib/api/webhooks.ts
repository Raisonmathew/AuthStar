/**
 * Typed API client wrappers for Tenant Webhook endpoints.
 *
 * Base path: /api/v1/webhooks
 *
 * Security: The `secret` field is only present on the CreateWebhookResponse
 * (returned once at creation). List responses return `secret_masked` ("********").
 * Never persist the secret beyond the one-time reveal UX.
 */

import { api } from '../api/client';

// ---- Shared types ------------------------------------------------------------

export interface WebhookEndpoint {
  id: string;
  url: string;
  /** Always "********" on list responses. Full value only in CreateWebhookResponse. */
  secret_masked: string;
  description: string | null;
  active: boolean;
  last_delivery_at: string | null;
  last_delivery_status: number | null;
  last_delivery_success: boolean | null;
  created_at: string;
  updated_at: string;
}

export interface CreateWebhookRequest {
  url: string;
  secret: string;
  description?: string;
}

/** Full secret returned once at creation. Store it now — it cannot be retrieved later. */
export interface CreateWebhookResponse {
  id: string;
  url: string;
  secret: string;
  description: string | null;
  active: boolean;
  created_at: string;
}

export interface UpdateWebhookRequest {
  url?: string;
  secret?: string;
  description?: string;
  active?: boolean;
}

// ---- API functions -----------------------------------------------------------

export const webhooksApi = {
  list: () =>
    api.get<WebhookEndpoint[]>('/api/v1/webhooks'),

  create: (req: CreateWebhookRequest) =>
    api.post<CreateWebhookResponse>('/api/v1/webhooks', req),

  update: (webhookId: string, req: UpdateWebhookRequest) =>
    api.put<WebhookEndpoint>(`/api/v1/webhooks/${encodeURIComponent(webhookId)}`, req),

  delete: (webhookId: string) =>
    api.delete(`/api/v1/webhooks/${encodeURIComponent(webhookId)}`),

  test: (webhookId: string) =>
    api.post(`/api/v1/webhooks/${encodeURIComponent(webhookId)}/test`, {}),
};
