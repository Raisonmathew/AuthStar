/**
 * Typed API client wrappers for all AI Agent endpoints.
 *
 * Base paths:
 *   Manage/list/get/deactivate/revoke:  POST|GET|PUT|DELETE /api/v1/agents/...
 *   Token issuance:                     POST /api/v1/agents/token
 *   Task chain audit:                   GET  /api/v1/audit/task/:task_id
 *   Agent history:                      GET  /api/v1/audit/agent/:agent_id
 */

import { api } from '../api/client';

// ─── Shared types ─────────────────────────────────────────────────────────────

export interface AgentPrincipal {
  id: string;
  agent_id: string;
  name: string;
  model_id: string | null;
  allowed_tools: string;
  max_delegation_depth: number;
  token_ttl_seconds: number;
  principal_source: string;
  cimd_metadata_url: string | null;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface RegisterAgentRequest {
  name: string;
  model_id?: string;
  allowed_tools?: string;
  max_delegation_depth?: number;
  token_ttl_seconds?: number;
  cimd_metadata_url?: string;
}

export interface RegisterAgentResponse {
  agent_id: string;
  name: string;
  model_id: string | null;
  allowed_tools: string;
  max_delegation_depth: number;
  token_ttl_seconds: number;
  principal_source: string;
  created_at: string;
}

export interface UpdateAgentRequest {
  model_id?: string;
  allowed_tools?: string;
  max_delegation_depth?: number;
  token_ttl_seconds?: number;
}

export interface IssueTokenRequest {
  agent_id: string;
  task_id: string;
  delegation_chain?: string[];
  allowed_tools?: string[];
}

export interface IssueTokenResponse {
  token: string;
  agent_id: string;
  task_id: string;
  expires_in: number;
}

export interface ExecutionRow {
  id: string;
  decision_ref: string;
  action: string;
  capsule_hash_b64: string;
  decision: { allow?: boolean; allowed?: boolean; reason?: string };
  attestation_signature_b64: string;
  attestation_timestamp: string;
  created_at: string;
  task_id: string | null;
  parent_action_id: string | null;
  delegation_depth: number;
  principal_type: string;
  agent_id: string | null;
  model_id: string | null;
  tool_name: string | null;
  tool_args_hash: string | null;
  user_id: string | null;
}

export interface ChainResponse {
  items: ExecutionRow[];
  next_cursor: string | null;
}

// ─── API functions ────────────────────────────────────────────────────────────

export const agentsApi = {
  register: (req: RegisterAgentRequest) =>
    api.post<RegisterAgentResponse>('/api/v1/agents/register', req),

  list: () =>
    api.get<AgentPrincipal[]>('/api/v1/agents'),

  get: (agentId: string) =>
    api.get<AgentPrincipal>(`/api/v1/agents/${encodeURIComponent(agentId)}`),

  update: (agentId: string, req: UpdateAgentRequest) =>
    api.put<AgentPrincipal>(`/api/v1/agents/${encodeURIComponent(agentId)}`, req),

  deactivate: (agentId: string) =>
    api.delete(`/api/v1/agents/${encodeURIComponent(agentId)}`),

  revoke: (agentId: string) =>
    api.post(`/api/v1/agents/${encodeURIComponent(agentId)}/revoke`, {}),

  issueToken: (req: IssueTokenRequest) =>
    api.post<IssueTokenResponse>('/api/v1/agents/token', req),

  getTaskChain: (taskId: string, cursor?: string) =>
    api.get<ChainResponse>(
      `/api/v1/audit/task/${encodeURIComponent(taskId)}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
    ),

  getAgentHistory: (agentId: string, cursor?: string) =>
    api.get<ChainResponse>(
      `/api/v1/audit/agent/${encodeURIComponent(agentId)}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
    ),
};
