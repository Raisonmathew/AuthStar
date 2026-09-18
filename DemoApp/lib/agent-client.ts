/**
 * AgentAuthzClient singleton factory.
 *
 * Creates a new @idaas/agent AgentAuthzClient for the given task session.
 * Each task gets its own client instance so task_id and token lifecycle
 * are correctly scoped.
 *
 * Usage in a tool dispatcher:
 *   const client = makeAgentClient(agentId, taskId, adminJwt);
 *   const decision = await client.authorizeToolCall('web_search', { q });
 */
import { AgentAuthzClient } from '@idaas/agent';

const baseUrl = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

export function makeAgentClient(
  agentId: string,
  taskId: string,
  agentToken?: string,
): AgentAuthzClient {
  return new AgentAuthzClient({
    baseUrl,
    tenantId: process.env.AUTHSTAR_TENANT_ID || 'system',
    apiKey: process.env.AUTHSTAR_SERVICE_API_KEY || '',
    agentId,
    taskId,
    agentToken,
    tokenTtlSeconds: 3600,
  });
}
