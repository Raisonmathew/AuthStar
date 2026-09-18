# @idaas/agent

**AuthStar AI Agent Authorization SDK** — EIAA-backed tool-call authorization for Node.js LLM runtimes.

Drop-in client for [LangChain.js](https://github.com/langchain-ai/langchainjs), [Vercel AI SDK](https://sdk.vercel.ai), [OpenAI Agents SDK](https://github.com/openai/openai-agents-python), and any Node.js-based LLM pipeline.

Unlike `@idaas/core` (human authentication), this package is **agent-only**: no browser cookies, no CSRF, no human auth flows — just the six operations an agentic pipeline needs.

---

## Install

```bash
npm install @idaas/agent
# or
pnpm add @idaas/agent
```

---

## Quick start

```ts
import { AgentAuthzClient, AgentAuthzDenied } from '@idaas/agent';

const client = new AgentAuthzClient({
  baseUrl: 'https://api.authstar.com',
  tenantId: 'acme',
  apiKey: 'sk_live_...',     // service API key
  agentId: 'agt_abc123',
  taskId: 'task_xyz789',
});

// 1. Authorize before invoking any tool
const decision = await client.authorizeToolCall('send_email', {
  to: 'user@example.com',
  subject: 'Your flight is booked',
});

if (!decision.allowed) {
  throw new AgentAuthzDenied(decision);
}

// 2. Execute the tool
const result = await sendEmail({ to: 'user@example.com', subject: '...' });

// 3. Record for audit trail
await client.recordExecution('send_email', {
  allowed: true,
  decisionRef: decision.decision_ref,
});
```

---

## API

### `new AgentAuthzClient(config)`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `baseUrl` | `string` | ✅ | AuthStar API base URL |
| `tenantId` | `string` | ✅ | Tenant slug or ID |
| `apiKey` | `string` | ✅ | Service API key (`sk_live_…`) |
| `agentId` | `string` | ✅ | Registered agent ID (`agt_…`) |
| `taskId` | `string` | ✅ | Task ID for audit chaining |
| `agentToken` | `string` | — | Pre-minted agent JWT (skips token issuance) |
| `tokenTtlSeconds` | `number` | — | TTL to request (default `3600`) |
| `timeoutMs` | `number` | — | HTTP timeout (default `10000`) |

### Tool-call authorization

```ts
// Returns AgentDecision. Throws AgentAuthzDenied when raiseOnDeny=true.
const decision = await client.authorizeToolCall(toolName, args, { raiseOnDeny: true });

// Record after execution
await client.recordExecution(toolName, { allowed: true, decisionRef: decision.decision_ref });
```

### Audit chain queries

```ts
// Cursor-paginated task chain
const chain = await client.getTaskChain();                    // uses config.taskId
const next  = await client.getTaskChain(undefined, chain.next_cursor);

// All executions for an agent
const history = await client.getAgentHistory();               // uses config.agentId
```

### Agent lifecycle management

```ts
// Register / update (requires admin JWT — call setAdminToken() first)
client.setAdminToken(adminJwt);
const reg = await client.registerAgent({ name: 'My Agent', allowed_tools: 'search email' });

const agents = await client.listAgents();
const agent  = await client.getAgent('agt_abc123');
await client.deactivateAgent('agt_abc123');
await client.revokeAgentTokens('agt_abc123');   // immediate blocklist, no wait for expiry
```

### Utilities

```ts
// Canonical SHA-256 hash of args (send this, not raw args)
const hash = await AgentAuthzClient.hashToolArgs({ to: 'a@b.com' });
```

---

## Token refresh (automatic)

The client re-mints the agent token **60 seconds before expiry** on every
`authorize_tool_call` call. Long-running agentic sessions (Airflow DAGs,
Prefect flows) are handled without any manual refresh logic.

---

## LangChain.js integration example

```ts
import { tool } from '@langchain/core/tools';
import { AgentAuthzClient } from '@idaas/agent';

const authz = new AgentAuthzClient({ ... });

const sendEmailTool = tool(
  async ({ to, body }) => {
    await authz.authorizeToolCall('send_email', { to, body }, { raiseOnDeny: true });
    return sendEmail(to, body);
  },
  { name: 'send_email', description: 'Send an email' },
);
```
