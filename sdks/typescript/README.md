# @authstar/sdk

TypeScript SDK for [AuthStar](https://github.com/your-org/AuthStar) — AI agent authorization, audit, and verification.

## Requirements

- Node.js ≥ 18 (uses native `fetch`)
- TypeScript ≥ 5 (optional, types included)

## Installation

```bash
npm install @authstar/sdk
```

## Quick start

```typescript
import { AuthstarClient } from "@authstar/sdk";

const client = new AuthstarClient({
  baseUrl: "https://your-authstar-instance.example.com",
  apiKey: "sk-...",
  tenantId: "acme",   // optional
  timeout: 5_000,     // ms, default 10 000
});

// Request an authorization decision
const decision = await client.authorize("read:documents", {
  resource_id: "doc-42",
  user_id: "user-7",
});

if (!decision.allowed) {
  throw new Error(`Denied: ${decision.reason}`);
}
console.log("Decision ref:", decision.decision_ref);
```

## API

### `new AuthstarClient(options: ClientOptions)`

| Option | Type | Required | Description |
|---|---|---|---|
| `baseUrl` | `string` | ✅ | Root URL of your AuthStar instance |
| `apiKey` | `string` | ✅ | API key (`Bearer` token) |
| `tenantId` | `string` | | Forwarded as `X-Tenant-Id` header |
| `timeout` | `number` | | Request timeout in ms (default `10000`) |

### `client.authorize(action, context?)`

Request an authorization decision.

```typescript
const decision: AuthzDecision = await client.authorize("write:secrets", {
  environment: "production",
});
// { allowed, decision_ref, attestation_sig, reason }
```

### `client.revoke(agentId)`

Revoke all active sessions/tokens for an agent.

```typescript
await client.revoke("agent-abc123");
```

### `client.getTaskChain(taskId, opts?)`

Retrieve the paginated audit task chain.

```typescript
let page = await client.getTaskChain("task-xyz");
while (page.next_cursor) {
  page = await client.getTaskChain("task-xyz", { cursor: page.next_cursor });
}
```

### `client.verifyDecision(decisionRef)`

Re-execute a past decision and compare results (tamper detection).

```typescript
const result: VerificationResult = await client.verifyDecision(decision.decision_ref);
if (result.verification_status === "discrepancy") {
  console.warn("Policy drift detected:", result.discrepancy_reason);
}
```

### `client.health()`

Ping the API and measure round-trip latency.

```typescript
const { ok, latency_ms } = await client.health();
```

## Error handling

All non-2xx responses throw an `AuthstarError`:

```typescript
import { AuthstarError } from "@authstar/sdk";

try {
  await client.authorize("delete:everything");
} catch (err) {
  if (err instanceof AuthstarError) {
    console.error(err.status); // HTTP status code
    console.error(err.code);   // machine-readable error code
    console.error(err.message);
  }
}
```

## Framework integrations

### LangChain

```typescript
import { AuthstarAuthzTool } from "./examples/langchain.js";

const tool = new AuthstarAuthzTool(client);
// Pass to createToolCallingAgent({ llm, tools: [tool], prompt })
```

See [`examples/langchain.ts`](examples/langchain.ts).

### OpenAI Agents SDK

```typescript
import { authorizeTool, handleAuthorizeCall } from "./examples/openai-agents.js";

// Pass authorizeTool to your Responses API call, then:
const output = await handleAuthorizeCall(client, toolCall.arguments);
```

See [`examples/openai-agents.ts`](examples/openai-agents.ts).

## Build

```bash
npm run build      # compile to dist/
npm test           # vitest
npm run typecheck  # tsc --noEmit
```

## License

MIT
