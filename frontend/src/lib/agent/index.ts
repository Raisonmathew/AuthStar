/**
 * AuthStar Agent SDK — TypeScript helpers for AI agent authorization.
 *
 * ## Usage (Anthropic Claude / OpenAI / any LLM tool loop)
 *
 * ```typescript
 * import { AgentClient } from '@authstar/agent';
 *
 * const agent = new AgentClient({
 *   agentId: 'agt_abc123',
 *   taskId:  crypto.randomUUID(),
 *   token:   agentJwt,          // token issued by POST /api/v1/agents/token
 * });
 *
 * // Before calling any tool:
 * const granted = await agent.authorizeToolCall('send_email');
 * if (!granted) throw new Error('Tool call denied by EIAA capsule');
 *
 * // After the task finishes:
 * const chain = await agent.getTaskChain();
 * ```
 *
 * @module
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/** Options passed to the AgentClient constructor. */
export interface AgentClientOptions {
  /** Stable agent ID (`agent_id` claim from the agent JWT). */
  agentId: string;
  /**
   * Task identifier grouping all tool calls in this run.
   * Use `crypto.randomUUID()` or any stable, unique string per task.
   */
  taskId: string;
  /**
   * Short-lived agent JWT issued by `POST /api/v1/agents/token`.
   * Do NOT use a long-lived human session JWT here.
   */
  token: string;
  /**
   * Base URL of the AuthStar API server.
   * Defaults to `window.location.origin` when running in a browser.
   */
  apiBaseUrl?: string;
}

/** Response from `POST /api/v1/agents/:agent_id/authorize`. */
export interface ToolAuthorizeResponse {
  /** Whether the EIAA capsule granted authorization. */
  allowed: boolean;
  /** Human-readable denial reason when `allowed = false`. */
  reason?: string;
  /** EIAA attestation reference for this decision. */
  decision_ref?: string;
  attestation_ref?: string;
}

/** A single EIAA execution row from the task chain. */
export interface TaskChainItem {
  id: string;
  decisionRef: string;
  action: string;
  capsuleHashB64: string;
  decision: { allow: boolean; reason?: string };
  attestationTimestamp: string;
  createdAt: string;
  taskId?: string;
  parentActionId?: string;
  delegationDepth: number;
  principalType: string;
  agentId?: string;
  modelId?: string;
  toolName?: string;
  toolArgsHash?: string;
}

/** Response from task chain and agent history endpoints. */
export interface ChainResponse {
  items: TaskChainItem[];
  /** ISO-8601 cursor for the next page, or `null` if this is the last page. */
  nextCursor: string | null;
}

/** Request body for tool-call pre-authorization. */
export interface AuthorizeToolCallRequest {
  toolName: string;
  /** Optional SHA-256 (hex) of the serialised tool arguments for audit. */
  toolArgsHash?: string;
  /** Optional resource pattern being accessed (e.g. `"email:*@company.com"`). */
  resourcePattern?: string;
}

/** Request body for recording a completed tool execution. */
export interface RecordExecutionRequest {
  toolName: string;
  /** Whether the tool call was authorized (true) or denied (false). */
  allowed: boolean;
  /** Hex SHA-256 of the serialised tool arguments (optional). */
  toolArgsHash?: string;
  /** Denial reason if `allowed = false`. */
  denialReason?: string;
  /** The `decision_ref` from the preceding `/authorize` call — stored for audit linkage. */
  eiaaExecutionId?: string;
}

/** Response from `POST /api/v1/agents/:agent_id/executions`. */
export interface RecordExecutionResponse {
  execution_id: string;
  tool_name: string;
  task_id: string;
  recorded_at: string;
}

/**
 * Thrown when an EIAA capsule denies a tool-call authorization and
 * `authorizeToolCall` is called with `{ raiseOnDeny: true }`.
 */
export class AgentAuthzDenied extends Error {
  readonly reason: string | undefined;
  readonly attestation: string | undefined;
  readonly decisionRef: string | undefined;

  constructor(opts: {
    reason?: string;
    attestation?: string;
    decisionRef?: string;
  }) {
    super(opts.reason ?? 'Agent tool call denied by EIAA capsule');
    this.name = 'AgentAuthzDenied';
    this.reason = opts.reason;
    this.attestation = opts.attestation;
    this.decisionRef = opts.decisionRef;
  }
}

// ─── AgentClient ─────────────────────────────────────────────────────────────

/**
 * Stateful client for an AI agent task.
 *
 * Each `AgentClient` is bound to a specific `(agentId, taskId)` pair.
 * Instantiate one per task, not once for the lifetime of the agent.
 */
export class AgentClient {
  private readonly agentId: string;
  private readonly taskId: string;
  private readonly token: string;
  private readonly apiBaseUrl: string;

  constructor(opts: AgentClientOptions) {
    this.agentId = opts.agentId;
    this.taskId = opts.taskId;
    this.token = opts.token;
    this.apiBaseUrl =
      opts.apiBaseUrl?.replace(/\/$/, '') ??
      (typeof window !== 'undefined' ? window.location.origin : '');
  }

  // ── Authorization ──────────────────────────────────────────────────────────

  /**
   * Authorize a tool call against the EIAA capsule BEFORE executing the tool.
   *
   * Sends `POST /api/v1/agents/tool-authorize` and returns whether the call
   * is permitted.  Always fail-closed: if the network request fails, this
   * method throws rather than silently allowing the call.
   *
   * @param toolName   EIAA action string for the tool (e.g. `"send_email"`).
   * @param opts       Optional additional context for the authorization decision.
   */
  async authorizeToolCall(
    toolName: string,
    opts?: Pick<AuthorizeToolCallRequest, 'toolArgsHash' | 'resourcePattern'> & {
      /** When true, throws `AgentAuthzDenied` instead of returning `false`. */
      raiseOnDeny?: boolean;
    },
  ): Promise<boolean> {
    const body: AuthorizeToolCallRequest = {
      toolName,
      toolArgsHash: opts?.toolArgsHash,
      resourcePattern: opts?.resourcePattern,
    };

    // HIGH-1 FIX: Use the correct endpoint URL with agentId path segment.
    // Was: '/api/v1/agents/tool-authorize' (404 — no such route).
    // Now: '/api/v1/agents/:agent_id/authorize' (matches router.rs).
    const resp = await this.post<ToolAuthorizeResponse>(
      `/api/v1/agents/${encodeURIComponent(this.agentId)}/authorize`,
      body,
      { 'X-Tool-Name': toolName, ...(opts?.toolArgsHash ? { 'X-Tool-Args-Hash': opts.toolArgsHash } : {}) },
    );

    if (!resp.allowed) {
      if (opts?.raiseOnDeny) {
        throw new AgentAuthzDenied({
          reason: resp.reason,
          attestation: resp.attestation_ref,
          decisionRef: resp.decision_ref,
        });
      }
      console.warn(
        `[AuthStar] Tool call denied: toolName=${toolName} reason=${resp.reason ?? 'unknown'}`,
      );
    }

    return resp.allowed;
  }

  /**
   * Record the completion of a tool execution after receiving an authorization decision.
   *
   * Sends `POST /api/v1/agents/:agent_id/executions`. Call this after every tool
   * invocation — whether allowed or denied — so the audit trail is complete.
   *
   * @param toolName        Name of the tool that was (or was not) invoked.
   * @param allowed         Whether the tool call was authorized.
   * @param opts            Optional audit fields.
   */
  async recordExecution(
    toolName: string,
    allowed: boolean,
    opts?: Pick<RecordExecutionRequest, 'toolArgsHash' | 'denialReason' | 'eiaaExecutionId'>,
  ): Promise<RecordExecutionResponse> {
    return this.post<RecordExecutionResponse>(
      `/api/v1/agents/${encodeURIComponent(this.agentId)}/executions`,
      {
        tool_name: toolName,
        task_id: this.taskId,
        allowed,
        tool_args_hash: opts?.toolArgsHash,
        denial_reason: opts?.denialReason,
        eiaa_execution_id: opts?.eiaaExecutionId,
      },
    );
  }

  // ── Audit / chain queries ──────────────────────────────────────────────────

  /**
   * Fetch the full causal chain for this task (all tool calls in order).
   *
   * Wraps `GET /api/v1/audit/task/:taskId` with automatic cursor pagination:
   * pass `cursor` from a previous response's `nextCursor` to page through long chains.
   */
  async getTaskChain(cursor?: string): Promise<ChainResponse> {
    const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    const raw = await this.get<{ items: TaskChainItem[]; nextCursor?: string | null; next_cursor?: string | null }>(
      `/api/v1/audit/task/${encodeURIComponent(this.taskId)}${qs}`
    );
    // Normalise snake_case → camelCase from the backend response.
    return {
      items: raw.items ?? [],
      nextCursor: raw.nextCursor ?? raw.next_cursor ?? null,
    };
  }

  /**
   * Fetch all EIAA executions ever produced by this agent across all tasks.
   *
   * Wraps `GET /api/v1/audit/agent/:agentId` with cursor pagination.
   */
  async getAgentHistory(cursor?: string): Promise<ChainResponse> {
    const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    const raw = await this.get<{ items: TaskChainItem[]; nextCursor?: string | null; next_cursor?: string | null }>(
      `/api/v1/audit/agent/${encodeURIComponent(this.agentId)}${qs}`
    );
    return {
      items: raw.items ?? [],
      nextCursor: raw.nextCursor ?? raw.next_cursor ?? null,
    };
  }

  // ── Static factory helpers ─────────────────────────────────────────────────

  /**
   * Mint a new agent token for a task by calling `POST /api/v1/agents/token`.
   *
   * This is a **human session** call — the `humanToken` must be an admin or
   * service JWT, NOT an existing agent token.
   *
   * Returns a fully configured `AgentClient` for the issued token.
   */
  static async mintToken(
    humanToken: string,
    params: {
      agentId: string;
      taskId: string;
      delegationChain?: string[];
      allowedTools?: string[];
      apiBaseUrl?: string;
    },
  ): Promise<AgentClient> {
    const baseUrl = params.apiBaseUrl?.replace(/\/$/, '') ?? '';
    const resp = await fetch(`${baseUrl}/api/v1/agents/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${humanToken}`,
      },
      body: JSON.stringify({
        agent_id: params.agentId,
        task_id: params.taskId,
        delegation_chain: params.delegationChain ?? [],
        allowed_tools: params.allowedTools,
      }),
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(`AgentClient.mintToken failed: ${resp.status} ${text}`);
    }

    const data = (await resp.json()) as { token: string; agent_id: string; task_id: string };
    return new AgentClient({
      agentId: data.agent_id,
      taskId: data.task_id,
      token: data.token,
      apiBaseUrl: params.apiBaseUrl,
    });
  }

  // ── Private HTTP helpers ───────────────────────────────────────────────────

  private authHeaders(extra?: Record<string, string>): Record<string, string> {
    const orgId =
      typeof sessionStorage !== 'undefined' ? (sessionStorage.getItem('active_org_id') ?? '') : '';
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${this.token}`,
      ...(orgId ? { 'X-Organization-Id': orgId } : {}),
      ...extra,
    };
  }

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.apiBaseUrl}${path}`, {
      method: 'GET',
      headers: this.authHeaders(),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(`AgentClient GET ${path} failed: ${resp.status} ${text}`);
    }
    return resp.json() as Promise<T>;
  }

  private async post<T>(
    path: string,
    body: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const resp = await fetch(`${this.apiBaseUrl}${path}`, {
      method: 'POST',
      headers: this.authHeaders(extraHeaders),
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(`AgentClient POST ${path} failed: ${resp.status} ${text}`);
    }
    return resp.json() as Promise<T>;
  }
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

/**
 * Compute SHA-256 (hex) of a JSON-serialisable value using the Web Crypto API.
 *
 * Use this to produce the `toolArgsHash` parameter for `authorizeToolCall`:
 *
 * ```typescript
 * const hash = await hashToolArgs({ to: 'user@example.com', subject: 'Hello' });
 * await agent.authorizeToolCall('send_email', { toolArgsHash: hash });
 * ```
 */
export async function hashToolArgs(args: unknown): Promise<string> {
  const json = JSON.stringify(args);
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
