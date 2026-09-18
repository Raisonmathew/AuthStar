import axios, { type AxiosInstance } from 'axios';
import {
  AgentAuthzConfig,
  AgentDecision,
  AgentExecution,
  AgentChainResponse,
  RegisterAgentRequest,
  RegisterAgentResponse,
  AgentPrincipal,
  AgentAuthzDenied,
} from './types.js';

/**
 * AuthStar AI Agent Authorization client for Node.js.
 *
 * Drop-in client for LangChain.js, Vercel AI SDK, OpenAI Agents SDK, and any
 * other Node.js-based LLM runtime. Wraps the EIAA-backed agent authorization
 * endpoints with automatic token lifecycle management.
 *
 * ## Quick start
 *
 * ```ts
 * import { AgentAuthzClient } from '@idaas/agent';
 *
 * const client = new AgentAuthzClient({
 *   baseUrl: 'https://api.authstar.com',
 *   tenantId: 'acme',
 *   apiKey: 'sk_live_...',
 *   agentId: 'agt_abc123',
 *   taskId: 'task_xyz789',
 * });
 *
 * // Before invoking any tool:
 * const decision = await client.authorizeToolCall('send_email', { to: 'user@example.com' });
 * if (!decision.allowed) throw new AgentAuthzDenied(decision);
 *
 * const result = await sendEmail(...);
 * await client.recordExecution('send_email', { allowed: true });
 * ```
 *
 * ## Lifecycle management (admin operations)
 *
 * The same client handles agent registration and revocation so orchestration
 * pipelines (Prefect, Airflow) have a single dependency.
 *
 * ```ts
 * const reg = await client.registerAgent({ name: 'My Agent', allowed_tools: 'search email' });
 * const agents = await client.listAgents();
 * await client.revokeAgentTokens('agt_abc123');
 * ```
 */
export class AgentAuthzClient {
  private readonly http: AxiosInstance;
  private readonly config: {
    baseUrl: string;
    tenantId: string;
    apiKey: string;
    agentId: string;
    taskId: string;
    agentToken: string | undefined;
    tokenTtlSeconds: number;
    timeoutMs: number;
  };
  private _token?: string;
  private _tokenExpiresAt = 0; // monotonic ms

  constructor(config: AgentAuthzConfig) {
    this.config = {
      baseUrl: config.baseUrl.replace(/\/$/, ''),
      tenantId: config.tenantId,
      apiKey: config.apiKey,
      agentId: config.agentId,
      taskId: config.taskId,
      agentToken: config.agentToken,
      tokenTtlSeconds: config.tokenTtlSeconds ?? 3600,
      timeoutMs: config.timeoutMs ?? 10_000,
    };

    // Pre-seed from a caller-supplied token; treat it as expiring in tokenTtlSeconds.
    if (config.agentToken) {
      this._token = config.agentToken;
      this._tokenExpiresAt = Date.now() + this.config.tokenTtlSeconds * 1000;
    }

    this.http = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeoutMs,
      headers: { 'X-API-Key': this.config.apiKey },
    });
  }

  // ─── Tool-call authorization ────────────────────────────────────────────────

  /**
   * Authorize a tool call through the EIAA capsule.
   *
   * Sends a SHA-256 hash of the serialised args — raw argument values never
   * leave the caller's process.
   *
   * POST /api/v1/agents/:agentId/authorize
   *
   * @param toolName   Name of the tool about to be invoked.
   * @param args       Tool arguments. SHA-256 hashed before sending.
   * @param raiseOnDeny  When true, throws {@link AgentAuthzDenied} on denial.
   */
  async authorizeToolCall(
    toolName: string,
    args: Record<string, unknown> = {},
    { raiseOnDeny = false }: { raiseOnDeny?: boolean } = {},
  ): Promise<AgentDecision> {
    const token = await this._ensureToken();
    const argsHash = await AgentAuthzClient.hashToolArgs(args);

    const { data } = await this.http.post<AgentDecision>(
      `/api/v1/agents/${this.config.agentId}/authorize`,
      {
        tool_name: toolName,
        tool_args_hash: argsHash,
        task_id: this.config.taskId,
      },
      { headers: { Authorization: `Bearer ${token}` } },
    );

    if (raiseOnDeny && !data.allowed) {
      throw new AgentAuthzDenied(data);
    }
    return data;
  }

  /**
   * Record the completion of a tool execution in the audit trail.
   *
   * POST /api/v1/agents/:agentId/executions
   */
  async recordExecution(
    toolName: string,
    opts: {
      allowed: boolean;
      toolArgsHash?: string;
      denialReason?: string;
      decisionRef?: string;
      eiaaExecutionId?: string;
    },
  ): Promise<AgentExecution> {
    const token = await this._ensureToken();
    const { data } = await this.http.post<AgentExecution>(
      `/api/v1/agents/${this.config.agentId}/executions`,
      {
        tool_name: toolName,
        task_id: this.config.taskId,
        allowed: opts.allowed,
        tool_args_hash: opts.toolArgsHash,
        denial_reason: opts.denialReason,
        eiaa_execution_id: opts.eiaaExecutionId ?? opts.decisionRef,
      },
      { headers: { Authorization: `Bearer ${token}` } },
    );
    return data;
  }

  // ─── Audit chain queries (G-1 parity) ──────────────────────────────────────

  /**
   * Fetch the full causal audit chain for a task, cursor-paginated.
   *
   * GET /api/v1/audit/task/:taskId
   *
   * @param taskId   Task to query (defaults to `this.config.taskId`).
   * @param cursor   Opaque pagination cursor from a previous response.
   */
  async getTaskChain(
    taskId?: string,
    cursor?: string,
  ): Promise<AgentChainResponse> {
    const token = await this._ensureToken();
    const tid = taskId ?? this.config.taskId;
    const params = cursor ? { cursor } : undefined;
    const { data } = await this.http.get<AgentChainResponse>(
      `/api/v1/audit/task/${tid}`,
      { params, headers: { Authorization: `Bearer ${token}` } },
    );
    return data;
  }

  /**
   * Fetch all EIAA executions for an agent across all tasks, cursor-paginated.
   *
   * GET /api/v1/audit/agent/:agentId
   *
   * @param agentId  Agent to query (defaults to `this.config.agentId`).
   * @param cursor   Opaque pagination cursor from a previous response.
   */
  async getAgentHistory(
    agentId?: string,
    cursor?: string,
  ): Promise<AgentChainResponse> {
    const token = await this._ensureToken();
    const aid = agentId ?? this.config.agentId;
    const params = cursor ? { cursor } : undefined;
    const { data } = await this.http.get<AgentChainResponse>(
      `/api/v1/audit/agent/${aid}`,
      { params, headers: { Authorization: `Bearer ${token}` } },
    );
    return data;
  }

  // ─── Agent lifecycle management (G-2 parity) ───────────────────────────────

  /**
   * Register or update a pre-registered agent principal.
   * Requires an admin or service session — set a service-account JWT on
   * the client via `setAdminToken()` before calling.
   *
   * POST /api/v1/agents/register
   */
  async registerAgent(req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    const { data } = await this.http.post<RegisterAgentResponse>(
      '/api/v1/agents/register',
      req,
    );
    return data;
  }

  /**
   * List all active agent principals for the tenant.
   *
   * GET /api/v1/agents
   */
  async listAgents(): Promise<AgentPrincipal[]> {
    const { data } = await this.http.get<AgentPrincipal[]>('/api/v1/agents');
    return data;
  }

  /**
   * Retrieve a single agent principal by ID.
   *
   * GET /api/v1/agents/:agentId
   */
  async getAgent(agentId: string): Promise<AgentPrincipal> {
    const { data } = await this.http.get<AgentPrincipal>(
      `/api/v1/agents/${agentId}`,
    );
    return data;
  }

  /**
   * Soft-deactivate an agent principal (sets active=false).
   *
   * DELETE /api/v1/agents/:agentId
   */
  async deactivateAgent(agentId: string): Promise<void> {
    await this.http.delete(`/api/v1/agents/${agentId}`);
  }

  /**
   * Immediately invalidate all active tokens for an agent by writing a Redis
   * blocklist key.
   *
   * POST /api/v1/agents/:agentId/revoke
   */
  async revokeAgentTokens(agentId: string): Promise<void> {
    await this.http.post(`/api/v1/agents/${agentId}/revoke`);
  }

  // ─── Token management ───────────────────────────────────────────────────────

  /**
   * Override the Authorization header for admin operations (register, list,
   * deactivate, revoke). Pass a human admin or service JWT here.
   */
  setAdminToken(jwt: string): void {
    this.http.defaults.headers.common['Authorization'] = `Bearer ${jwt}`;
  }

  /**
   * G-6 fix: Return a valid agent JWT, proactively re-minting 60 s before
   * expiry. Eliminates the "cache-forever" bug where a long-running agent
   * session would receive a stale token and every subsequent call would fail
   * with HTTP 401.
   */
  private async _ensureToken(): Promise<string> {
    const REFRESH_MARGIN_MS = 60_000;
    if (this._token && Date.now() < this._tokenExpiresAt - REFRESH_MARGIN_MS) {
      return this._token;
    }

    const { data } = await this.http.post<{
      token: string;
      expires_in?: number;
    }>('/api/v1/agents/token', {
      agent_id: this.config.agentId,
      task_id: this.config.taskId,
      ttl_seconds: this.config.tokenTtlSeconds,
    });

    this._token = data.token;
    const expiresIn = data.expires_in ?? this.config.tokenTtlSeconds;
    this._tokenExpiresAt = Date.now() + expiresIn * 1000;
    return this._token;
  }

  // ─── Utilities ──────────────────────────────────────────────────────────────

  /**
   * Return a hex SHA-256 hash of the canonical JSON serialisation of `args`.
   * Pass the result as `toolArgsHash` so raw argument values never leave the
   * caller's process.
   *
   * Uses `crypto.subtle` (available in Node.js ≥ 15 and all modern browsers).
   */
  static async hashToolArgs(args: Record<string, unknown>): Promise<string> {
    const sorted = Object.keys(args)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => { acc[k] = args[k]; return acc; }, {});
    const canonical = JSON.stringify(sorted);
    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
}
