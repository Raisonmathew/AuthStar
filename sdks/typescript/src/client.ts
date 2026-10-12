import { AuthstarError } from "./errors.js";
import type {
  AuthzDecision,
  ClientOptions,
  HealthStatus,
  TaskChainPage,
  VerificationResult,
} from "./models.js";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Build common headers from client options. */
function buildHeaders(
  apiKey: string,
  tenantId: string | undefined
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    Authorization: `Bearer ${apiKey}`,
    ...(tenantId ? { "X-Tenant-Id": tenantId } : {}),
  };
}

/** Parse an error response and throw `AuthstarError`. */
async function throwForStatus(response: Response): Promise<never> {
  let code = "api_error";
  let message = `HTTP ${response.status}`;
  try {
    const body = (await response.json()) as {
      code?: string;
      message?: string;
      detail?: string;
    };
    code = body.code ?? code;
    message = body.message ?? body.detail ?? message;
  } catch {
    // ignore JSON parse failures; keep the default message
  }
  throw new AuthstarError(message, response.status, code);
}

// ---------------------------------------------------------------------------
// AuthstarClient — async, fetch-based (works in Node ≥18, Deno, browsers,
//                  Cloudflare Workers, Bun)
// ---------------------------------------------------------------------------

/**
 * Primary AuthStar SDK client.
 *
 * All methods are `async` and use the global `fetch` API (available natively
 * in Node ≥18, browsers, Deno, Bun, and Cloudflare Workers). No external
 * dependencies are required.
 *
 * @example
 * ```ts
 * import { AuthstarClient } from "@authstar/sdk";
 *
 * const client = new AuthstarClient({
 *   baseUrl: "https://api.authstar.io",
 *   apiKey: "ask_abc123",
 *   tenantId: "your-tenant-uuid",
 * });
 *
 * const decision = await client.authorize("billing:read", "user_abc");
 * console.log(decision.allowed);
 * ```
 */
export class AuthstarClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly tenantId: string | undefined;
  private readonly timeout: number;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.tenantId = options.tenantId;
    this.timeout = options.timeout ?? 10_000;
  }

  // ─── Public API ──────────────────────────────────────────────────────────

  /**
   * Request an authorization decision for a subject performing an action.
   *
   * @param action   EIAA action string, e.g. `"billing:read"`.
   * @param subject  The principal's identifier (user UUID, agent_id, etc.).
   * @param context  Optional key/value pairs forwarded to the policy capsule
   *                 (e.g. `{ task_id: "...", resource: "..." }`).
   *
   * @example
   * ```ts
   * const { allowed, decision_ref } = await client.authorize(
   *   "billing:read",
   *   "user_abc",
   *   { resource: "invoice_123" }
   * );
   * ```
   */
  async authorize(
    action: string,
    subject: string,
    context?: Record<string, unknown>
  ): Promise<AuthzDecision> {
    const data = await this._post<{
      allowed: boolean;
      decision_ref: string;
      attestation_ref?: string;
      attestation_sig?: string;
      reason?: string | null;
    }>("/api/v1/decisions", {
      action,
      subject_id: subject,
      context: context ?? {},
    });
    return {
      allowed: Boolean(data.allowed),
      decision_ref: data.decision_ref ?? "",
      attestation_sig: data.attestation_ref ?? data.attestation_sig ?? null,
      reason: data.reason ?? null,
    };
  }

  /**
   * Immediately revoke all active tokens for an agent.
   *
   * Writes a Redis blocklist entry server-side so subsequent requests
   * bearing the agent's JWT are denied within 100 ms.
   */
  async revoke(agentId: string): Promise<void> {
    await this._request(
      `/api/v1/agents/${encodeURIComponent(agentId)}/revoke`,
      { method: "POST" }
    );
  }

  /**
   * Retrieve a paginated page of EIAA execution records for a task.
   * Records are ordered oldest-first.
   *
   * @param taskId  The task identifier embedded in the agent JWT.
   * @param opts    Pagination options (`cursor`, `limit`).
   */
  async getTaskChain(
    taskId: string,
    opts?: { cursor?: string; limit?: number }
  ): Promise<TaskChainPage> {
    const params = new URLSearchParams();
    if (opts?.cursor) params.set("cursor", opts.cursor);
    if (opts?.limit !== undefined) params.set("limit", String(opts.limit));
    const qs = params.size > 0 ? `?${params.toString()}` : "";
    return this._get<TaskChainPage>(
      `/api/v1/audit/task/${encodeURIComponent(taskId)}${qs}`
    );
  }

  /**
   * Re-execute a past authorization decision and verify its attestation.
   *
   * @param decisionRef  The opaque reference returned by `authorize()`.
   */
  async verifyDecision(decisionRef: string): Promise<VerificationResult> {
    return this._get<VerificationResult>(
      `/api/v1/audit/reexecution/verify/${encodeURIComponent(decisionRef)}`
    );
  }

  /**
   * Check API liveness and measure round-trip latency.
   */
  async health(): Promise<HealthStatus> {
    const start = Date.now();
    const resp = await this._request("/health");
    const latency_ms = Date.now() - start;
    let version: string | undefined;
    try {
      const body = (await resp.json()) as { version?: string };
      version = body.version;
    } catch {
      // ignore
    }
    return { ok: true, latency_ms, version };
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private async _get<T>(path: string): Promise<T> {
    const resp = await this._request(path, { method: "GET" });
    return resp.json() as Promise<T>;
  }

  private async _post<T>(path: string, body: unknown): Promise<T> {
    const resp = await this._request(path, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (resp.status === 204) return undefined as unknown as T;
    return resp.json() as Promise<T>;
  }

  private async _request(
    path: string,
    init: RequestInit = {}
  ): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers = buildHeaders(this.apiKey, this.tenantId);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        ...init,
        headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
        signal: controller.signal,
      });
    } catch (err) {
      throw new AuthstarError(
        err instanceof Error ? err.message : "Network error",
        0,
        "network_error"
      );
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      await throwForStatus(response);
    }

    return response;
  }
}
