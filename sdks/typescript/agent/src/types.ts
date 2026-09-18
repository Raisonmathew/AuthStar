// ─── Public types ─────────────────────────────────────────────────────────────

export interface AgentAuthzConfig {
  /** Base URL of the AuthStar API (no trailing slash). */
  baseUrl: string;
  /** Tenant slug or ID. */
  tenantId: string;
  /** Service API key used to mint agent tokens. Sent as X-API-Key. */
  apiKey: string;
  /** Registered agent principal ID (agt_…). */
  agentId: string;
  /** Task identifier grouping all tool calls in this session for audit chaining. */
  taskId: string;
  /**
   * Pre-minted agent JWT. When supplied, `apiKey` is not used for token issuance.
   * If omitted, `AgentAuthzClient._ensureToken()` mints one on first use.
   */
  agentToken?: string;
  /**
   * TTL to request when minting a new agent token (seconds, default 3600).
   * The client re-mints 60 s before expiry (G-6 fix).
   */
  tokenTtlSeconds?: number;
  /** HTTP request timeout in milliseconds (default 10 000). */
  timeoutMs?: number;
}

/** Result of an EIAA tool-call authorization check. */
export interface AgentDecision {
  allowed: boolean;
  reason?: string;
  decision_ref: string;
  attestation_ref?: string;
  risk_score?: number;
}

/** Confirmation returned after recording a tool execution. */
export interface AgentExecution {
  execution_id: string;
  tool_name: string;
  task_id: string;
  recorded_at: string;
}

/** A single EIAA execution row from the task audit chain. */
export interface AgentTaskChainItem {
  id: string;
  decision_ref: string;
  action: string;
  capsule_hash_b64: string;
  decision: unknown;
  attestation_signature_b64: string;
  attestation_timestamp: string;
  created_at: string;
  task_id?: string;
  parent_action_id?: string;
  delegation_depth: number;
  principal_type: string;
  agent_id?: string;
  model_id?: string;
  tool_name?: string;
  tool_args_hash?: string;
}

/** Cursor-paginated response from task-chain and agent-history endpoints. */
export interface AgentChainResponse {
  items: AgentTaskChainItem[];
  next_cursor?: string;
}

/** Payload for POST /api/v1/agents/register. */
export interface RegisterAgentRequest {
  name: string;
  model_id?: string;
  /** Space-separated EIAA action strings to restrict this agent to. */
  allowed_tools?: string;
  /** Max delegation chain depth (1–8, default 3). */
  max_delegation_depth?: number;
  /** Token TTL in seconds (60–86400, default 3600). */
  token_ttl_seconds?: number;
  /** CIMD metadata URL (must be https://). */
  cimd_metadata_url?: string;
}

/** Response from POST /api/v1/agents/register. */
export interface RegisterAgentResponse {
  agent_id: string;
  name: string;
  model_id?: string;
  allowed_tools: string;
  max_delegation_depth: number;
  token_ttl_seconds: number;
  principal_source: string;
  created_at: string;
}

/** A registered agent principal record. */
export interface AgentPrincipal {
  id: string;
  agent_id: string;
  name: string;
  model_id?: string;
  allowed_tools: string;
  max_delegation_depth: number;
  token_ttl_seconds: number;
  principal_source: string;
  cimd_metadata_url?: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

/** Thrown when an EIAA capsule denies a tool-call authorization. */
export class AgentAuthzDenied extends Error {
  readonly reason?: string;
  readonly attestation_ref?: string;
  readonly decision_ref: string;

  constructor(decision: AgentDecision) {
    super(decision.reason ?? 'Agent tool call denied by EIAA capsule');
    this.name = 'AgentAuthzDenied';
    this.reason = decision.reason;
    this.attestation_ref = decision.attestation_ref;
    this.decision_ref = decision.decision_ref;
  }
}
