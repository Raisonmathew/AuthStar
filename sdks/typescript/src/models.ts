// ─── Public API models ─────────────────────────────────────────────────────

export interface ClientOptions {
  /** Root URL of the AuthStar backend, e.g. `"https://api.authstar.io"`. */
  baseUrl: string;
  /** AuthStar API key (`ask_...`). */
  apiKey: string;
  /** Tenant / organisation UUID. Sent as `X-Tenant-Id` on every request. */
  tenantId?: string;
  /** Per-request timeout in milliseconds. Default: `10_000`. */
  timeout?: number;
}

/** Authorization decision returned by `authorize()`. */
export interface AuthzDecision {
  /** Whether the action is permitted. */
  allowed: boolean;
  /** Opaque reference for audit queries and `verifyDecision()`. */
  decision_ref: string;
  /** Base64url-encoded Ed25519 attestation signature (may be empty in dev). */
  attestation_sig: string | null;
  /** Human-readable denial reason. `null` when `allowed = true`. */
  reason: string | null;
}

/** A single item in an agent task's audit chain. */
export interface TaskChainItem {
  id: string;
  action: string;
  allowed: boolean;
  agent_id: string | null;
  tool_name: string | null;
  created_at: string;
  attestation_signature_b64: string | null;
}

/** A paginated page of task chain items. */
export interface TaskChainPage {
  items: TaskChainItem[];
  /** ISO-8601 cursor for the next page. `null` when exhausted. */
  next_cursor: string | null;
}

/** Result of re-executing a past authorization decision for verification. */
export interface VerificationResult {
  decision_ref: string;
  original_decision: boolean;
  replayed_decision: boolean;
  decisions_match: boolean;
  verification_status:
    | "verified"
    | "discrepancy"
    | "capsule_not_found"
    | "execution_error";
  discrepancy_reason: string | null;
}

/** Result of the `health()` probe. */
export interface HealthStatus {
  ok: boolean;
  latency_ms: number;
  version?: string;
}
