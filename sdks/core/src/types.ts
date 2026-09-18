// ─── SDK Configuration ────────────────────────────────────────────────────────

export interface IDaaSConfig {
    apiUrl: string;
    apiKey?: string;
    /** 'browser' uses httpOnly cookies + CSRF, 'server' uses Bearer tokens */
    mode?: 'browser' | 'server';
    /** Verify EIAA attestations on API responses that include an `attestation` field. Defaults to true. */
    verifyAttestations?: boolean;
    /** Runtime public-key cache TTL in milliseconds. Defaults to 10 minutes. */
    runtimeKeyTtlMs?: number;
    /**
     * If true, allow API responses through when the runtime-key endpoint is
     * unreachable after all retries (instead of throwing). Defaults to false
     * (fail-closed) so that a transient verifier outage does not silently
     * downgrade the EIAA invariant. Enable only for non-security-critical
     * read paths (e.g. dashboards) that prefer availability over proof.
     */
    failOpenOnVerifierUnavailable?: boolean;
    /**
     * Maximum number of attempts (including the first) when fetching runtime
     * keys from `/api/eiaa/v1/runtime/keys`. Defaults to 3.
     */
    runtimeKeyFetchMaxAttempts?: number;
}

// ─── User & Auth ──────────────────────────────────────────────────────────────

export interface User {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    emailVerified: boolean;
    mfaEnabled: boolean;
}

export interface SignUpRequest {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
    /** Any additional custom fields defined by the tenant manifest */
    [key: string]: unknown;
}

export interface SignInRequest {
    identifier: string;
    password: string;
}

// ─── Organization ─────────────────────────────────────────────────────────────

export interface Organization {
    id: string;
    name: string;
    slug: string;
    createdAt: string;
}

// ─── SDK Manifest ─────────────────────────────────────────────────────────────
// These types mirror the Rust structs in sdk_manifest.rs exactly.
// They are SAFE for client-side use — no secrets are ever included.

export interface OAuthDescriptor {
    provider: string;
    label: string;
    enabled: boolean;
}

export interface FieldDescriptor {
    name: string;
    field_type: string;
    label: string;
    required: boolean;
    order: number;
}

export interface BrandingSafeFields {
    logo_url?: string;
    primary_color: string;
    background_color: string;
    text_color: string;
    font_family: string;
}

export interface SignInManifest {
    oauth_providers: OAuthDescriptor[];
    passkey_enabled: boolean;
    email_password_enabled: boolean;
}

export interface SignUpManifest {
    fields: FieldDescriptor[];
}

export interface FlowsManifest {
    sign_in: SignInManifest;
    sign_up: SignUpManifest;
}

export interface SdkManifest {
    org_id: string;
    org_name: string;
    slug: string;
    /** Hash of branding + auth_config — use as ETag for caching */
    version: number;
    branding: BrandingSafeFields;
    flows: FlowsManifest;
}

// ─── Agent Authorization (G-3) ────────────────────────────────────────────────

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

export interface AgentDecision {
    allowed: boolean;
    reason?: string;
    decision_ref: string;
    attestation_ref?: string;
    risk_score?: number;
}

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

export interface AgentChainResponse {
    items: AgentTaskChainItem[];
    next_cursor?: string;
}

export interface AuthorizeToolCallRequest {
    tool_name: string;
    tool_args_hash?: string;
    task_id?: string;
}

export interface RecordExecutionRequest {
    tool_name: string;
    task_id: string;
    allowed: boolean;
    tool_args_hash?: string;
    denial_reason?: string;
    eiaa_execution_id?: string;
}

export interface RecordExecutionResponse {
    execution_id: string;
    tool_name: string;
    task_id: string;
    recorded_at: string;
}
