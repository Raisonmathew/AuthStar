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
