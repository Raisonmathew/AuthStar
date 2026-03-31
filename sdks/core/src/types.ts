// ─── SDK Configuration ────────────────────────────────────────────────────────

export interface IDaaSConfig {
    apiUrl: string;
    apiKey?: string;
    /** 'browser' uses httpOnly cookies + CSRF, 'server' uses Bearer tokens */
    mode?: 'browser' | 'server';
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
