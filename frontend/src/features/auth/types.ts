export interface User {
    id: string;
    created_at: string;
    email: string | null;
    first_name: string | null;
    last_name: string | null;
    profile_image_url: string | null;
    organization_id?: string;
    // These fields mirror the backend's `UserResponse` struct (identity_engine::models).
    // They are populated by `to_user_response()` which queries the identities and
    // mfa_factors tables.
    email_verified: boolean;
    phone: string | null;
    phone_verified: boolean;
    mfa_enabled: boolean;
    public_metadata?: Record<string, unknown>;
}

export interface LoginResponse {
    token: string;
    user: User;
}

export interface AuthState {
    user: User | null;
    token: string | null;
    isAuthenticated: boolean;
}
