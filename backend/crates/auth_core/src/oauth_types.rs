//! OAuth 2.0 Authorization Server token types.
//!
//! Separate from [`crate::jwt::Claims`] to preserve the EIAA invariant:
//! internal platform tokens carry identity only (no scopes/permissions).
//! OAuth access tokens carry `scope` as **consent metadata** — the EIAA
//! capsule at the resource server still makes the real allow/deny decision.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// OAuth 2.0 Access Token Claims (issued by AS to third-party clients).
///
/// Extends identity claims with `client_id` and `scope` per RFC 6749.
/// The `scope` field records what the user consented the client to request —
/// it is NOT an authorization grant. EIAA capsules still decide actual access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccessTokenClaims {
    /// Subject (user ID) — empty for client_credentials grant
    pub sub: String,
    /// Issuer (AS URL)
    pub iss: String,
    /// Audience (client_id of the requesting application)
    pub aud: String,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// Session ID (links to sessions table) — empty for client_credentials
    pub sid: String,
    /// Tenant context
    pub tenant_id: String,
    /// Always "oauth_access_token" — distinguishes from internal JWTs
    pub token_type: String,
    /// The OAuth client that requested this token
    pub client_id: String,
    /// Space-separated consent scopes (e.g. "openid profile email")
    pub scope: String,
}

impl OAuthAccessTokenClaims {
    pub const TOKEN_TYPE: &'static str = "oauth_access_token";

    /// Build claims for an authorization_code or refresh_token grant (user-present).
    pub fn for_user(
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        issuer: &str,
        expires_in_secs: i64,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in_secs);
        Self {
            sub: user_id.to_string(),
            iss: issuer.to_string(),
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            sid: session_id.to_string(),
            tenant_id: tenant_id.to_string(),
            token_type: Self::TOKEN_TYPE.to_string(),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
        }
    }

    /// Build claims for a client_credentials grant (no user).
    pub fn for_client(
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        issuer: &str,
        expires_in_secs: i64,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in_secs);
        Self {
            sub: client_id.to_string(), // For M2M, sub = client_id
            iss: issuer.to_string(),
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            sid: String::new(),
            tenant_id: tenant_id.to_string(),
            token_type: Self::TOKEN_TYPE.to_string(),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
        }
    }
}

/// OIDC ID Token Claims (OIDC Core §2).
///
/// Issued alongside the access token when `scope` includes `openid`.
/// Contains identity assertions about the authenticated user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthIdTokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer (AS URL)
    pub iss: String,
    /// Audience (client_id)
    pub aud: String,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Auth time (Unix timestamp) — when the user authenticated
    pub auth_time: i64,
    /// Nonce from the authorization request (replay protection, §15.5.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access token hash (OIDC Core §3.1.3.6) — left half of SHA-256 of access_token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    // ── Profile claims (OIDC Core §5.1) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    // ── Email claims (OIDC Core §5.1) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

impl OAuthIdTokenClaims {
    /// Compute the `at_hash` value per OIDC Core §3.3.2.11.
    /// For ES256 (SHA-256): take the left-most 128 bits of SHA-256(access_token), base64url-encode.
    pub fn compute_at_hash(access_token: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let hash = Sha256::digest(access_token.as_bytes());
        // Left half = first 16 bytes (128 bits) for SHA-256
        URL_SAFE_NO_PAD.encode(&hash[..16])
    }
}

/// Standard OAuth 2.0 token response body (RFC 6749 §5.1, OIDC Core §3.1.3.3).
#[derive(Debug, Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl OAuthTokenResponse {
    pub fn bearer(access_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token: None,
            scope: None,
            id_token: None,
        }
    }
}

/// Standard OAuth 2.0 error response body (RFC 6749 §5.2).
#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// RFC 6749 §5.2 error codes.
pub mod oauth_error_codes {
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const INVALID_CLIENT: &str = "invalid_client";
    pub const INVALID_GRANT: &str = "invalid_grant";
    pub const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
    pub const UNSUPPORTED_GRANT_TYPE: &str = "unsupported_grant_type";
    pub const INVALID_SCOPE: &str = "invalid_scope";
    pub const ACCESS_DENIED: &str = "access_denied";
    pub const SERVER_ERROR: &str = "server_error";
}

/// Token introspection response (RFC 7662).
#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            client_id: None,
            scope: None,
            exp: None,
            iat: None,
            token_type: None,
            tenant_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_claims_contain_scope_and_client_id() {
        let claims = OAuthAccessTokenClaims::for_user(
            "user_123",
            "sess_456",
            "org_789",
            "client_abc",
            "openid profile",
            "https://auth.example.com",
            900,
        );
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"scope\":\"openid profile\""));
        assert!(json.contains("\"client_id\":\"client_abc\""));
        assert!(json.contains("\"token_type\":\"oauth_access_token\""));
        // EIAA: still no roles/permissions/entitlements
        assert!(!json.contains("role"));
        assert!(!json.contains("permission"));
        assert!(!json.contains("entitlement"));
    }

    #[test]
    fn test_client_credentials_claims_sub_is_client_id() {
        let claims = OAuthAccessTokenClaims::for_client(
            "org_789",
            "client_abc",
            "api:read",
            "https://auth.example.com",
            3600,
        );
        assert_eq!(claims.sub, "client_abc");
        assert!(claims.sid.is_empty());
    }

    #[test]
    fn test_oauth_token_response_serialization() {
        let resp = OAuthTokenResponse {
            access_token: "eyJ...".to_string(),
            token_type: "Bearer",
            expires_in: 900,
            refresh_token: Some("rft_abc".to_string()),
            scope: Some("openid profile".to_string()),
            id_token: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"token_type\":\"Bearer\""));
        assert!(json.contains("\"refresh_token\":\"rft_abc\""));
    }

    #[test]
    fn test_introspection_inactive() {
        let resp = IntrospectionResponse::inactive();
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"active":false}"#);
    }
}
