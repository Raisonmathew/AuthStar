use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub slug: String,
    pub logo_url: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub max_allowed_memberships: i32,
    pub public_metadata: serde_json::Value,
    pub private_metadata: serde_json::Value,
    pub branding_config: Option<serde_json::Value>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Membership {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub role: String,
    pub permissions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invitation {
    pub id: String,
    pub organization_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub email_address: String,
    pub role: String,
    pub inviter_user_id: Option<String>,
    pub status: String,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: String,
    pub organization_id: String,
    pub created_at: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub permissions: serde_json::Value,
    pub is_system_role: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Application {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tenant_id: String,
    pub name: String,
    pub r#type: String, // web, mobile, api
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_hash: Option<String>,
    pub redirect_uris: serde_json::Value,
    pub allowed_flows: serde_json::Value,
    pub public_config: serde_json::Value,
    // OAuth 2.0 AS fields (migration 046)
    pub allowed_scopes: serde_json::Value,
    pub is_first_party: bool,
    pub token_lifetime_secs: i32,
    pub refresh_token_lifetime_secs: i32,
}

/// Scopes that the OAuth 2.0 AS actually understands and enforces.
/// Any value outside this list is rejected during app creation/update.
pub const KNOWN_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Default scopes for newly-created applications.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub r#type: String,
    pub redirect_uris: Vec<String>,
    pub allowed_flows: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub public_config: Option<AppPublicConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAppRequest {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub allowed_flows: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub public_config: Option<AppPublicConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppPublicConfig {
    pub enforce_pkce: Option<bool>,
    pub allowed_origins: Option<Vec<String>>,
}
