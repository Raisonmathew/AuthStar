use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub profile_image_url: Option<String>,
    pub banned: bool,
    pub locked: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub public_metadata: serde_json::Value,
    pub private_metadata: serde_json::Value,
    pub unsafe_metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "type")]
    #[sqlx(rename = "type")]
    pub identity_type: String,
    pub identifier: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub oauth_provider: Option<String>,
    pub oauth_subject: Option<String>,
    pub oauth_access_token: Option<String>,
    pub oauth_refresh_token: Option<String>,
    pub oauth_token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Password {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub password_hash: String,
    pub algorithm: String,
    pub previous_hashes: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SignupTicket {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password_hash: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub verification_code: Option<String>,
    pub verification_code_expires_at: Option<DateTime<Utc>>,
    pub verification_attempts: i32,
    /// MEDIUM-EIAA-9: EIAA execution decision_ref that authorized this signup.
    /// Populated by `create_signup_ticket` when the signup capsule has been executed
    /// and the decision_ref is available. Links the signup ticket to the
    /// `eiaa_executions` row for audit and re-execution verification.
    pub decision_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VerificationToken {
    pub id: String,
    pub identity_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub code: Option<String>,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUpResponse {
    pub ticket_id: String,
    pub status: String,
    pub requires_verification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub ticket_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInRequest {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInResponse {
    pub user: User,
    pub session_id: String,
    pub jwt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub profile_image_url: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub mfa_enabled: bool,
    pub public_metadata: serde_json::Value,
}
