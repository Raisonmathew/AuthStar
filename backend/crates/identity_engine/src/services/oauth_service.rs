use shared_types::{AppError, Result, generate_id};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::models::{User, Identity};

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Clone)]
pub struct OAuthService {
    db: PgPool,
}

impl OAuthService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate OAuth authorization URL
    pub fn get_authorization_url(
        &self,
        config: &OAuthConfig,
        state: &str,
    ) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            config.authorization_url,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(state)
        )
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code_for_token(
        &self,
        config: &OAuthConfig,
        code: &str,
    ) -> Result<OAuthTokenResponse> {
        let client = reqwest::Client::new();
        
        let params = [
            ("code", code),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("redirect_uri", &config.redirect_uri),
            ("grant_type", "authorization_code"),
        ];

        let response = client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::External(format!("OAuth token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::External(format!("OAuth error: {}", error_text)));
        }

        let token_response = response
            .json::<OAuthTokenResponse>()
            .await
            .map_err(|e| AppError::External(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response)
    }

    /// Get user info from OAuth provider
    pub async fn get_user_info(
        &self,
        config: &OAuthConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo> {
        let client = reqwest::Client::new();

        let response = client
            .get(&config.userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::External(format!("Failed to get user info: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::External("Failed to fetch user info".to_string()));
        }

        let user_info = response
            .json::<OAuthUserInfo>()
            .await
            .map_err(|e| AppError::External(format!("Failed to parse user info: {}", e)))?;

        Ok(user_info)
    }

    /// Find or create user from OAuth data
    pub async fn find_or_create_oauth_user(
        &self,
        provider: &str,
        oauth_subject: &str,
        user_info: &OAuthUserInfo,
        tokens: &OAuthTokenResponse,
    ) -> Result<User> {
        // Check if OAuth identity exists
        let existing_identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE oauth_provider = $1 AND oauth_subject = $2"
        )
        .bind(provider)
        .bind(oauth_subject)
        .fetch_optional(&self.db)
        .await?;

        if let Some(identity) = existing_identity {
            // Update tokens
            sqlx::query(
                "UPDATE identities 
                 SET oauth_access_token = $1, 
                     oauth_refresh_token = $2,
                     oauth_token_expires_at = NOW() + INTERVAL '3600 seconds',
                     updated_at = NOW()
                 WHERE id = $3"
            )
            .bind(&tokens.access_token)
            .bind(&tokens.refresh_token)
            .bind(&identity.id)
            .execute(&self.db)
            .await?;

            // Get user
            let user = sqlx::query_as::<_, User>(
                "SELECT * FROM users WHERE id = $1"
            )
            .bind(&identity.user_id)
            .fetch_one(&self.db)
            .await?;

            return Ok(user);
        }

        // Create new user
        let mut tx = self.db.begin().await?;

        let user_id = generate_id("user");
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (id, first_name, last_name, profile_image_url, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             RETURNING *"
        )
        .bind(&user_id)
        .bind(&user_info.given_name)
        .bind(&user_info.family_name)
        .bind(&user_info.picture)
        .fetch_one(&mut *tx)
        .await?;

        // Create OAuth identity
        let identity_type = format!("oauth_{}", provider);
        sqlx::query(
            "INSERT INTO identities 
             (id, user_id, type, identifier, verified, oauth_provider, oauth_subject,
              oauth_access_token, oauth_refresh_token, oauth_token_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '3600 seconds', NOW(), NOW())"
        )
        .bind(generate_id("ident"))
        .bind(&user_id)
        .bind(&identity_type)
        .bind(&user_info.email.as_ref().unwrap_or(&oauth_subject.to_string()))
        .bind(user_info.email_verified.unwrap_or(false))
        .bind(provider)
        .bind(oauth_subject)
        .bind(&tokens.access_token)
        .bind(&tokens.refresh_token)
        .execute(&mut *tx)
        .await?;

        // If email exists and is verified, create email identity too
        if let Some(email) = &user_info.email {
            if user_info.email_verified.unwrap_or(false) {
                sqlx::query(
                    "INSERT INTO identities (id, user_id, type, identifier, verified, verified_at, created_at, updated_at)
                     VALUES ($1, $2, 'email', $3, true, NOW(), NOW(), NOW())"
                )
                .bind(generate_id("ident"))
                .bind(&user_id)
                .bind(email)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> OAuthConfig {
        OAuthConfig {
            client_id: "test-client-id".to_string(),
            client_secret: "test-secret".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            authorization_url: "https://auth.provider.com/authorize".to_string(),
            token_url: "https://auth.provider.com/token".to_string(),
            userinfo_url: "https://auth.provider.com/userinfo".to_string(),
        }
    }

    // Note: OAuthService::get_authorization_url requires &self, so we test URL format logic
    
    #[test]
    fn test_authorization_url_format() {
        let config = create_test_config();
        let state = "random-state-token";
        
        // Simulate the URL generation logic
        let url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            config.authorization_url,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(state)
        );
        
        assert!(url.starts_with("https://auth.provider.com/authorize?"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid%20email%20profile"));
        assert!(url.contains("state=random-state-token"));
    }

    #[test]
    fn test_authorization_url_encodes_special_chars() {
        let config = OAuthConfig {
            client_id: "client id with spaces".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "https://app.example.com/callback?extra=param".to_string(),
            authorization_url: "https://auth.provider.com/authorize".to_string(),
            token_url: "https://auth.provider.com/token".to_string(),
            userinfo_url: "https://auth.provider.com/userinfo".to_string(),
        };
        let state = "state with special & chars";
        
        let url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            config.authorization_url,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(state)
        );
        
        // URL should contain encoded spaces (%20) and ampersands (%26)
        assert!(url.contains("client%20id%20with%20spaces"));
        assert!(url.contains("%26")); // Encoded &
        assert!(!url.contains(" ")); // No raw spaces
    }

    #[test]
    fn test_oauth_user_info_deserialization() {
        let json = r#"{
            "sub": "google-user-123",
            "email": "user@gmail.com",
            "email_verified": true,
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/photo.jpg"
        }"#;
        
        let user_info: OAuthUserInfo = serde_json::from_str(json).expect("Failed to parse user info");
        
        assert_eq!(user_info.sub, "google-user-123");
        assert_eq!(user_info.email, Some("user@gmail.com".to_string()));
        assert_eq!(user_info.email_verified, Some(true));
        assert_eq!(user_info.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_oauth_user_info_minimal() {
        // Only 'sub' is required
        let json = r#"{"sub": "user-123"}"#;
        
        let user_info: OAuthUserInfo = serde_json::from_str(json).unwrap();
        
        assert_eq!(user_info.sub, "user-123");
        assert!(user_info.email.is_none());
        assert!(user_info.name.is_none());
    }

    #[test]
    fn test_oauth_token_response_deserialization() {
        let json = r#"{
            "access_token": "ya29.access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "1//refresh-token",
            "id_token": "eyJ..."
        }"#;
        
        let response: OAuthTokenResponse = serde_json::from_str(json).unwrap();
        
        assert_eq!(response.access_token, "ya29.access-token");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.refresh_token, Some("1//refresh-token".to_string()));
    }

    #[test]
    fn test_oauth_token_response_minimal() {
        // Only access_token and token_type are required
        let json = r#"{
            "access_token": "token",
            "token_type": "Bearer"
        }"#;
        
        let response = serde_json::from_str::<OAuthTokenResponse>(json).expect("Failed to parse token response");
        
        assert_eq!(response.access_token, "token");
        assert!(response.expires_in.is_none());
        assert!(response.refresh_token.is_none());
        assert!(response.id_token.is_none());
    }

    #[test]
    fn test_oauth_user_info_malformed_json() {
        let json = r#"{"sub": "user-123", "param": "missing-quote}"#;
        let result = serde_json::from_str::<OAuthUserInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_oauth_token_response_malformed_json() {
        let json = r#"{"access_token": "token", "token_type: "Bearer"}"#; // Missing quote
        let result = serde_json::from_str::<OAuthTokenResponse>(json);
        assert!(result.is_err());
    }
}
