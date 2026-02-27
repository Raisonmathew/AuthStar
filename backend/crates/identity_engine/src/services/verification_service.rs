use crate::models::{SignupTicket, VerificationToken};
use shared_types::{AppError, Result, generate_id};
use sqlx::PgPool;
use chrono::{Duration, Utc};
use rand::Rng;

use email_service::EmailService;

#[derive(Clone)]
pub struct VerificationService {
    db: PgPool,
    email_service: EmailService,
}

impl VerificationService {
    pub fn new(db: PgPool, email_service: EmailService) -> Self {
        Self { db, email_service }
    }

    // ... (keep existing methods until send_verification_email)

    /// Send verification email
    pub async fn send_verification_email(&self, email: &str, code: &str) -> Result<()> {
        self.email_service.send_verification_code(email, code)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to send email: {}", e)))?;
        
        tracing::info!("Sent verification code to {}", email);
        Ok(())
    }
    // ... (keep existing methods)

    /// Create a signup ticket
    pub async fn create_signup_ticket(
        &self,
        email: &str,
        password_hash: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<SignupTicket> {
        // Check if email already exists
        let email_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE type = 'email' AND identifier = $1)"
        )
        .bind(email)
        .fetch_one(&self.db)
        .await?;

        if email_exists {
            return Err(AppError::Conflict("Email already registered".to_string()));
        }

        let ticket_id = generate_id("ticket");
        let expires_at = Utc::now() + Duration::minutes(15);
        let verification_code = self.generate_verification_code();
        let code_expires_at = Utc::now() + Duration::minutes(10);

        let ticket = sqlx::query_as::<_, SignupTicket>(
            "INSERT INTO signup_tickets 
             (id, email, password_hash, first_name, last_name, status, 
              verification_code, verification_code_expires_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, 'awaiting_verification', $6, $7, $8, NOW())
             RETURNING *"
        )
        .bind(&ticket_id)
        .bind(email)
        .bind(password_hash)
        .bind(first_name)
        .bind(last_name)
        .bind(&verification_code)
        .bind(code_expires_at)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await?;

        Ok(ticket)
    }

    /// Get signup ticket by ID
    pub async fn get_signup_ticket(&self, ticket_id: &str) -> Result<SignupTicket> {
        let ticket = sqlx::query_as::<_, SignupTicket>(
            "SELECT * FROM signup_tickets WHERE id = $1"
        )
        .bind(ticket_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signup ticket not found".to_string()))?;

        // Check if expired
        if ticket.expires_at < Utc::now() {
            return Err(AppError::BadRequest("Signup ticket has expired".to_string()));
        }

        Ok(ticket)
    }

    /// Verify signup code
    pub async fn verify_signup_code(&self, ticket_id: &str, code: &str) -> Result<bool> {
        let ticket = self.get_signup_ticket(ticket_id).await?;

        // Check attempts
        if ticket.verification_attempts >= 3 {
            return Err(AppError::TooManyRequests("Too many verification attempts".to_string()));
        }

        // Check if code is expired
        if let Some(code_expires_at) = ticket.verification_code_expires_at {
            if code_expires_at < Utc::now() {
                return Err(AppError::BadRequest("Verification code has expired".to_string()));
            }
        }

        // Verify code
        let is_valid = ticket.verification_code.as_deref() == Some(code);

        if !is_valid {
            // Increment attempts
            sqlx::query(
                "UPDATE signup_tickets SET verification_attempts = verification_attempts + 1 WHERE id = $1"
            )
            .bind(ticket_id)
            .execute(&self.db)
            .await?;

            return Ok(false);
        }

        // Mark as complete
        sqlx::query(
            "UPDATE signup_tickets SET status = 'complete' WHERE id = $1"
        )
        .bind(ticket_id)
        .execute(&self.db)
        .await?;

        Ok(true)
    }

    /// Verify signup code and create user (combined operation for EIAA flow)
    pub async fn verify_and_create_user(&self, ticket_id: &str, code: &str) -> Result<crate::models::User> {
        // First verify the code
        let is_valid = self.verify_signup_code(ticket_id, code).await?;
        if !is_valid {
            return Err(AppError::BadRequest("Invalid verification code".to_string()));
        }

        // Get the ticket to extract user info
        let ticket = self.get_signup_ticket(ticket_id).await?;

        // Extract required fields
        let email = ticket.email.as_deref()
            .ok_or_else(|| AppError::BadRequest("Email is required".to_string()))?;
        let password_hash = ticket.password_hash.as_deref()
            .ok_or_else(|| AppError::BadRequest("Password is required".to_string()))?;

        // Create the user from ticket data
        let user_id = generate_id("user");
        let identity_id = generate_id("ident");
        let password_id = generate_id("pass");

        // 1. Create user
        sqlx::query(
            "INSERT INTO users (id, first_name, last_name, created_at, updated_at) 
             VALUES ($1, $2, $3, NOW(), NOW())"
        )
        .bind(&user_id)
        .bind(&ticket.first_name)
        .bind(&ticket.last_name)
        .execute(&self.db)
        .await?;

        // 2. Create verified identity
        sqlx::query(
            "INSERT INTO identities (id, user_id, type, identifier, verified, created_at, updated_at) 
             VALUES ($1, $2, 'email', $3, true, NOW(), NOW())"
        )
        .bind(&identity_id)
        .bind(&user_id)
        .bind(email)
        .execute(&self.db)
        .await?;

        // 3. Create password
        sqlx::query(
            "INSERT INTO passwords (id, user_id, password_hash, algorithm, created_at) 
             VALUES ($1, $2, $3, 'argon2id', NOW())"
        )
        .bind(&password_id)
        .bind(&user_id)
        .bind(password_hash)
        .execute(&self.db)
        .await?;

        // Fetch the created user
        let user = sqlx::query_as::<_, crate::models::User>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(&user_id)
        .fetch_one(&self.db)
        .await?;

        tracing::info!(user_id = %user_id, email = %email, "Created user from signup");

        Ok(user)
    }

    /// Create verification token for identity
    pub async fn create_verification_token(&self, identity_id: &str) -> Result<VerificationToken> {
        let token = self.generate_secure_token();
        let code = self.generate_verification_code();
        let expires_at = Utc::now() + Duration::minutes(10);

        let verification_token = sqlx::query_as::<_, VerificationToken>(
            "INSERT INTO verification_tokens (id, identity_id, token, code, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             RETURNING *"
        )
        .bind(generate_id("vtoken"))
        .bind(identity_id)
        .bind(&token)
        .bind(&code)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await?;

        Ok(verification_token)
    }

    /// Verify token
    pub async fn verify_token(&self, token: &str) -> Result<String> {
        let verification_token = sqlx::query_as::<_, VerificationToken>(
            "SELECT * FROM verification_tokens WHERE token = $1 AND used = false"
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Invalid verification token".to_string()))?;

        // Check expiration
        if verification_token.expires_at < Utc::now() {
            return Err(AppError::BadRequest("Verification token has expired".to_string()));
        }

        // Mark as used
        sqlx::query(
            "UPDATE verification_tokens SET used = true, used_at = NOW() WHERE id = $1"
        )
        .bind(&verification_token.id)
        .execute(&self.db)
        .await?;

        // Mark identity as verified
        sqlx::query(
            "UPDATE identities SET verified = true, verified_at = NOW() WHERE id = $1"
        )
        .bind(&verification_token.identity_id)
        .execute(&self.db)
        .await?;

        Ok(verification_token.identity_id)
    }

    /// Generate 6-digit verification code
    fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let code = format!("{:06}", rng.gen_range(0..1000000));
        tracing::info!("GENERATED_VERIFICATION_CODE: {}", code);
        code
    }

    /// Generate secure random token
    fn generate_secure_token(&self) -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;

        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

}

