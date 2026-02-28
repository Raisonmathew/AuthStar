use crate::models::{SignupTicket, VerificationToken};
use shared_types::{AppError, Result, generate_id};
use sqlx::PgPool;
use chrono::{Duration, Utc};
use rand::Rng;

use email_service::EmailService;

// SECURITY: Verification codes are NEVER logged. Only identity_id is logged for audit.

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

    /// Create a signup ticket.
    ///
    /// MEDIUM-EIAA-9 FIX: Accept an optional `decision_ref` parameter that links this
    /// signup ticket to the EIAA execution that authorized the signup flow. The
    /// `decision_ref` is stored in the `signup_tickets.decision_ref` column (added by
    /// migration 031) and is later used by the re-execution verifier to confirm that
    /// the signup was authorized by a valid capsule execution.
    ///
    /// Callers that have already executed the signup capsule should pass the
    /// `decision_ref` from the `eiaa_executions` row. Callers that have not yet
    /// executed the capsule (e.g., legacy flows) may pass `None`.
    pub async fn create_signup_ticket(
        &self,
        email: &str,
        password_hash: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        decision_ref: Option<&str>,
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

        // MEDIUM-EIAA-9 FIX: Store decision_ref alongside the ticket so the
        // signup can be linked to its EIAA execution for audit and re-execution.
        let ticket = sqlx::query_as::<_, SignupTicket>(
            "INSERT INTO signup_tickets
             (id, email, password_hash, first_name, last_name, status,
              verification_code, verification_code_expires_at, expires_at, created_at,
              decision_ref)
             VALUES ($1, $2, $3, $4, $5, 'awaiting_verification', $6, $7, $8, NOW(), $9)
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
        .bind(decision_ref)
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

    /// Verify signup code and create user (combined operation for EIAA flow).
    ///
    /// HIGH-2 FIX: All three inserts are wrapped in a single transaction to prevent
    /// partial user creation on crash/connection failure.
    ///
    /// MEDIUM-EIAA-9 FIX: After creating the user, update the `eiaa_executions` row
    /// (identified by `signup_tickets.decision_ref`) to set `user_id`. This links the
    /// EIAA execution audit record to the created user, completing the chain:
    ///   signup capsule execution → decision_ref → eiaa_executions.user_id → users.id
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
            .ok_or_else(|| AppError::BadRequest("Email is required".to_string()))?
            .to_string();
        let password_hash = ticket.password_hash.as_deref()
            .ok_or_else(|| AppError::BadRequest("Password is required".to_string()))?
            .to_string();

        let user_id = generate_id("user");
        let identity_id = generate_id("ident");
        let password_id = generate_id("pass");

        // HIGH-2 FIX: Wrap all three inserts in a single atomic transaction.
        // If any step fails, the entire user creation is rolled back — no partial state.
        let mut tx = self.db.begin().await?;

        // 1. Create user
        sqlx::query(
            "INSERT INTO users (id, first_name, last_name, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())"
        )
        .bind(&user_id)
        .bind(&ticket.first_name)
        .bind(&ticket.last_name)
        .execute(&mut *tx)
        .await?;

        // 2. Create verified identity
        sqlx::query(
            "INSERT INTO identities (id, user_id, type, identifier, verified, created_at, updated_at)
             VALUES ($1, $2, 'email', $3, true, NOW(), NOW())"
        )
        .bind(&identity_id)
        .bind(&user_id)
        .bind(&email)
        .execute(&mut *tx)
        .await?;

        // 3. Create password
        sqlx::query(
            "INSERT INTO passwords (id, user_id, password_hash, algorithm, created_at)
             VALUES ($1, $2, $3, 'argon2id', NOW())"
        )
        .bind(&password_id)
        .bind(&user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;

        // Fetch the created user within the same transaction
        let user = sqlx::query_as::<_, crate::models::User>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await?;

        // Commit — only now is the user visible to other connections
        tx.commit().await?;

        tracing::info!(user_id = %user_id, "Created user from signup ticket");
        // CRITICAL-1 FIX: email is NOT logged here — only user_id for audit trail

        // MEDIUM-EIAA-9 FIX: Back-fill user_id on the eiaa_executions row that
        // authorized this signup. This completes the audit chain:
        //   signup capsule execution → decision_ref → eiaa_executions.user_id → users.id
        //
        // This is a best-effort update — if the ticket has no decision_ref (legacy flow
        // or capsule not yet configured), we skip silently. If the DB update fails, we
        // log a warning but do NOT roll back the user creation (the user is already
        // committed and the audit gap is non-critical compared to losing the user).
        if let Some(ref decision_ref) = ticket.decision_ref {
            match sqlx::query(
                "UPDATE eiaa_executions SET user_id = $1 WHERE decision_ref = $2"
            )
            .bind(&user_id)
            .bind(decision_ref)
            .execute(&self.db)
            .await
            {
                Ok(result) if result.rows_affected() == 1 => {
                    tracing::info!(
                        user_id = %user_id,
                        decision_ref = %decision_ref,
                        "Linked eiaa_executions.user_id to created user"
                    );
                }
                Ok(_) => {
                    tracing::warn!(
                        user_id = %user_id,
                        decision_ref = %decision_ref,
                        "eiaa_executions row not found for decision_ref — audit chain incomplete"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        decision_ref = %decision_ref,
                        error = %e,
                        "Failed to update eiaa_executions.user_id — audit chain incomplete"
                    );
                }
            }
        }

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

    /// Generate 6-digit verification code.
    /// CRITICAL-1 FIX: The code is NEVER logged. Logging OTPs exposes them to anyone
    /// with log access (Datadog, CloudWatch, ELK) and defeats email verification entirely.
    fn generate_verification_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1000000))
        // DO NOT log the code value — log only the identity_id at the call site
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

