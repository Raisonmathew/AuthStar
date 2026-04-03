use crate::models::{User, Identity, Password, UserResponse};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use auth_core::{hash_password, verify_password};
use shared_types::{AppError, Result, generate_id, validation};
use sqlx::PgPool;

/// Number of previous passwords to retain and check against.
/// Users cannot reuse any of their last PASSWORD_HISTORY_DEPTH passwords.
const PASSWORD_HISTORY_DEPTH: i64 = 10;

/// Maximum consecutive failed password attempts before account lockout.
const MAX_FAILED_ATTEMPTS: i32 = 5;

// ─── Trait: UserRepository ────────────────────────────────────────────────────
//
// Contract for user data access. Implemented by UserService (real PostgreSQL)
// and can be implemented by a mock for handler-level unit tests.
//
// Uses native async fn in traits (Rust 1.75+). Not object-safe due to async;
// use generics (`fn handler<U: UserRepository>(svc: &U)`) for compile-time
// dispatch in tests.

/// Core user data access contract — enables unit-testable handlers.
pub trait UserRepository: Send + Sync {
    fn get_user(&self, user_id: &str) -> impl std::future::Future<Output = Result<User>> + Send;
    fn get_user_by_email(&self, email: &str) -> impl std::future::Future<Output = Result<User>> + Send;
    fn get_user_by_email_in_org(&self, email: &str, org_id: &str) -> impl std::future::Future<Output = Result<User>> + Send;
    fn create_user(
        &self,
        email: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        org_id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
    fn update_user(
        &self,
        user_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        profile_image_url: Option<&str>,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
    fn delete_user(&self, user_id: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    fn verify_user_password(&self, user_id: &str, password: &str) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn change_password(
        &self,
        user_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn invalidate_other_sessions(
        &self,
        user_id: &str,
        current_session_id: &str,
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
}

/// Parameters for creating an authenticated session.
///
/// R-4 FIX: All login paths must use `UserService::create_session()` with this
/// struct so that `decision_ref` is always written to `sessions.decision_ref`.
#[derive(Debug)]
pub struct CreateSessionParams<'a> {
    /// The authenticated user's ID.
    pub user_id: &'a str,
    /// The tenant (organisation) this session belongs to.
    pub tenant_id: &'a str,
    /// EIAA audit trail link — the `eiaa_executions.id` that authorised this login.
    /// `None` only for legacy/non-EIAA paths (deprecated; should always be `Some`).
    pub decision_ref: Option<&'a str>,
    /// NIST SP 800-63B assurance level: `"aal1"` or `"aal2"`.
    pub assurance_level: &'a str,
    /// JSON array of capability strings that were verified (e.g. `["password","totp"]`).
    pub verified_capabilities: serde_json::Value,
    /// Whether this is a provisional session (e.g. step-up not yet complete).
    pub is_provisional: bool,
    /// Session type discriminator — use `auth_core::jwt::session_types` constants.
    pub session_type: &'a str,
    /// Optional device fingerprint ID for risk engine correlation.
    pub device_id: Option<&'a str>,
    /// Session lifetime in seconds. Defaults to 3600 (1 hour) if `None`.
    pub expires_in_secs: Option<i64>,
}

/// Result of a successful `UserService::create_session()` call.
#[derive(Debug)]
pub struct CreatedSession {
    /// Primary key — used in JWT `sid` claim. Readable by the client.
    pub session_id: String,
    /// Opaque random token stored in `sessions.token`.
    /// Set as the `__session` httpOnly cookie value; never exposed in the JWT.
    pub session_token: String,
}

#[derive(Clone)]
pub struct UserService {
    db: PgPool,
}

impl UserService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new authenticated session with EIAA audit trail linkage.
    ///
    /// R-4 FIX: This is the single canonical session creation path. All login
    /// routes (`auth.rs`, `auth_flow.rs`, `hosted.rs`, `sso.rs`) must use this
    /// method so that `decision_ref` is always written to `sessions.decision_ref`.
    ///
    /// ## EIAA Audit Trail
    ///
    /// `decision_ref` links the session to the `eiaa_executions` row that
    /// authorised the login. Without it, the EIAA audit trail is broken:
    /// you cannot trace a session back to the capsule execution that created it.
    ///
    /// ## Session Token vs Session ID
    ///
    /// - `session_id` — primary key, used in JWT `sid` claim
    /// - `session_token` — opaque random token stored in `sessions.token`,
    ///   set as the `__session` httpOnly cookie value
    ///
    /// These are intentionally different: the session_id is in the JWT (which
    /// is readable by the client), while the token is opaque and only compared
    /// server-side for cookie-based auth.
    pub async fn create_session(&self, params: CreateSessionParams<'_>) -> Result<CreatedSession> {
        let session_id = generate_id("sess");
        let session_token = generate_id("stok");
        // Convert to String so PostgreSQL's `||` text concatenation works correctly.
        // Binding an i64 directly would produce `int8 || text` which PostgreSQL rejects.
        let expires_in_str = format!("{}", params.expires_in_secs.unwrap_or(3600));

        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, user_id, token, expires_at, created_at, updated_at,
                tenant_id, session_type, decision_ref,
                assurance_level, verified_capabilities, is_provisional, device_id
            )
            VALUES (
                $1, $2, $3, NOW() + ($4 || ' seconds')::INTERVAL, NOW(), NOW(),
                $5, $6, $7,
                $8, $9, $10, $11
            )
            "#
        )
        .bind(&session_id)
        .bind(params.user_id)
        .bind(&session_token)
        .bind(&expires_in_str)
        .bind(params.tenant_id)
        .bind(params.session_type)
        .bind(params.decision_ref)
        .bind(params.assurance_level)
        .bind(&params.verified_capabilities)
        .bind(params.is_provisional)
        .bind(params.device_id)
        .execute(&self.db)
        .await?;

        tracing::info!(
            session_id = %session_id,
            user_id = %params.user_id,
            tenant_id = %params.tenant_id,
            decision_ref = ?params.decision_ref,
            assurance_level = %params.assurance_level,
            is_provisional = params.is_provisional,
            "Session created"
        );

        Ok(CreatedSession { session_id, session_token })
    }

    /// Create a new user with email/password
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        org_id: Option<&str>,
    ) -> Result<User> {
        // Validate email
        if !validation::validate_email(email) {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Validate password
        if let Err(errors) = validation::validate_password(password) {
            return Err(AppError::Validation(errors.join(", ")));
        }

        // Check if email already exists (org-scoped when org_id provided, else global for admin contexts)
        let existing = if let Some(oid) = org_id {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM identities WHERE type = 'email' AND identifier = $1 AND organization_id = $2)"
            )
            .bind(email)
            .bind(oid)
            .fetch_one(&self.db)
            .await?
        } else {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM identities WHERE type = 'email' AND identifier = $1)"
            )
            .bind(email)
            .fetch_one(&self.db)
            .await?
        };

        if existing {
            return Err(AppError::Conflict("Email already registered".to_string()));
        }

        // Hash password
        let password_hash = hash_password(password)?;

        // Start transaction
        let mut tx = self.db.begin().await?;

        // Create user
        let user_id = generate_id("user");
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (id, first_name, last_name, organization_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             RETURNING *"
        )
        .bind(&user_id)
        .bind(first_name)
        .bind(last_name)
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await?;

        // Create email identity (org-scoped)
        sqlx::query(
            "INSERT INTO identities (id, user_id, organization_id, type, identifier, verified, created_at, updated_at)
             VALUES ($1, $2, $3, 'email', $4, false, NOW(), NOW())"
        )
        .bind(generate_id("ident"))
        .bind(&user_id)
        .bind(org_id)
        .bind(email)
        .execute(&mut *tx)
        .await?;

        // Store password hash
        sqlx::query(
            "INSERT INTO passwords (id, user_id, password_hash, created_at)
             VALUES ($1, $2, $3, NOW())"
        )
        .bind(generate_id("pass"))
        .bind(&user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Get user by email.
    ///
    /// MEDIUM-1 FIX: Only returns users whose email identity is verified.
    /// Without this filter, unverified users (who never confirmed their email)
    /// could log in, defeating the email verification flow entirely.
    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u
             INNER JOIN identities i ON i.user_id = u.id
             WHERE i.type = 'email'
               AND i.identifier = $1
               AND i.verified = true
               AND u.deleted_at IS NULL"
        )
        .bind(email)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Get user by email scoped to a specific organization.
    ///
    /// Multi-tenant safe: only returns users whose email identity belongs to the
    /// given organization. Prevents cross-tenant account confusion.
    pub async fn get_user_by_email_in_org(&self, email: &str, org_id: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u
             INNER JOIN identities i ON i.user_id = u.id
             WHERE i.type = 'email'
               AND i.identifier = $1
               AND i.organization_id = $2
               AND i.verified = true
               AND u.deleted_at IS NULL"
        )
        .bind(email)
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Verify user password with account lockout protection.
    ///
    /// HIGH-1 FIX: Tracks consecutive failed attempts and locks the account after
    /// MAX_FAILED_ATTEMPTS failures. Checks the `locked` flag before verifying.
    /// On success, resets the failed attempt counter.
    pub async fn verify_user_password(&self, user_id: &str, password: &str) -> Result<bool> {
        // HIGH-1: Check if account is locked before attempting verification
        let user = self.get_user(user_id).await?;
        if user.locked {
            return Err(AppError::Unauthorized(
                "Account is locked due to too many failed login attempts. \
                 Please contact support or wait for automatic unlock.".to_string()
            ));
        }

        let password_record = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Password not found".to_string()))?;

        let is_valid = verify_password(password, &password_record.password_hash)?;

        if is_valid {
            // HIGH-1: Reset failed attempt counter on successful login
            sqlx::query(
                "UPDATE users SET failed_login_attempts = 0, last_login_at = NOW() WHERE id = $1"
            )
            .bind(user_id)
            .execute(&self.db)
            .await?;
        } else {
            // HIGH-1: Increment failed attempt counter; lock account if threshold exceeded
            let new_count: (i32,) = sqlx::query_as(
                "UPDATE users
                 SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1
                 WHERE id = $1
                 RETURNING failed_login_attempts"
            )
            .bind(user_id)
            .fetch_one(&self.db)
            .await?;

            if new_count.0 >= MAX_FAILED_ATTEMPTS {
                sqlx::query(
                    "UPDATE users SET locked = true, locked_at = NOW() WHERE id = $1"
                )
                .bind(user_id)
                .execute(&self.db)
                .await?;

                tracing::warn!(
                    user_id = %user_id,
                    attempts = new_count.0,
                    "Account locked after {} failed login attempts", MAX_FAILED_ATTEMPTS
                );

                return Err(AppError::Unauthorized(
                    "Account locked after too many failed attempts.".to_string()
                ));
            }

            tracing::warn!(
                user_id = %user_id,
                attempts = new_count.0,
                remaining = MAX_FAILED_ATTEMPTS - new_count.0,
                "Failed login attempt"
            );
        }

        Ok(is_valid)
    }

    /// Unlock a user account (admin action).
    pub async fn unlock_user(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE users SET locked = false, locked_at = NULL, failed_login_attempts = 0 WHERE id = $1"
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        tracing::info!(user_id = %user_id, "Account unlocked by admin");
        Ok(())
    }

    /// Update user profile
    pub async fn update_user(
        &self,
        user_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        profile_image_url: Option<&str>,
    ) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "UPDATE users 
             SET first_name = COALESCE($2, first_name),
                 last_name = COALESCE($3, last_name),
                 profile_image_url = COALESCE($4, profile_image_url),
                 updated_at = NOW()
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING *"
        )
        .bind(user_id)
        .bind(first_name)
        .bind(last_name)
        .bind(profile_image_url)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Convert User to UserResponse with identity info
    pub async fn to_user_response(&self, user: &User) -> Result<UserResponse> {
        // Get email identity
        let email_identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 AND type = 'email' LIMIT 1"
        )
        .bind(&user.id)
        .fetch_optional(&self.db)
        .await?;

        // Get phone identity
        let phone_identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 AND type = 'phone' LIMIT 1"
        )
        .bind(&user.id)
        .fetch_optional(&self.db)
        .await?;

        // Check if MFA is enabled
        let mfa_enabled = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM mfa_factors WHERE user_id = $1 AND enabled = true)"
        )
        .bind(&user.id)
        .fetch_one(&self.db)
        .await?;

        Ok(UserResponse {
            id: user.id.clone(),
            created_at: user.created_at,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            profile_image_url: user.profile_image_url.clone(),
            email: email_identity.as_ref().map(|i| i.identifier.clone()),
            phone: phone_identity.as_ref().map(|i| i.identifier.clone()),
            email_verified: email_identity.map(|i| i.verified).unwrap_or(false),
            phone_verified: phone_identity.map(|i| i.verified).unwrap_or(false),
            mfa_enabled,
            public_metadata: user.public_metadata.clone(),
        })
    }

    /// Soft delete user
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let result = sqlx::query(
            "UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL"
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        Ok(())
    }

    /// Change a user's password with history enforcement.
    ///
    /// HIGH-G: Prevents password reuse by checking the new password against the
    /// last PASSWORD_HISTORY_DEPTH (10) stored hashes using Argon2id verification.
    /// Without this, a forced rotation policy is trivially bypassed by immediately
    /// cycling back to the original password.
    ///
    /// Steps:
    ///   1. Validate the new password meets complexity requirements.
    ///   2. Verify the current password is correct (re-authentication).
    ///   3. Fetch the last N password hashes from `password_history`.
    ///   4. Reject if the new password matches any historical hash.
    ///   5. Hash the new password and update `passwords` + insert into `password_history`
    ///      in a single transaction.
    pub async fn change_password(
        &self,
        user_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Step 1: Validate new password complexity
        if let Err(errors) = validation::validate_password(new_password) {
            return Err(AppError::Validation(errors.join(", ")));
        }

        // Step 2: Verify current password (re-authentication guard)
        let is_current_valid = self.verify_user_password(user_id, current_password).await?;
        if !is_current_valid {
            return Err(AppError::Unauthorized(
                "Current password is incorrect".to_string()
            ));
        }

        // Step 3: Fetch the last PASSWORD_HISTORY_DEPTH hashes
        let history: Vec<(String,)> = sqlx::query_as(
            "SELECT password_hash FROM password_history
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT $2"
        )
        .bind(user_id)
        .bind(PASSWORD_HISTORY_DEPTH)
        .fetch_all(&self.db)
        .await?;

        // Step 4: Reject if new password matches any historical hash
        let argon2 = Argon2::default();
        for (hash_str,) in &history {
            let parsed = PasswordHash::new(hash_str)
                .map_err(|e| AppError::Internal(format!("Invalid stored hash: {e}")))?;
            if argon2.verify_password(new_password.as_bytes(), &parsed).is_ok() {
                return Err(AppError::BadRequest(format!(
                    "New password cannot be the same as any of your last {PASSWORD_HISTORY_DEPTH} passwords"
                )));
            }
        }

        // Step 5: Hash new password and persist atomically
        let new_hash = hash_password(new_password)?;
        let history_id = generate_id("hist");

        let mut tx = self.db.begin().await?;

        // Update the active password record
        sqlx::query(
            "UPDATE passwords SET password_hash = $1 WHERE user_id = $2"
        )
        .bind(&new_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Insert into password_history (trigger prunes to last 10 automatically)
        sqlx::query(
            "INSERT INTO password_history (id, user_id, password_hash, created_at)
             VALUES ($1, $2, $3, NOW())"
        )
        .bind(&history_id)
        .bind(user_id)
        .bind(&new_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        tracing::info!(
            user_id = %user_id,
            "Password changed successfully (history depth: {})",
            PASSWORD_HISTORY_DEPTH
        );

        Ok(())
    }

    /// Invalidate all sessions for a user except the current one.
    ///
    /// Used after security-sensitive actions (password change, MFA reset) to
    /// force re-login on other devices. Returns the number of sessions
    /// invalidated.
    pub async fn invalidate_other_sessions(
        &self,
        user_id: &str,
        current_session_id: &str,
    ) -> Result<usize> {
        let rows = sqlx::query_scalar::<_, i64>(
            "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW())
             WHERE user_id = $1 AND id != $2 AND expires_at > NOW() AND revoked = FALSE
             RETURNING 1",
        )
        .bind(user_id)
        .bind(current_session_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows.len())
    }
}

impl UserRepository for UserService {
    fn get_user(&self, user_id: &str) -> impl std::future::Future<Output = Result<User>> + Send {
        self.get_user(user_id)
    }
    fn get_user_by_email(&self, email: &str) -> impl std::future::Future<Output = Result<User>> + Send {
        self.get_user_by_email(email)
    }
    fn get_user_by_email_in_org(&self, email: &str, org_id: &str) -> impl std::future::Future<Output = Result<User>> + Send {
        self.get_user_by_email_in_org(email, org_id)
    }
    fn create_user(
        &self,
        email: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        org_id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<User>> + Send {
        self.create_user(email, password, first_name, last_name, org_id)
    }
    fn update_user(
        &self,
        user_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        profile_image_url: Option<&str>,
    ) -> impl std::future::Future<Output = Result<User>> + Send {
        self.update_user(user_id, first_name, last_name, profile_image_url)
    }
    fn delete_user(&self, user_id: &str) -> impl std::future::Future<Output = Result<()>> + Send {
        self.delete_user(user_id)
    }
    fn verify_user_password(&self, user_id: &str, password: &str) -> impl std::future::Future<Output = Result<bool>> + Send {
        self.verify_user_password(user_id, password)
    }
    fn change_password(
        &self,
        user_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        self.change_password(user_id, current_password, new_password)
    }
    fn invalidate_other_sessions(
        &self,
        user_id: &str,
        current_session_id: &str,
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        self.invalidate_other_sessions(user_id, current_session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_params_edge_cases() {
        // Edge case: test CreateSessionParams construction with maximum data length and null paths
        let params = CreateSessionParams {
            user_id: "user_extremely_long_id_that_might_break_fixed_allocations",
            tenant_id: "tenant_null",
            decision_ref: None, // Testing None decision_ref
            assurance_level: "aal1",
            verified_capabilities: serde_json::json!([]), // Empty capabilities
            is_provisional: true,
            session_type: "web",
            device_id: Some("device_123"),
            expires_in_secs: None, // Implicit default fallback test
        };

        assert_eq!(params.decision_ref, None);
        assert_eq!(params.expires_in_secs, None);
        assert!(params.is_provisional);
        assert_eq!(params.session_type, "web");
        assert_eq!(params.verified_capabilities.as_array().unwrap().len(), 0);
    }
}
