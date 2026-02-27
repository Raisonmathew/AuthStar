use crate::models::{User, Identity, Password, UserResponse};
use auth_core::{hash_password, verify_password};
use shared_types::{AppError, Result, generate_id, validation};
use sqlx::PgPool;

#[derive(Clone)]
pub struct UserService {
    db: PgPool,
}

impl UserService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new user with email/password
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<User> {
        // Validate email
        if !validation::validate_email(email) {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Validate password
        if let Err(errors) = validation::validate_password(password) {
            return Err(AppError::Validation(errors.join(", ")));
        }

        // Check if email already exists
        let existing = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE type = 'email' AND identifier = $1)"
        )
        .bind(email)
        .fetch_one(&self.db)
        .await?;

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
            "INSERT INTO users (id, first_name, last_name, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             RETURNING *"
        )
        .bind(&user_id)
        .bind(first_name)
        .bind(last_name)
        .fetch_one(&mut *tx)
        .await?;

        // Create email identity
        sqlx::query(
            "INSERT INTO identities (id, user_id, type, identifier, verified, created_at, updated_at)
             VALUES ($1, $2, 'email', $3, false, NOW(), NOW())"
        )
        .bind(generate_id("ident"))
        .bind(&user_id)
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

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u
             INNER JOIN identities i ON i.user_id = u.id
             WHERE i.type = 'email' AND i.identifier = $1 AND u.deleted_at IS NULL"
        )
        .bind(email)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Verify user password
    pub async fn verify_user_password(&self, user_id: &str, password: &str) -> Result<bool> {
        let password_record = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Password not found".to_string()))?;

        verify_password(password, &password_record.password_hash)
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
}

#[cfg(test)]
mod tests {
    

    // Note: These tests require a test database
    // Run with: DATABASE_URL=postgres://... cargo test
}
