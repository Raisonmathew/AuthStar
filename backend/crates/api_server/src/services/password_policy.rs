use crate::middleware::org_context::set_rls_context_on_conn;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use sqlx::{PgPool, Postgres};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    pub id: String,
    pub tenant_id: String,
    pub enabled: bool,
    pub min_length: i32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub history_depth: i32,
    pub max_age_days: Option<i32>,
    pub force_rotation: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePasswordPolicyRequest {
    pub enabled: Option<bool>,
    pub min_length: Option<i32>,
    pub require_uppercase: Option<bool>,
    pub require_lowercase: Option<bool>,
    pub require_digit: Option<bool>,
    pub require_symbol: Option<bool>,
    pub history_depth: Option<i32>,
    pub max_age_days: Option<Option<i32>>,
    pub force_rotation: Option<bool>,
}

#[derive(Clone)]
pub struct PasswordPolicyService {
    db: PgPool,
}

impl PasswordPolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn get_policy(&self, tenant_id: &str) -> Result<PasswordPolicy> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        self.get_policy_with_conn(tenant_id, &mut conn).await
    }

    pub async fn update_policy(
        &self,
        tenant_id: &str,
        req: UpdatePasswordPolicyRequest,
    ) -> Result<PasswordPolicy> {
        if let Some(min_length) = req.min_length {
            if !(8..=256).contains(&min_length) {
                return Err(AppError::Validation(
                    "minLength must be between 8 and 256".to_string(),
                ));
            }
        }
        if let Some(history_depth) = req.history_depth {
            if !(0..=50).contains(&history_depth) {
                return Err(AppError::Validation(
                    "historyDepth must be between 0 and 50".to_string(),
                ));
            }
        }
        if let Some(Some(max_age_days)) = req.max_age_days {
            if !(1..=3650).contains(&max_age_days) {
                return Err(AppError::Validation(
                    "maxAgeDays must be between 1 and 3650".to_string(),
                ));
            }
        }

        let mut conn = self.tenant_conn(tenant_id).await?;
        self.get_policy_with_conn(tenant_id, &mut conn).await?;
        let max_age_days = req.max_age_days.flatten();
        let clear_max_age = matches!(req.max_age_days, Some(None));

        let policy = sqlx::query_as::<_, PasswordPolicy>(
            r#"
            UPDATE password_policies
            SET enabled = COALESCE($2, enabled),
                min_length = COALESCE($3, min_length),
                require_uppercase = COALESCE($4, require_uppercase),
                require_lowercase = COALESCE($5, require_lowercase),
                require_digit = COALESCE($6, require_digit),
                require_symbol = COALESCE($7, require_symbol),
                history_depth = COALESCE($8, history_depth),
                max_age_days = CASE WHEN $10 THEN NULL ELSE COALESCE($9, max_age_days) END,
                force_rotation = COALESCE($11, force_rotation),
                updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING id, tenant_id, enabled, min_length, require_uppercase, require_lowercase,
                      require_digit, require_symbol, history_depth, max_age_days, force_rotation,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(req.enabled)
        .bind(req.min_length)
        .bind(req.require_uppercase)
        .bind(req.require_lowercase)
        .bind(req.require_digit)
        .bind(req.require_symbol)
        .bind(req.history_depth)
        .bind(max_age_days)
        .bind(clear_max_age)
        .bind(req.force_rotation)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Update password policy: {e}")))?;

        Ok(policy)
    }

    pub async fn validate_password(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        password: &str,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let policy = self.get_policy_with_conn(tenant_id, &mut conn).await?;
        let errors = validate_password_against_policy(&policy, password);
        if !errors.is_empty() {
            return Err(AppError::Validation(errors.join(", ")));
        }

        if policy.enabled && policy.history_depth > 0 {
            if let Some(user_id) = user_id {
                let history: Vec<(String,)> = sqlx::query_as(
                    r#"
                    SELECT password_hash
                    FROM password_history
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(user_id)
                .bind(policy.history_depth as i64)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| AppError::Internal(format!("Fetch password history: {e}")))?;

                for (hash,) in history {
                    if auth_core::verify_password(password, &hash)? {
                        return Err(AppError::BadRequest(format!(
                            "New password cannot match any of your last {} passwords",
                            policy.history_depth
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn get_policy_with_conn(
        &self,
        tenant_id: &str,
        conn: &mut sqlx::pool::PoolConnection<Postgres>,
    ) -> Result<PasswordPolicy> {
        if let Some(policy) = sqlx::query_as::<_, PasswordPolicy>(
            r#"
            SELECT id, tenant_id, enabled, min_length, require_uppercase, require_lowercase,
                   require_digit, require_symbol, history_depth, max_age_days, force_rotation,
                   created_at, updated_at
            FROM password_policies
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut **conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch password policy: {e}")))?
        {
            return Ok(policy);
        }

        sqlx::query_as::<_, PasswordPolicy>(
            r#"
            INSERT INTO password_policies (tenant_id)
            VALUES ($1)
            RETURNING id, tenant_id, enabled, min_length, require_uppercase, require_lowercase,
                      require_digit, require_symbol, history_depth, max_age_days, force_rotation,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&mut **conn)
        .await
        .map_err(|e| AppError::Internal(format!("Create default password policy: {e}")))
    }

    async fn tenant_conn(&self, tenant_id: &str) -> Result<sqlx::pool::PoolConnection<Postgres>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set password-policy RLS context".into()))?;
        Ok(conn)
    }
}

pub fn validate_password_against_policy(policy: &PasswordPolicy, password: &str) -> Vec<String> {
    if !policy.enabled {
        return Vec::new();
    }

    let mut errors = Vec::new();
    if password.chars().count() < policy.min_length as usize {
        errors.push(format!(
            "Password must be at least {} characters",
            policy.min_length
        ));
    }
    if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        errors.push("Password must include an uppercase letter".to_string());
    }
    if policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        errors.push("Password must include a lowercase letter".to_string());
    }
    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("Password must include a digit".to_string());
    }
    if policy.require_symbol && !password.chars().any(|c| c.is_ascii_punctuation()) {
        errors.push("Password must include a symbol".to_string());
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::{validate_password_against_policy, PasswordPolicy};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            id: "pwpol_test".to_string(),
            tenant_id: "org_test".to_string(),
            enabled: true,
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_symbol: true,
            history_depth: 10,
            max_age_days: None,
            force_rotation: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn accepts_strong_password() {
        assert!(validate_password_against_policy(&policy(), "StrongPass123!").is_empty());
    }

    #[test]
    fn rejects_missing_requirements() {
        let errors = validate_password_against_policy(&policy(), "weak");
        assert!(errors.iter().any(|e| e.contains("at least")));
        assert!(errors.iter().any(|e| e.contains("uppercase")));
        assert!(errors.iter().any(|e| e.contains("digit")));
        assert!(errors.iter().any(|e| e.contains("symbol")));
    }

    #[test]
    fn disabled_policy_allows_anything() {
        let mut policy = policy();
        policy.enabled = false;
        assert!(validate_password_against_policy(&policy, "x").is_empty());
    }
}
