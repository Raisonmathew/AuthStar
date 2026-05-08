use crate::middleware::org_context::set_rls_context_on_conn;
use crate::services::password_policy::validate_password_against_policy;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use shared_types::{generate_id, AppError, Result};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    NotRequired,
    Pending,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext<'a> {
    pub tenant_id: &'a str,
    pub user_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub code: String,
    pub status: ActionStatus,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RequiredActionRecord {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub code: String,
    pub state: String,
    pub priority: i32,
    pub ttl_seconds: Option<i32>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait RequiredAction: Send + Sync {
    fn code(&self) -> &'static str;
    fn priority(&self) -> i32;
    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus>;
    async fn challenge(&self, _db: &PgPool, ctx: &ActionContext<'_>) -> Result<ChallengeResponse> {
        Ok(ChallengeResponse {
            code: self.code().to_string(),
            status: ActionStatus::Pending,
            metadata: serde_json::json!({
                "tenant_id": ctx.tenant_id,
                "user_id": ctx.user_id,
            }),
        })
    }
    async fn complete(
        &self,
        _db: &PgPool,
        _ctx: &ActionContext<'_>,
        _payload: serde_json::Value,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RequiredActionRegistry {
    actions: Arc<HashMap<&'static str, Arc<dyn RequiredAction>>>,
}

impl RequiredActionRegistry {
    pub fn new(actions: Vec<Arc<dyn RequiredAction>>) -> Self {
        let actions = actions.into_iter().map(|a| (a.code(), a)).collect();
        Self {
            actions: Arc::new(actions),
        }
    }

    pub fn default_actions() -> Self {
        Self::new(vec![
            Arc::new(VerifyEmailRequiredAction),
            Arc::new(VerifyPhoneRequiredAction),
            Arc::new(ConfigureMfaRequiredAction),
            Arc::new(UpdatePasswordRequiredAction),
        ])
    }

    pub fn get(&self, code: &str) -> Option<Arc<dyn RequiredAction>> {
        self.actions.get(code).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<dyn RequiredAction>> + '_ {
        self.actions.values().cloned()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }
}

#[derive(Clone)]
pub struct RequiredActionService {
    db: PgPool,
    registry: RequiredActionRegistry,
}

impl RequiredActionService {
    pub fn new(db: PgPool, registry: RequiredActionRegistry) -> Self {
        Self { db, registry }
    }

    pub async fn evaluate_and_sync(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<RequiredActionRecord>> {
        let ctx = ActionContext { tenant_id, user_id };
        for action in self.registry.iter() {
            match action.evaluate(&self.db, &ctx).await? {
                ActionStatus::Pending => {
                    self.ensure_pending(tenant_id, user_id, action.code(), action.priority(), None)
                        .await?;
                }
                ActionStatus::Completed => {
                    self.mark_completed_if_pending(tenant_id, user_id, action.code())
                        .await?;
                }
                ActionStatus::NotRequired => {}
            }
        }
        self.pending_for_user(tenant_id, user_id).await
    }

    pub async fn pending_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<RequiredActionRecord>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, RequiredActionRecord>(
            r#"
            SELECT id, tenant_id, user_id, code, state, priority, ttl_seconds, metadata,
                   created_at, updated_at, completed_at, expires_at
            FROM required_actions
            WHERE tenant_id = $1
              AND user_id = $2
              AND state = 'pending'
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("List required actions: {e}")))?;
        Ok(rows)
    }

    pub async fn pending_codes(&self, tenant_id: &str, user_id: &str) -> Result<Vec<String>> {
        Ok(self
            .pending_for_user(tenant_id, user_id)
            .await?
            .into_iter()
            .map(|r| r.code)
            .collect())
    }

    pub async fn ensure_pending(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
        priority: i32,
        metadata: Option<serde_json::Value>,
    ) -> Result<RequiredActionRecord> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let id = generate_id("reqact");
        let metadata = metadata.unwrap_or_else(|| serde_json::json!({}));
        let row = sqlx::query_as::<_, RequiredActionRecord>(
            r#"
            INSERT INTO required_actions (id, tenant_id, user_id, code, state, priority, metadata)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            ON CONFLICT (tenant_id, user_id, code, state)
            DO UPDATE SET priority = EXCLUDED.priority, metadata = EXCLUDED.metadata, updated_at = NOW()
            RETURNING id, tenant_id, user_id, code, state, priority, ttl_seconds, metadata,
                      created_at, updated_at, completed_at, expires_at
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(code)
        .bind(priority)
        .bind(metadata)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Ensure required action: {e}")))?;
        Ok(row)
    }

    pub async fn challenge(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<ChallengeResponse> {
        let action = self
            .registry
            .get(code)
            .ok_or_else(|| AppError::NotFound(format!("Unknown required action: {code}")))?;
        action
            .challenge(&self.db, &ActionContext { tenant_id, user_id })
            .await
    }

    pub async fn complete(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let action = self
            .registry
            .get(code)
            .ok_or_else(|| AppError::NotFound(format!("Unknown required action: {code}")))?;
        action
            .complete(&self.db, &ActionContext { tenant_id, user_id }, payload)
            .await?;
        self.mark_completed_if_pending(tenant_id, user_id, code)
            .await
    }

    async fn mark_completed_if_pending(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE required_actions
            SET state = 'completed', completed_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND code = $3 AND state = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(code)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Complete required action: {e}")))?;
        Ok(())
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set required-action RLS context".into()))?;
        Ok(conn)
    }
}

pub struct VerifyEmailRequiredAction;

#[async_trait]
impl RequiredAction for VerifyEmailRequiredAction {
    fn code(&self) -> &'static str {
        "verify_email"
    }

    fn priority(&self) -> i32 {
        10
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        evaluate_identity_verification(db, ctx, "email", "verify_email").await
    }

    async fn challenge(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ChallengeResponse> {
        create_identity_verification_challenge(db, ctx, "email", self.code()).await
    }

    async fn complete(
        &self,
        db: &PgPool,
        ctx: &ActionContext<'_>,
        payload: serde_json::Value,
    ) -> Result<()> {
        complete_identity_verification(db, ctx, "email", payload).await
    }
}

pub struct VerifyPhoneRequiredAction;

#[async_trait]
impl RequiredAction for VerifyPhoneRequiredAction {
    fn code(&self) -> &'static str {
        "verify_phone"
    }

    fn priority(&self) -> i32 {
        15
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        evaluate_identity_verification(db, ctx, "phone", "verify_phone").await
    }

    async fn challenge(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ChallengeResponse> {
        create_identity_verification_challenge(db, ctx, "phone", self.code()).await
    }

    async fn complete(
        &self,
        db: &PgPool,
        ctx: &ActionContext<'_>,
        payload: serde_json::Value,
    ) -> Result<()> {
        complete_identity_verification(db, ctx, "phone", payload).await
    }
}

async fn evaluate_identity_verification(
    db: &PgPool,
    ctx: &ActionContext<'_>,
    identity_type: &str,
    action_code: &str,
) -> Result<ActionStatus> {
    let mut conn = db
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("Acquire {action_code} connection: {e}")))?;
    set_rls_context_on_conn(&mut conn, ctx.tenant_id)
        .await
        .map_err(|_| AppError::Internal(format!("Set {action_code} RLS context")))?;

    let state: Option<(bool,)> = sqlx::query_as(
        r#"
        SELECT verified
        FROM identities
        WHERE organization_id = $1 AND user_id = $2 AND type = $3
        ORDER BY verified DESC, created_at ASC
        LIMIT 1
        "#,
    )
    .bind(ctx.tenant_id)
    .bind(ctx.user_id)
    .bind(identity_type)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Evaluate {action_code} action: {e}")))?;

    Ok(match state {
        Some((true,)) => ActionStatus::Completed,
        Some((false,)) => ActionStatus::Pending,
        None => ActionStatus::NotRequired,
    })
}

async fn create_identity_verification_challenge(
    db: &PgPool,
    ctx: &ActionContext<'_>,
    identity_type: &str,
    action_code: &str,
) -> Result<ChallengeResponse> {
    let mut conn = db.acquire().await.map_err(|e| {
        AppError::Internal(format!("Acquire {action_code} challenge connection: {e}"))
    })?;
    set_rls_context_on_conn(&mut conn, ctx.tenant_id)
        .await
        .map_err(|_| AppError::Internal(format!("Set {action_code} challenge RLS context")))?;

    let identity: Option<(String, String, bool)> = sqlx::query_as(
        r#"
        SELECT id, identifier, verified
        FROM identities
        WHERE organization_id = $1 AND user_id = $2 AND type = $3
        ORDER BY verified DESC, created_at ASC
        LIMIT 1
        "#,
    )
    .bind(ctx.tenant_id)
    .bind(ctx.user_id)
    .bind(identity_type)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch {action_code} identity: {e}")))?;

    let (identity_id, identifier, verified) = identity.ok_or_else(|| {
        AppError::BadRequest(format!(
            "No {identity_type} identity is registered for this user"
        ))
    })?;

    if verified {
        return Ok(ChallengeResponse {
            code: action_code.to_string(),
            status: ActionStatus::Completed,
            metadata: serde_json::json!({
                "channel": identity_type,
                "identifier": mask_identifier(identity_type, &identifier),
            }),
        });
    }

    let verification_code = generate_verification_code();
    let token = generate_verification_token();
    let expires_at = Utc::now() + Duration::minutes(10);
    sqlx::query(
        r#"
        INSERT INTO verification_tokens (id, identity_id, token, code, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(generate_id("vtoken"))
    .bind(&identity_id)
    .bind(&token)
    .bind(&verification_code)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Internal(format!("Create {action_code} verification token: {e}")))?;

    let mut metadata = serde_json::json!({
        "channel": identity_type,
        "identifier": mask_identifier(identity_type, &identifier),
        "rawIdentifier": identifier,
        "expiresAt": expires_at,
        "deliveryCode": verification_code,
    });
    if !is_production() {
        let debug_code = metadata
            .get("deliveryCode")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        metadata["debugCode"] = debug_code;
    }

    Ok(ChallengeResponse {
        code: action_code.to_string(),
        status: ActionStatus::Pending,
        metadata,
    })
}

async fn complete_identity_verification(
    db: &PgPool,
    ctx: &ActionContext<'_>,
    identity_type: &str,
    payload: serde_json::Value,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload {
        token: Option<String>,
        code: Option<String>,
    }

    let payload: Payload = serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("token or code is required".to_string()))?;
    if payload
        .token
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
        && payload
            .code
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(AppError::BadRequest(
            "token or code is required".to_string(),
        ));
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Begin {identity_type} verification: {e}")))?;
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(ctx.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Set {identity_type} verification RLS context: {e}"))
        })?;

    let identity: Option<(String, bool)> = sqlx::query_as(
        r#"
        SELECT id, verified
        FROM identities
        WHERE organization_id = $1 AND user_id = $2 AND type = $3
        ORDER BY verified DESC, created_at ASC
        LIMIT 1
        "#,
    )
    .bind(ctx.tenant_id)
    .bind(ctx.user_id)
    .bind(identity_type)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Fetch {identity_type} identity: {e}")))?;

    let (identity_id, verified) = identity.ok_or_else(|| {
        AppError::BadRequest(format!(
            "No {identity_type} identity is registered for this user"
        ))
    })?;
    if verified {
        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Commit verified {identity_type}: {e}")))?;
        return Ok(());
    }

    let token = payload
        .token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let code = payload
        .code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let verification_token_id: Option<String> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM verification_tokens
        WHERE identity_id = $1
          AND used = FALSE
          AND expires_at > NOW()
          AND (($2::text IS NOT NULL AND token = $2) OR ($3::text IS NOT NULL AND code = $3))
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&identity_id)
    .bind(token)
    .bind(code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Verify {identity_type} token: {e}")))?;

    let verification_token_id = verification_token_id
        .ok_or_else(|| AppError::BadRequest("Invalid or expired verification code".to_string()))?;

    sqlx::query("UPDATE verification_tokens SET used = TRUE, used_at = NOW() WHERE id = $1")
        .bind(&verification_token_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Consume {identity_type} token: {e}")))?;

    sqlx::query(
        "UPDATE identities SET verified = TRUE, verified_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(&identity_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("Mark {identity_type} verified: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Commit {identity_type} verification: {e}")))?;
    Ok(())
}

fn is_production() -> bool {
    std::env::var("ENVIRONMENT").unwrap_or_default() == "production"
        || std::env::var("APP_ENV").unwrap_or_default() == "production"
}

fn generate_verification_code() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

fn generate_verification_token() -> String {
    use rand::distributions::Alphanumeric;

    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn mask_identifier(identity_type: &str, identifier: &str) -> String {
    if identity_type == "email" {
        if let Some((local, domain)) = identifier.split_once('@') {
            let first = local.chars().next().unwrap_or('*');
            return format!("{first}***@{domain}");
        }
    }

    let tail: String = identifier
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if tail.is_empty() {
        "***".to_string()
    } else {
        format!("***{tail}")
    }
}

pub struct ConfigureMfaRequiredAction;

#[async_trait]
impl RequiredAction for ConfigureMfaRequiredAction {
    fn code(&self) -> &'static str {
        "configure_mfa"
    }

    fn priority(&self) -> i32 {
        20
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        let has_factor: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM user_factors
                WHERE user_id = $1 AND tenant_id = $2 AND status IN ('active', 'verified')
                UNION ALL
                SELECT 1 FROM mfa_factors
                WHERE user_id = $1 AND enabled = TRUE AND verified = TRUE
                LIMIT 1
            )
            "#,
        )
        .bind(ctx.user_id)
        .bind(ctx.tenant_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Internal(format!("Evaluate configure_mfa action: {e}")))?;
        Ok(if has_factor {
            ActionStatus::Completed
        } else {
            ActionStatus::NotRequired
        })
    }
}

pub struct UpdatePasswordRequiredAction;

#[async_trait]
impl RequiredAction for UpdatePasswordRequiredAction {
    fn code(&self) -> &'static str {
        "update_password"
    }

    fn priority(&self) -> i32 {
        30
    }

    async fn evaluate(&self, db: &PgPool, ctx: &ActionContext<'_>) -> Result<ActionStatus> {
        // Surface this action when either:
        //   * the per-tenant policy has `force_rotation = TRUE`, OR
        //   * the user's `passwords.must_change` flag is set (admin trigger), OR
        //   * the policy sets `max_age_days` and the credential has aged past it.
        // LDAP-only users have no row in `passwords`; treat that as "no local
        // credential to expire".
        let mut conn = db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, ctx.tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set update-password RLS context".into()))?;

        let policy: Option<(bool, Option<i32>, bool)> = sqlx::query_as(
            r#"
            SELECT enabled, max_age_days, force_rotation
            FROM password_policies
            WHERE tenant_id = $1
            "#,
        )
        .bind(ctx.tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch password policy: {e}")))?;

        let cred: Option<(chrono::DateTime<chrono::Utc>, bool)> = sqlx::query_as(
            "SELECT password_changed_at, must_change FROM passwords WHERE user_id = $1",
        )
        .bind(ctx.user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch password row: {e}")))?;

        let Some((changed_at, must_change)) = cred else {
            return Ok(ActionStatus::NotRequired);
        };
        if must_change {
            return Ok(ActionStatus::Pending);
        }
        let Some((enabled, max_age_days, force_rotation)) = policy else {
            return Ok(ActionStatus::NotRequired);
        };
        if !enabled {
            return Ok(ActionStatus::NotRequired);
        }
        if force_rotation {
            return Ok(ActionStatus::Pending);
        }
        if let Some(days) = max_age_days {
            let age = chrono::Utc::now() - changed_at;
            if age > chrono::Duration::days(days as i64) {
                return Ok(ActionStatus::Pending);
            }
        }
        Ok(ActionStatus::NotRequired)
    }

    async fn complete(
        &self,
        db: &PgPool,
        ctx: &ActionContext<'_>,
        payload: serde_json::Value,
    ) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload {
            new_password: String,
        }

        let payload: Payload = serde_json::from_value(payload)
            .map_err(|_| AppError::BadRequest("newPassword is required".to_string()))?;

        let mut conn = db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("Acquire DB connection: {e}")))?;
        set_rls_context_on_conn(&mut conn, ctx.tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set update-password RLS context".into()))?;

        let policy = sqlx::query_as::<_, crate::services::PasswordPolicy>(
            r#"
            SELECT id, tenant_id, enabled, min_length, require_uppercase, require_lowercase,
                   require_digit, require_symbol, history_depth, max_age_days, force_rotation,
                   created_at, updated_at
            FROM password_policies
            WHERE tenant_id = $1
            "#,
        )
        .bind(ctx.tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch password policy: {e}")))?;

        if let Some(policy) = &policy {
            let errors = validate_password_against_policy(policy, &payload.new_password);
            if !errors.is_empty() {
                return Err(AppError::Validation(errors.join(", ")));
            }

            if policy.enabled && policy.history_depth > 0 {
                let history: Vec<(String,)> = sqlx::query_as(
                    r#"
                    SELECT password_hash
                    FROM password_history
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(ctx.user_id)
                .bind(policy.history_depth as i64)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| AppError::Internal(format!("Fetch password history: {e}")))?;

                for (hash,) in history {
                    if auth_core::verify_password(&payload.new_password, &hash)? {
                        return Err(AppError::BadRequest(format!(
                            "New password cannot match any of your last {} passwords",
                            policy.history_depth
                        )));
                    }
                }
            }
        }

        let password_hash = auth_core::hash_password(&payload.new_password)?;
        let mut tx = db
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Begin password update transaction: {e}")))?;
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(ctx.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Set password update RLS context: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO passwords (id, user_id, password_hash, created_at, password_changed_at, must_change)
            VALUES ($1, $2, $3, NOW(), NOW(), FALSE)
            ON CONFLICT (user_id)
            DO UPDATE SET password_hash = EXCLUDED.password_hash,
                          password_changed_at = NOW(),
                          must_change = FALSE
            "#,
        )
        .bind(generate_id("pass"))
        .bind(ctx.user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Update password: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO password_history (id, user_id, password_hash, created_at)
            VALUES ($1, $2, $3, NOW())
            "#,
        )
        .bind(generate_id("hist"))
        .bind(ctx.user_id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Insert password history: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Commit password update: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RequiredActionRegistry;

    #[test]
    fn default_registry_has_expected_actions() {
        let registry = RequiredActionRegistry::default_actions();
        assert_eq!(registry.len(), 4);
        assert!(registry.get("verify_email").is_some());
        assert!(registry.get("verify_phone").is_some());
        assert!(registry.get("configure_mfa").is_some());
        assert!(registry.get("update_password").is_some());
    }
}
