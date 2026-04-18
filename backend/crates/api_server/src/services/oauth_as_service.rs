//! OAuth 2.0 Authorization Server service.
//!
//! Handles authorization codes, client authentication, refresh tokens,
//! and token issuance. Integrates with EIAA capsule-based authorization.

use auth_core::{oauth_types::OAuthAccessTokenClaims, oauth_types::OAuthIdTokenClaims, JwtService};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::Rng;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared_types::{AppError, Result};
use sqlx::PgPool;
use std::sync::Arc;

// ─── Authorization Code Context ────────────────────────────────────────────────

/// Stored in Redis during the authorization flow (10-min TTL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub tenant_id: String,
    pub nonce: Option<String>,
}

/// Stored in Redis after the user authenticates and grants consent.
/// The authorization code maps to this context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeContext {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub user_id: String,
    pub session_id: String,
    pub tenant_id: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub created_at: i64,
    pub decision_ref: Option<String>,
    /// OIDC nonce from the authorization request — passed through to id_token.
    #[serde(default)]
    pub nonce: Option<String>,
}

// ─── Refresh Token Model ────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct OAuthRefreshToken {
    pub id: String,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub session_id: String,
    pub tenant_id: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
    pub replaced_by: Option<String>,
    pub decision_ref: Option<String>,
}

// ─── Consent Model ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OAuthConsent {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub tenant_id: String,
    pub scope: String,
    pub granted_at: chrono::DateTime<Utc>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
    pub decision_ref: Option<String>,
}

// ─── OAuth AS Service ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct OAuthAsService {
    db: PgPool,
    redis: ConnectionManager,
    jwt_service: Arc<JwtService>,
    issuer: String,
}

impl OAuthAsService {
    pub fn new(
        db: PgPool,
        redis: ConnectionManager,
        jwt_service: Arc<JwtService>,
        issuer: String,
    ) -> Self {
        Self {
            db,
            redis,
            jwt_service,
            issuer,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Authorization Flow
    // ═══════════════════════════════════════════════════════════════════════════

    /// Store OAuth authorization context in Redis when /oauth/authorize is hit.
    /// Returns the flow_id to pass through the EIAA auth flow.
    pub async fn start_authorization(&self, ctx: AuthorizationContext) -> Result<String> {
        let flow_id = shared_types::generate_id("oaf"); // oauth_auth_flow

        let redis_key = format!("oauth_authz:{flow_id}");
        let value = serde_json::to_string(&ctx)
            .map_err(|e| AppError::Internal(format!("Serialize auth context: {e}")))?;

        let mut conn = self.redis.clone();
        redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(600i64) // 10-minute TTL
            .arg(&value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX: {e}")))?;

        Ok(flow_id)
    }

    /// Load the authorization context from Redis (used after EIAA auth completes).
    pub async fn load_authorization_context(
        &self,
        flow_id: &str,
    ) -> Result<Option<AuthorizationContext>> {
        let redis_key = format!("oauth_authz:{flow_id}");
        let mut conn = self.redis.clone();

        let raw: Option<String> = redis::cmd("GET")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET: {e}")))?;

        match raw {
            Some(json) => {
                let ctx: AuthorizationContext = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(format!("Deserialize auth context: {e}")))?;
                Ok(Some(ctx))
            }
            None => Ok(None),
        }
    }

    /// Delete the authorization context from Redis (consumed after code issuance).
    pub async fn consume_authorization_context(&self, flow_id: &str) -> Result<()> {
        let redis_key = format!("oauth_authz:{flow_id}");
        let mut conn = self.redis.clone();
        redis::cmd("DEL")
            .arg(&redis_key)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis DEL: {e}")))?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Authorization Code
    // ═══════════════════════════════════════════════════════════════════════════

    /// Generate an authorization code and store it in Redis.
    /// Returns the raw code to send to the client via redirect.
    pub async fn create_authorization_code(&self, ctx: AuthorizationCodeContext) -> Result<String> {
        // Generate high-entropy code: oac_{base64url(32 random bytes)}
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let code = format!("oac_{}", URL_SAFE_NO_PAD.encode(bytes));

        let code_hash = Self::hash_value(&code);
        let redis_key = format!("oauth_code:{code_hash}");
        let value = serde_json::to_string(&ctx)
            .map_err(|e| AppError::Internal(format!("Serialize code context: {e}")))?;

        let mut conn = self.redis.clone();
        redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(600i64) // RFC 6749 §4.1.2: max 10 minutes
            .arg(&value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX code: {e}")))?;

        Ok(code)
    }

    /// Consume an authorization code (single-use). Returns the bound context.
    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeContext>> {
        let code_hash = Self::hash_value(code);
        let redis_key = format!("oauth_code:{code_hash}");
        let mut conn = self.redis.clone();

        // Atomically read and delete the code using Lua for Redis compatibility.
        let raw: Option<String> = redis::cmd("EVAL")
            .arg("local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); end; return v")
            .arg(1)
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis atomic GET+DEL code: {e}")))?;

        match raw {
            Some(json) => {
                let ctx: AuthorizationCodeContext = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(format!("Deserialize code context: {e}")))?;
                Ok(Some(ctx))
            }
            None => Ok(None),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PKCE Validation
    // ═══════════════════════════════════════════════════════════════════════════

    /// Validate PKCE code_verifier against stored code_challenge (S256).
    pub fn validate_pkce(code_verifier: &str, code_challenge: &str) -> bool {
        let digest = Sha256::digest(code_verifier.as_bytes());
        let computed = URL_SAFE_NO_PAD.encode(digest);
        // Use constant-time comparison
        use subtle::ConstantTimeEq;
        computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Client Authentication
    // ═══════════════════════════════════════════════════════════════════════════

    /// Authenticate a client by client_id + client_secret.
    /// Returns the Application if authentication succeeds.
    pub async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: &str,
        tenant_id: &str,
    ) -> Result<org_manager::Application> {
        let app = sqlx::query_as::<_, org_manager::Application>(
            "SELECT * FROM applications WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error looking up client: {e}")))?
        .ok_or_else(|| AppError::Unauthorized("invalid_client".into()))?;

        // Verify secret: SHA-256(presented) == stored hash (constant-time)
        let presented_hash = Self::hash_value(client_secret);
        let stored_hash = app
            .client_secret_hash
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("Client has no secret".into()))?;

        use subtle::ConstantTimeEq;
        if presented_hash
            .as_bytes()
            .ct_eq(stored_hash.as_bytes())
            .into()
        {
            Ok(app)
        } else {
            Err(AppError::Unauthorized("invalid_client".into()))
        }
    }

    /// Look up client by client_id only (for public client validation at /authorize).
    pub async fn get_client_by_client_id(
        &self,
        client_id: &str,
        tenant_id: &str,
    ) -> Result<org_manager::Application> {
        sqlx::query_as::<_, org_manager::Application>(
            "SELECT * FROM applications WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error: {e}")))?
        .ok_or_else(|| AppError::BadRequest("Unknown client_id".into()))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Token Issuance
    // ═══════════════════════════════════════════════════════════════════════════

    /// Issue an OAuth access token (ES256 JWT).
    pub fn issue_access_token(
        &self,
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        expires_in_secs: i64,
    ) -> Result<String> {
        let claims = OAuthAccessTokenClaims::for_user(
            user_id,
            session_id,
            tenant_id,
            client_id,
            scope,
            &self.issuer,
            expires_in_secs,
        );

        self.jwt_service.sign_claims(&claims)
    }

    /// Issue a client_credentials access token (no user).
    pub fn issue_client_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        expires_in_secs: i64,
    ) -> Result<String> {
        let claims = OAuthAccessTokenClaims::for_client(
            tenant_id,
            client_id,
            scope,
            &self.issuer,
            expires_in_secs,
        );
        self.jwt_service.sign_claims(&claims)
    }

    /// Issue an OIDC ID Token (ES256 JWT) per OIDC Core §3.1.3.6.
    /// Only called when the granted scope includes "openid".
    pub async fn issue_id_token(
        &self,
        user_id: &str,
        client_id: &str,
        nonce: Option<&str>,
        access_token: &str,
        scope: &str,
        expires_in_secs: i64,
    ) -> Result<String> {
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::seconds(expires_in_secs);

        let scopes: std::collections::HashSet<&str> = scope.split_whitespace().collect();

        // Fetch profile + email claims from DB when the corresponding scopes are granted.
        let (given_name, family_name, name, picture, email, email_verified) =
            if scopes.contains("profile") || scopes.contains("email") {
                self.fetch_user_claims(user_id, &scopes).await?
            } else {
                (None, None, None, None, None, None)
            };

        let claims = OAuthIdTokenClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            nonce: nonce.map(|n| n.to_string()),
            at_hash: Some(OAuthIdTokenClaims::compute_at_hash(access_token)),
            name,
            given_name,
            family_name,
            picture,
            email,
            email_verified,
        };

        self.jwt_service.sign_claims(&claims)
    }

    /// Fetch user profile and email claims from DB for id_token population.
    async fn fetch_user_claims(
        &self,
        user_id: &str,
        scopes: &std::collections::HashSet<&str>,
    ) -> Result<(
        Option<String>, // given_name
        Option<String>, // family_name
        Option<String>, // name
        Option<String>, // picture
        Option<String>, // email
        Option<bool>,   // email_verified
    )> {
        let mut given_name = None;
        let mut family_name = None;
        let mut name = None;
        let mut picture = None;
        let mut email = None;
        let mut email_verified = None;

        if scopes.contains("profile") {
            let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT first_name, last_name, profile_image_url FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Internal(format!("Fetch user profile: {e}")))?;

            if let Some((first, last, pic)) = row {
                given_name = first.clone();
                family_name = last.clone();
                let full = format!(
                    "{} {}",
                    first.as_deref().unwrap_or(""),
                    last.as_deref().unwrap_or("")
                )
                .trim()
                .to_string();
                if !full.is_empty() {
                    name = Some(full);
                }
                picture = pic;
            }
        }

        if scopes.contains("email") {
            let row: Option<(String, bool)> = sqlx::query_as(
                "SELECT identifier, verified FROM identities WHERE user_id = $1 AND type = 'email' LIMIT 1",
            )
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Internal(format!("Fetch user email: {e}")))?;

            if let Some((addr, verified)) = row {
                email = Some(addr);
                email_verified = Some(verified);
            }
        }

        Ok((
            given_name,
            family_name,
            name,
            picture,
            email,
            email_verified,
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Refresh Tokens
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a new refresh token, store its hash in the database.
    /// Returns the raw token string to send to the client.
    pub async fn create_refresh_token(
        &self,
        client_id: &str,
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        scope: &str,
        lifetime_secs: i64,
        decision_ref: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<String> {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let mut bytes2 = [0u8; 8];
        rand::thread_rng().fill(&mut bytes2);
        let raw_token = format!(
            "ort_{}{}",
            URL_SAFE_NO_PAD.encode(bytes),
            URL_SAFE_NO_PAD.encode(bytes2)
        );
        let token_hash = Self::hash_value(&raw_token);
        let id = shared_types::generate_id("ort");
        let expires_at = Utc::now() + Duration::seconds(lifetime_secs);

        sqlx::query(
            r#"
            INSERT INTO oauth_refresh_tokens
                (id, token_hash, client_id, user_id, session_id, tenant_id, scope, expires_at, decision_ref, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::inet, $11)
            "#,
        )
        .bind(&id)
        .bind(&token_hash)
        .bind(client_id)
        .bind(user_id)
        .bind(session_id)
        .bind(tenant_id)
        .bind(scope)
        .bind(expires_at)
        .bind(decision_ref)
        .bind(ip_address)
        .bind(user_agent)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Create refresh token: {e}")))?;

        Ok(raw_token)
    }

    /// Validate and consume a refresh token (one-time use with rotation).
    /// Returns the old token's metadata.
    pub async fn consume_refresh_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<OAuthRefreshToken>> {
        let token_hash = Self::hash_value(raw_token);

        let row = sqlx::query_as::<_, OAuthRefreshToken>(
            r#"
            SELECT * FROM oauth_refresh_tokens
            WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Lookup refresh token: {e}")))?;

        match row {
            Some(rt) => {
                // Revoke the old token (one-time use)
                sqlx::query("UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE id = $1")
                    .bind(&rt.id)
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Internal(format!("Revoke refresh token: {e}")))?;

                Ok(Some(rt))
            }
            None => {
                // Check if this is a revoked token — potential reuse attack!
                let revoked = sqlx::query_as::<_, OAuthRefreshToken>(
                    "SELECT * FROM oauth_refresh_tokens WHERE token_hash = $1 AND revoked_at IS NOT NULL",
                )
                .bind(&token_hash)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Internal(format!("Check revoked token: {e}")))?;

                if let Some(revoked_rt) = revoked {
                    // Grace period: if the token was revoked < 5 seconds ago, this is
                    // likely a network retry, not a stolen-token replay attack.
                    // Only trigger family revocation after the grace window.
                    let grace_secs = 5;
                    let recently_revoked = revoked_rt
                        .revoked_at
                        .map(|ra| (Utc::now() - ra).num_seconds() < grace_secs)
                        .unwrap_or(false);

                    if recently_revoked {
                        tracing::info!(
                            client_id = %revoked_rt.client_id,
                            "Refresh token reuse within grace period — ignoring (likely network retry)"
                        );
                    } else {
                        // REUSE DETECTED outside grace window: Revoke the entire token family
                        tracing::warn!(
                            client_id = %revoked_rt.client_id,
                            user_id = %revoked_rt.user_id,
                            "Refresh token reuse detected — revoking entire token family"
                        );
                        self.revoke_token_family(
                            &revoked_rt.client_id,
                            &revoked_rt.user_id,
                            &revoked_rt.tenant_id,
                        )
                        .await?;
                    }
                }
                Ok(None)
            }
        }
    }

    /// Revoke all refresh tokens for a client+user combination (family revocation).
    pub async fn revoke_token_family(
        &self,
        client_id: &str,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE oauth_refresh_tokens
            SET revoked_at = NOW()
            WHERE client_id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
            "#,
        )
        .bind(client_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Revoke token family: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Revoke a single token by its raw value.
    pub async fn revoke_token(&self, raw_token: &str) -> Result<bool> {
        let token_hash = Self::hash_value(raw_token);
        let result = sqlx::query(
            "UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(&token_hash)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Revoke token: {e}")))?;

        Ok(result.rows_affected() > 0)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JWT Access Token Blocklist (Redis-backed)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Add a JWT access token to the blocklist.
    /// The token is stored by its SHA-256 hash with a TTL equal to its remaining lifetime.
    /// After the token's natural expiry the blocklist entry auto-evicts.
    pub async fn blocklist_access_token(&self, token: &str, exp: i64) -> Result<bool> {
        let remaining_secs = exp - Utc::now().timestamp();
        if remaining_secs <= 0 {
            // Token already expired — nothing to blocklist
            return Ok(false);
        }

        let token_hash = Self::hash_value(token);
        let redis_key = format!("oauth_blocklist:{token_hash}");
        let mut conn = self.redis.clone();

        redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(remaining_secs)
            .arg("1")
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX blocklist: {e}")))?;

        Ok(true)
    }

    /// Check if an access token has been revoked (blocklisted).
    pub async fn is_access_token_blocklisted(&self, token: &str) -> bool {
        let token_hash = Self::hash_value(token);
        let redis_key = format!("oauth_blocklist:{token_hash}");
        let mut conn = self.redis.clone();

        let exists: bool = redis::cmd("EXISTS")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .unwrap_or(false);

        exists
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Consent Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Check if user has already consented to the requested scopes for this client.
    pub async fn check_consent(
        &self,
        user_id: &str,
        client_id: &str,
        tenant_id: &str,
        requested_scope: &str,
    ) -> Result<bool> {
        let consent = sqlx::query_as::<_, OAuthConsent>(
            r#"
            SELECT * FROM oauth_consents
            WHERE user_id = $1 AND client_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Check consent: {e}")))?;

        match consent {
            Some(c) => {
                // Check if all requested scopes are covered by existing consent
                let consented: std::collections::HashSet<&str> =
                    c.scope.split_whitespace().collect();
                let requested: std::collections::HashSet<&str> =
                    requested_scope.split_whitespace().collect();
                Ok(requested.is_subset(&consented))
            }
            None => Ok(false),
        }
    }

    /// Record user consent for a client's requested scopes.
    pub async fn grant_consent(
        &self,
        user_id: &str,
        client_id: &str,
        tenant_id: &str,
        scope: &str,
        decision_ref: Option<&str>,
    ) -> Result<OAuthConsent> {
        let id = shared_types::generate_id("ocs");
        let consent = sqlx::query_as::<_, OAuthConsent>(
            r#"
            INSERT INTO oauth_consents (id, user_id, client_id, tenant_id, scope, decision_ref)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT ON CONSTRAINT uq_oauth_consent_user_client_tenant
            DO UPDATE SET scope = EXCLUDED.scope, granted_at = NOW(), revoked_at = NULL, decision_ref = EXCLUDED.decision_ref
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(client_id)
        .bind(tenant_id)
        .bind(scope)
        .bind(decision_ref)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Grant consent: {e}")))?;

        Ok(consent)
    }

    /// List all active consents for a user (consent management UI).
    #[allow(dead_code)]
    pub async fn list_user_consents(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<Vec<OAuthConsent>> {
        let consents = sqlx::query_as::<_, OAuthConsent>(
            "SELECT * FROM oauth_consents WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL ORDER BY granted_at DESC",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("List consents: {e}")))?;

        Ok(consents)
    }

    /// Revoke consent (and all associated refresh tokens).
    #[allow(dead_code)]
    pub async fn revoke_consent(
        &self,
        user_id: &str,
        client_id: &str,
        tenant_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE oauth_consents SET revoked_at = NOW() WHERE user_id = $1 AND client_id = $2 AND tenant_id = $3 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Revoke consent: {e}")))?;

        // Also revoke all refresh tokens for this client+user
        self.revoke_token_family(client_id, user_id, tenant_id)
            .await?;

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    fn hash_value(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validate that redirect_uri exactly matches one of the registered URIs.
    pub fn validate_redirect_uri(app: &org_manager::Application, redirect_uri: &str) -> bool {
        if let Some(uris) = app.redirect_uris.as_array() {
            uris.iter()
                .any(|u| u.as_str().map_or(false, |s| s == redirect_uri))
        } else {
            false
        }
    }

    /// Check if a grant type is allowed for this application.
    pub fn is_flow_allowed(app: &org_manager::Application, grant_type: &str) -> bool {
        if let Some(flows) = app.allowed_flows.as_array() {
            flows
                .iter()
                .any(|f| f.as_str().map_or(false, |s| s == grant_type))
        } else {
            false
        }
    }

    /// Get allowed scopes for an application, intersected with requested scopes.
    pub fn resolve_scopes(app: &org_manager::Application, requested: &str) -> String {
        let allowed: std::collections::HashSet<String> = app
            .allowed_scopes
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| {
                org_manager::DEFAULT_SCOPES
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });

        let requested_scopes: Vec<&str> = requested.split_whitespace().collect();

        if requested_scopes.is_empty() {
            // Default scopes
            return allowed.into_iter().collect::<Vec<_>>().join(" ");
        }

        requested_scopes
            .into_iter()
            .filter(|s| allowed.contains(*s))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Check if PKCE is required for this application.
    pub fn is_pkce_required(app: &org_manager::Application) -> bool {
        app.public_config
            .get("enforce_pkce")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || app.r#type == "mobile" // Always require PKCE for mobile/SPA
    }
}
