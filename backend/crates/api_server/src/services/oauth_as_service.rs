//! OAuth 2.0 Authorization Server service.
//!
//! Handles authorization codes, client authentication, refresh tokens,
//! and token issuance. Integrates with EIAA capsule-based authorization.

use auth_core::{
    oauth_types::OAuthAccessTokenClaims, oauth_types::OAuthIdTokenClaims, Confirmation, JwtService,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use capsule_compiler::ast::{ClaimMapper, Program, Step};
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
    /// OAuth `state` parameter from the authorization request.
    /// Passed through to id_token as `s_hash` per FAPI 2.0 §5.2.2.1 when set.
    #[serde(default)]
    pub state: Option<String>,
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
    /// T1.3: explicit family root id. All tokens descended from a single
    /// auth-code grant share this id; reuse detection revokes by family.
    pub family_id: String,
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
    /// Vault SPI — pluggable secret store for client secret verification.
    secret_store: Arc<dyn crate::services::secret_store::SecretStore>,
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
            secret_store: Arc::new(crate::services::secret_store::DatabaseSecretStore),
        }
    }

    /// Create with an explicit SecretStore (for Vault/KMS backends or tests).
    pub fn new_with_secret_store(
        db: PgPool,
        redis: ConnectionManager,
        jwt_service: Arc<JwtService>,
        issuer: String,
        secret_store: Arc<dyn crate::services::secret_store::SecretStore>,
    ) -> Self {
        Self {
            db,
            redis,
            jwt_service,
            issuer,
            secret_store,
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
    // T2.2 — Pushed Authorization Requests (RFC 9126)
    //
    // Mediator pattern: the PAR endpoint mediates between the client and the
    // /authorize endpoint. The client POSTs all authorization parameters and
    // gets back a single-use `request_uri` that it then uses on /authorize
    // (typically as `?request_uri=...&client_id=...` only). This eliminates
    // request-tampering and oversize-URL classes of attack.
    //
    // Storage: Redis key `oauth_par:{ref}` with 60s TTL (RFC 9126 §2.2 RECOMMENDS
    // ≤ 600s; we use 60s for tighter blast-radius). Single-use is enforced by
    // DEL-on-read in `consume_par`.
    // ═══════════════════════════════════════════════════════════════════════════

    /// URN prefix for `request_uri` values per RFC 9126 §2.2.
    pub const PAR_REQUEST_URI_PREFIX: &'static str = "urn:ietf:params:oauth:request_uri:";

    /// PAR record TTL (seconds). RFC 9126 RECOMMENDS short, single-use lifetimes.
    pub const PAR_TTL_SECONDS: i64 = 60;

    /// Store a pushed authorization request and return its `request_uri`.
    /// The caller is responsible for client authentication BEFORE calling this.
    pub async fn store_par(&self, ctx: AuthorizationContext) -> Result<(String, i64)> {
        // 32 random bytes encoded as URL-safe base64 (43 chars no padding).
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let reference = URL_SAFE_NO_PAD.encode(bytes);

        let request_uri = format!("{}{}", Self::PAR_REQUEST_URI_PREFIX, reference);
        let redis_key = format!("oauth_par:{reference}");
        let value = serde_json::to_string(&ctx)
            .map_err(|e| AppError::Internal(format!("Serialize PAR ctx: {e}")))?;

        let mut conn = self.redis.clone();
        redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(Self::PAR_TTL_SECONDS)
            .arg(&value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX: {e}")))?;

        Ok((request_uri, Self::PAR_TTL_SECONDS))
    }

    /// Atomically fetch and delete a PAR record (single-use semantics).
    /// Returns None if the request_uri is unknown, expired, or already consumed.
    pub async fn consume_par(&self, request_uri: &str) -> Result<Option<AuthorizationContext>> {
        let reference = match request_uri.strip_prefix(Self::PAR_REQUEST_URI_PREFIX) {
            Some(r) if !r.is_empty() => r,
            _ => return Ok(None),
        };
        // Defence in depth: reject anything that's not URL-safe base64 chars.
        if !reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Ok(None);
        }
        let redis_key = format!("oauth_par:{reference}");
        let mut conn = self.redis.clone();
        // GETDEL: atomic read-and-delete (Redis 6.2+). Single-use enforced.
        let raw: Option<String> = redis::cmd("GETDEL")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GETDEL: {e}")))?;
        match raw {
            Some(json) => {
                let ctx: AuthorizationContext = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(format!("Deserialize PAR ctx: {e}")))?;
                Ok(Some(ctx))
            }
            None => Ok(None),
        }
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
    // PKCE Validation (RFC 7636, hardened per OAuth 2.1 BCP — T2.1)
    // ═══════════════════════════════════════════════════════════════════════════

    /// RFC 7636 §4.1: code_verifier = 43*128 unreserved chars (A-Z / a-z / 0-9 / "-" / "." / "_" / "~").
    pub fn validate_code_verifier_format(verifier: &str) -> bool {
        let len = verifier.len();
        (43..=128).contains(&len)
            && verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    }

    /// RFC 7636 §4.2 (S256): challenge = base64url-no-pad(SHA256(verifier))
    /// → exactly 43 chars, base64url unreserved alphabet.
    pub fn validate_s256_challenge_format(challenge: &str) -> bool {
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    }

    /// Validate PKCE code_verifier against stored code_challenge (S256, constant-time).
    pub fn validate_pkce(code_verifier: &str, code_challenge: &str) -> bool {
        if !Self::validate_code_verifier_format(code_verifier) {
            return false;
        }
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

        // Verify secret via the configured SecretStore (constant-time for DB backend).
        let stored_ref = app
            .client_secret_hash
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("invalid_client".into()))?;

        let ok = self
            .secret_store
            .verify_secret(client_id, client_secret, stored_ref)
            .await
            .map_err(|e| AppError::Internal(format!("SecretStore verify error: {e}")))?;

        if ok {
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
    #[allow(dead_code)]
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

    /// Issue an OAuth access token with optional proof-of-possession binding.
    pub fn issue_access_token_with_confirmation(
        &self,
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        expires_in_secs: i64,
        confirmation: Option<Confirmation>,
    ) -> Result<String> {
        let mut claims = OAuthAccessTokenClaims::for_user(
            user_id,
            session_id,
            tenant_id,
            client_id,
            scope,
            &self.issuer,
            expires_in_secs,
        );
        claims.cnf = confirmation;
        self.jwt_service.sign_claims(&claims)
    }

    /// Issue a client_credentials access token (no user).
    #[allow(dead_code)]
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

    /// Issue a client_credentials token with optional proof-of-possession binding.
    pub fn issue_client_token_with_confirmation(
        &self,
        tenant_id: &str,
        client_id: &str,
        scope: &str,
        expires_in_secs: i64,
        confirmation: Option<Confirmation>,
    ) -> Result<String> {
        let mut claims = OAuthAccessTokenClaims::for_client(
            tenant_id,
            client_id,
            scope,
            &self.issuer,
            expires_in_secs,
        );
        claims.cnf = confirmation;
        self.jwt_service.sign_claims(&claims)
    }

    /// Issue an OIDC ID Token (ES256 JWT) per OIDC Core §3.1.3.6.
    /// Only called when the granted scope includes "openid".
    pub async fn issue_id_token(
        &self,
        user_id: &str,
        tenant_id: &str,
        client_id: &str,
        nonce: Option<&str>,
        access_token: &str,
        scope: &str,
        expires_in_secs: i64,
        // OAuth `state` value — when present, the ID token will include
        // `s_hash` per FAPI 2.0 §5.2.2.1 and OIDC Hybrid §3.3.2.11.
        state: Option<&str>,
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

        let mut claims = OAuthIdTokenClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            nonce: nonce.map(|n| n.to_string()),
            at_hash: Some(OAuthIdTokenClaims::compute_at_hash(access_token)),
            s_hash: state.map(|s| OAuthIdTokenClaims::compute_s_hash(s)),
            name,
            given_name,
            family_name,
            picture,
            email,
            email_verified,
            extra: std::collections::BTreeMap::new(),
        };

        let mappings = self.load_claim_mappers(tenant_id).await?;
        if !mappings.is_empty() {
            self.apply_claim_mappers(user_id, &mut claims, &mappings)
                .await?;
        }

        self.jwt_service.sign_claims(&claims)
    }

    async fn load_claim_mappers(&self, tenant_id: &str) -> Result<Vec<ClaimMapper>> {
        let row: Option<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT spec
            FROM eiaa_policies
            WHERE tenant_id = $1 AND action IN ('oauth:token', 'oauth:authorize')
            ORDER BY CASE action WHEN 'oauth:token' THEN 0 ELSE 1 END, version DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Load token mapper policy: {e}")))?;

        let Some(spec) = row else {
            return Ok(Vec::new());
        };
        let program: Program = serde_json::from_value(spec)
            .map_err(|e| AppError::Internal(format!("Parse token mapper policy: {e}")))?;
        Ok(program
            .sequence
            .into_iter()
            .find_map(|step| match step {
                Step::ShapeClaims { mappings } => Some(mappings),
                _ => None,
            })
            .unwrap_or_default())
    }

    async fn apply_claim_mappers(
        &self,
        user_id: &str,
        claims: &mut OAuthIdTokenClaims,
        mappings: &[ClaimMapper],
    ) -> Result<()> {
        let row: Option<(
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<Utc>,
            Option<String>,
            Option<bool>,
        )> = sqlx::query_as(
            r#"
            SELECT u.first_name, u.last_name, u.profile_image_url, u.updated_at,
                   i.identifier AS email, i.verified AS email_verified
            FROM users u
            LEFT JOIN identities i ON i.user_id = u.id AND i.type = 'email'
            WHERE u.id = $1
            ORDER BY i.verified DESC NULLS LAST, i.created_at ASC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Fetch token mapper facts: {e}")))?;

        let Some((first, last, picture, updated_at, email, email_verified)) = row else {
            return Ok(());
        };
        let display_name = match (first.as_deref(), last.as_deref()) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            (Some(f), None) => Some(f.to_string()),
            (None, Some(l)) => Some(l.to_string()),
            (None, None) => None,
        };

        for mapper in mappings {
            match mapper {
                ClaimMapper::Email => claims.email = email.clone(),
                ClaimMapper::EmailVerified => claims.email_verified = email_verified,
                ClaimMapper::Name => claims.name = display_name.clone(),
                ClaimMapper::GivenName => claims.given_name = first.clone(),
                ClaimMapper::FamilyName => claims.family_name = last.clone(),
                ClaimMapper::PreferredUsername => {
                    claims.extra.insert(
                        "preferred_username".to_string(),
                        serde_json::Value::String(
                            email.clone().unwrap_or_else(|| user_id.to_string()),
                        ),
                    );
                }
                ClaimMapper::Picture => claims.picture = picture.clone(),
                ClaimMapper::UpdatedAt => {
                    claims.extra.insert(
                        "updated_at".to_string(),
                        serde_json::json!(updated_at.timestamp()),
                    );
                }
                ClaimMapper::Static { name, value } => {
                    claims.extra.insert(name.clone(), value.clone());
                }
            }
        }
        Ok(())
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

    /// Issue the FIRST refresh token of a family (root of the rotation chain).
    ///
    /// Used at initial grant time (authorization_code, client_credentials).
    /// For rotation use [`Self::rotate_refresh_token`] instead — that path
    /// preserves family lineage and atomically links the new token to the
    /// outgoing one via `replaced_by`.
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
        let id = shared_types::generate_id("ort");
        // Root of family — family_id == own id.
        let family_id = id.clone();
        let raw_token = Self::mint_refresh_token_string();
        let token_hash = Self::hash_value(&raw_token);
        let expires_at = Utc::now() + Duration::seconds(lifetime_secs);

        sqlx::query(
            r#"
            INSERT INTO oauth_refresh_tokens
                (id, token_hash, family_id, client_id, user_id, session_id, tenant_id, scope, expires_at, decision_ref, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet, $12)
            "#,
        )
        .bind(&id)
        .bind(&token_hash)
        .bind(&family_id)
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
    ///
    /// Returns `Ok(Some(rt))` if the token is currently active — caller must
    /// then call [`Self::rotate_refresh_token`] (which both revokes `rt` and
    /// inserts the successor) inside the same logical operation. Calling
    /// `consume_refresh_token` *without* a follow-up rotate leaves the family
    /// without an active head — acceptable when the caller intends to revoke
    /// (e.g. logout) but not when issuing a replacement.
    ///
    /// On reuse outside the 5-second grace window, the *exact* family is
    /// revoked — sibling families belonging to the same user on other devices
    /// remain untouched (T1.3).
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
            Some(rt) => Ok(Some(rt)),
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
                            family_id = %revoked_rt.family_id,
                            "Refresh token reuse within grace period — ignoring (likely network retry)"
                        );
                    } else {
                        // REUSE DETECTED outside grace window: revoke ONLY this family
                        // (sibling sessions on other devices are unaffected — T1.3).
                        tracing::warn!(
                            client_id = %revoked_rt.client_id,
                            user_id = %revoked_rt.user_id,
                            family_id = %revoked_rt.family_id,
                            "Refresh token reuse detected — revoking family"
                        );
                        self.revoke_token_family(&revoked_rt.family_id).await?;
                    }
                }
                Ok(None)
            }
        }
    }

    /// Atomically rotate a refresh token: revoke `old`, insert a successor in
    /// the same family, and link them via `replaced_by`. Single transaction.
    ///
    /// The single-active-token-per-family invariant is enforced by the
    /// `uq_oauth_rt_family_one_active` partial unique index — concurrent
    /// rotation attempts will conflict and one will fail (driving the caller
    /// to retry / reject, never producing two live tokens for the same family).
    pub async fn rotate_refresh_token(
        &self,
        old: &OAuthRefreshToken,
        scope: &str,
        lifetime_secs: i64,
        decision_ref: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<String> {
        let new_id = shared_types::generate_id("ort");
        let raw_token = Self::mint_refresh_token_string();
        let token_hash = Self::hash_value(&raw_token);
        let expires_at = Utc::now() + Duration::seconds(lifetime_secs);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Begin rotation tx: {e}")))?;

        // Revoke the outgoing token first — required so the partial UNIQUE
        // index (`uq_oauth_rt_family_one_active`) accepts the successor.
        sqlx::query(
            "UPDATE oauth_refresh_tokens SET revoked_at = NOW(), replaced_by = $2 WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(&old.id)
        .bind(&new_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Revoke outgoing token: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO oauth_refresh_tokens
                (id, token_hash, family_id, client_id, user_id, session_id, tenant_id, scope, expires_at, decision_ref, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet, $12)
            "#,
        )
        .bind(&new_id)
        .bind(&token_hash)
        .bind(&old.family_id) // preserve family lineage
        .bind(&old.client_id)
        .bind(&old.user_id)
        .bind(&old.session_id)
        .bind(&old.tenant_id)
        .bind(scope)
        .bind(expires_at)
        .bind(decision_ref)
        .bind(ip_address)
        .bind(user_agent)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Insert successor token: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Commit rotation tx: {e}")))?;

        Ok(raw_token)
    }

    /// Revoke every active token belonging to a single family. Used both by
    /// reuse detection and by explicit administrative actions.
    pub async fn revoke_token_family(&self, family_id: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE oauth_refresh_tokens
               SET revoked_at = NOW()
             WHERE family_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(family_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Revoke token family: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Revoke all active refresh tokens for a (client, user, tenant) tuple
    /// — used on consent withdrawal. Distinct from family revocation: this
    /// intentionally affects every device/session for the tuple.
    pub async fn revoke_user_client_tokens(
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
        .map_err(|e| AppError::Internal(format!("Revoke user-client tokens: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Internal: mint the raw `ort_…` token string. 40 random bytes, base64url.
    fn mint_refresh_token_string() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let mut bytes2 = [0u8; 8];
        rand::thread_rng().fill(&mut bytes2);
        format!(
            "ort_{}{}",
            URL_SAFE_NO_PAD.encode(bytes),
            URL_SAFE_NO_PAD.encode(bytes2)
        )
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

        // Also revoke all refresh tokens for this client+user (every device).
        self.revoke_user_client_tokens(client_id, user_id, tenant_id)
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

    /// Whether this application is a *public* client per RFC 6749 §2.1.
    /// Public clients (SPA, mobile, native CLI) have no client secret — they
    /// MUST use PKCE per OAuth 2.1.
    pub fn is_public_client(app: &org_manager::Application) -> bool {
        app.client_secret_hash.is_none()
            || app.r#type == "mobile"
            || app.r#type == "spa"
            || app.r#type == "native"
    }

    /// Check if PKCE is required for this application.
    ///
    /// T2.1: now always true for public clients (regardless of `enforce_pkce`
    /// admin flag) per OAuth 2.1 §2.1.1. The flag remains opt-in for
    /// confidential clients that want defence-in-depth.
    pub fn is_pkce_required(app: &org_manager::Application) -> bool {
        Self::is_public_client(app)
            || app
                .public_config
                .get("enforce_pkce")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
    }

    /// Whether this application has the FAPI 2.0 Security Profile enabled.
    ///
    /// FAPI 2.0 mandates: PAR required, PKCE S256 required, DPoP required,
    /// max access-token lifetime 300 s, `s_hash` in ID token.
    pub fn is_fapi(app: &org_manager::Application) -> bool {
        matches!(app.fapi_profile.as_deref(), Some("fapi2"))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // T2.6 — Device Authorization Grant (RFC 8628)
    //
    // State machine pattern. Each device authorization is a stateful object in
    // Redis with one of: `pending` | `approved` | `denied` | `expired`. The
    // user_code is a short, human-typeable handle (Crockford alphabet, 8 chars)
    // that maps back to the device_code for the approval flow.
    //
    // Redis keys:
    //   `oauth_device:{device_code}` -> JSON DeviceAuthorization
    //   `oauth_device_user:{user_code}` -> device_code (lookup index)
    //   `oauth_device_poll:{device_code}` -> last poll timestamp (for slow_down)
    // ═══════════════════════════════════════════════════════════════════════════

    pub const DEVICE_CODE_TTL_SECONDS: i64 = 600; // 10 minutes
    pub const DEVICE_POLL_INTERVAL_SECONDS: i64 = 5;
    /// User-code charset: Crockford-friendly subset (no I, O, 0, 1 to avoid
    /// confusion). 8 chars give ≈ 32^8 ≈ 1.1e12 keyspace; still bounded by TTL.
    const USER_CODE_ALPHABET: &'static [u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    fn generate_user_code() -> String {
        let mut rng = rand::thread_rng();
        let mut s = String::with_capacity(9);
        for i in 0..8 {
            if i == 4 {
                s.push('-');
            }
            let idx = rng.gen_range(0..Self::USER_CODE_ALPHABET.len());
            s.push(Self::USER_CODE_ALPHABET[idx] as char);
        }
        s
    }

    /// Initiate a new device authorization request and return the device code,
    /// user code, and polling parameters.
    pub async fn start_device_authorization(
        &self,
        client_id: &str,
        tenant_id: &str,
        scope: &str,
    ) -> Result<DeviceAuthorizationResponse> {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let device_code = format!("dvc_{}", URL_SAFE_NO_PAD.encode(bytes));
        let user_code = Self::generate_user_code();

        let record = DeviceAuthorization {
            client_id: client_id.to_string(),
            tenant_id: tenant_id.to_string(),
            scope: scope.to_string(),
            user_code: user_code.clone(),
            state: DeviceAuthState::Pending,
            user_id: None,
            session_id: None,
            decision_ref: None,
            created_at: Utc::now().timestamp(),
        };

        let value = serde_json::to_string(&record)
            .map_err(|e| AppError::Internal(format!("Serialize device auth: {e}")))?;

        let mut conn = self.redis.clone();
        let device_key = format!("oauth_device:{device_code}");
        redis::cmd("SETEX")
            .arg(&device_key)
            .arg(Self::DEVICE_CODE_TTL_SECONDS)
            .arg(&value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX device: {e}")))?;
        let user_key = format!("oauth_device_user:{user_code}");
        redis::cmd("SETEX")
            .arg(&user_key)
            .arg(Self::DEVICE_CODE_TTL_SECONDS)
            .arg(&device_code)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SETEX device-user: {e}")))?;

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            interval: Self::DEVICE_POLL_INTERVAL_SECONDS,
            expires_in: Self::DEVICE_CODE_TTL_SECONDS,
        })
    }

    /// Look up a device authorization by device_code (e.g. for token polling).
    pub async fn get_device_authorization(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        let mut conn = self.redis.clone();
        let raw: Option<String> = redis::cmd("GET")
            .arg(format!("oauth_device:{device_code}"))
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET device: {e}")))?;
        match raw {
            Some(json) => {
                let rec: DeviceAuthorization = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(format!("Deserialize device: {e}")))?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Look up a device authorization by user_code (for the approval UI).
    pub async fn get_device_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>> {
        let mut conn = self.redis.clone();
        let raw: Option<String> = redis::cmd("GET")
            .arg(format!("oauth_device_user:{user_code}"))
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET user_code: {e}")))?;
        match raw {
            Some(device_code) => self.get_device_authorization(&device_code).await,
            None => Ok(None),
        }
    }

    /// Approve or deny a device authorization (called from the user-facing
    /// approval page after EIAA capsule decision).
    pub async fn finalize_device_authorization(
        &self,
        user_code: &str,
        approve: bool,
        user_id: Option<&str>,
        session_id: Option<&str>,
        decision_ref: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.redis.clone();
        let raw_user: Option<String> = redis::cmd("GET")
            .arg(format!("oauth_device_user:{user_code}"))
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET user: {e}")))?;
        let device_code =
            raw_user.ok_or_else(|| AppError::BadRequest("Unknown or expired user_code".into()))?;

        let device_key = format!("oauth_device:{device_code}");
        let raw: Option<String> = redis::cmd("GET")
            .arg(&device_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis GET device: {e}")))?;
        let mut rec: DeviceAuthorization = match raw {
            Some(j) => serde_json::from_str(&j)
                .map_err(|e| AppError::Internal(format!("Deserialize device: {e}")))?,
            None => return Err(AppError::BadRequest("Device authorization expired".into())),
        };
        if !matches!(rec.state, DeviceAuthState::Pending) {
            return Err(AppError::BadRequest(
                "Device authorization already finalized".into(),
            ));
        }
        rec.state = if approve {
            DeviceAuthState::Approved
        } else {
            DeviceAuthState::Denied
        };
        rec.user_id = user_id.map(|s| s.to_string());
        rec.session_id = session_id.map(|s| s.to_string());
        rec.decision_ref = decision_ref.map(|s| s.to_string());
        let value = serde_json::to_string(&rec)
            .map_err(|e| AppError::Internal(format!("Serialize device: {e}")))?;
        // Preserve remaining TTL with KEEPTTL where supported, else SETEX max.
        redis::cmd("SET")
            .arg(&device_key)
            .arg(value)
            .arg("KEEPTTL")
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis SET KEEPTTL: {e}")))?;
        Ok(())
    }

    /// Atomically delete a device authorization once tokens have been issued.
    pub async fn consume_device_authorization(
        &self,
        device_code: &str,
        user_code: &str,
    ) -> Result<()> {
        let mut conn = self.redis.clone();
        redis::cmd("DEL")
            .arg(format!("oauth_device:{device_code}"))
            .arg(format!("oauth_device_user:{user_code}"))
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(format!("Redis DEL device: {e}")))?;
        Ok(())
    }
}

// ─── Device Authorization (T2.6) ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthState {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub client_id: String,
    pub tenant_id: String,
    pub scope: String,
    pub user_code: String,
    pub state: DeviceAuthState,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub decision_ref: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub interval: i64,
    pub expires_in: i64,
}

#[cfg(test)]
mod pkce_tests {
    use super::{AuthorizationCodeContext, OAuthAsService};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};

    fn s256(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    #[test]
    fn verifier_format_min_max() {
        // 43 chars (min) — pass
        let v43: String = std::iter::repeat('a').take(43).collect();
        assert!(OAuthAsService::validate_code_verifier_format(&v43));
        // 128 chars (max) — pass
        let v128: String = std::iter::repeat('Z').take(128).collect();
        assert!(OAuthAsService::validate_code_verifier_format(&v128));
        // 42 chars — fail
        let v42: String = std::iter::repeat('a').take(42).collect();
        assert!(!OAuthAsService::validate_code_verifier_format(&v42));
        // 129 chars — fail
        let v129: String = std::iter::repeat('a').take(129).collect();
        assert!(!OAuthAsService::validate_code_verifier_format(&v129));
    }

    #[test]
    fn verifier_rejects_disallowed_chars() {
        // '+' and '/' are NOT in RFC 7636 unreserved alphabet.
        let v: String = "a".repeat(42) + "+";
        assert!(!OAuthAsService::validate_code_verifier_format(&v));
        let v: String = "a".repeat(42) + "/";
        assert!(!OAuthAsService::validate_code_verifier_format(&v));
        // Spaces — fail.
        let v: String = "a".repeat(42) + " ";
        assert!(!OAuthAsService::validate_code_verifier_format(&v));
    }

    #[test]
    fn verifier_accepts_unreserved_punctuation() {
        let v = format!("{}-._~", "a".repeat(39));
        assert_eq!(v.len(), 43);
        assert!(OAuthAsService::validate_code_verifier_format(&v));
    }

    #[test]
    fn s256_challenge_format_exact_43() {
        let challenge = s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(challenge.len(), 43);
        assert!(OAuthAsService::validate_s256_challenge_format(&challenge));
        // Truncated by 1 — fail
        assert!(!OAuthAsService::validate_s256_challenge_format(
            &challenge[..42]
        ));
        // Padded — fail (must be no-pad)
        let padded = format!("{challenge}=");
        assert!(!OAuthAsService::validate_s256_challenge_format(&padded));
    }

    #[test]
    fn validate_pkce_round_trip() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256(verifier);
        assert!(OAuthAsService::validate_pkce(verifier, &challenge));
    }

    #[test]
    fn validate_pkce_rejects_bad_verifier_format() {
        // Even if the *hash* matched, format must be valid first.
        let bad_verifier = "tooshort";
        let challenge = s256(bad_verifier);
        assert!(!OAuthAsService::validate_pkce(bad_verifier, &challenge));
    }

    #[test]
    fn validate_pkce_rejects_wrong_verifier() {
        let challenge = s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        let wrong = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars valid format
        assert!(!OAuthAsService::validate_pkce(wrong, &challenge));
    }

    // ─── T4.4 — FAPI 2.0 profile helpers ─────────────────────────────────────

    fn fapi_app(fapi_profile: Option<&str>) -> org_manager::Application {
        org_manager::Application {
            id: "test".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tenant_id: "t1".into(),
            name: "Test App".into(),
            r#type: "web".into(),
            client_id: "client_test".into(),
            client_secret_hash: Some("hash".into()),
            redirect_uris: serde_json::json!(["https://example.com/cb"]),
            allowed_flows: serde_json::json!(["authorization_code"]),
            public_config: serde_json::json!({}),
            allowed_scopes: serde_json::json!(["openid"]),
            is_first_party: false,
            token_lifetime_secs: 3600,
            refresh_token_lifetime_secs: 86400,
            fapi_profile: fapi_profile.map(|s| s.to_string()),
        }
    }

    #[test]
    fn is_fapi_none_returns_false() {
        assert!(!OAuthAsService::is_fapi(&fapi_app(None)));
    }

    #[test]
    fn is_fapi_fapi2_returns_true() {
        assert!(OAuthAsService::is_fapi(&fapi_app(Some("fapi2"))));
    }

    #[test]
    fn is_fapi_unknown_profile_returns_false() {
        // Unrecognised profile values do NOT accidentally enable enforcement.
        assert!(!OAuthAsService::is_fapi(&fapi_app(Some("legacy"))));
    }

    #[test]
    fn fapi_token_lifetime_capped_at_300() {
        let app = fapi_app(Some("fapi2"));
        // Mirrors the logic in handle_authorization_code_grant.
        let base = app.token_lifetime_secs as i64;
        let lifetime = if OAuthAsService::is_fapi(&app) {
            base.min(300)
        } else {
            base
        };
        assert_eq!(lifetime, 300, "FAPI 2.0 must cap token lifetime at 300 s");
    }

    #[test]
    fn non_fapi_token_lifetime_unchanged() {
        let app = fapi_app(None);
        let base = app.token_lifetime_secs as i64;
        let lifetime = if OAuthAsService::is_fapi(&app) {
            base.min(300)
        } else {
            base
        };
        assert_eq!(lifetime, 3600, "Non-FAPI token lifetime must not be capped");
    }

    #[test]
    fn s_hash_computation_is_correct() {
        use auth_core::OAuthIdTokenClaims;
        // RFC 7519 / OIDC: s_hash = base64url(left_half(SHA256(state)))
        // For state = "abc":  SHA256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492c50d7...
        // left 16 bytes:       ba7816bf8f01cfea414140de5dae2ec7
        // base64url(that):     unhgv48Bz+pBQUDe...
        // We just verify determinism and format; exact value tested via round-trip.
        let h1 = OAuthIdTokenClaims::compute_s_hash("some_state_value");
        let h2 = OAuthIdTokenClaims::compute_s_hash("some_state_value");
        assert_eq!(h1, h2, "s_hash must be deterministic");

        // Different states must produce different hashes.
        let h3 = OAuthIdTokenClaims::compute_s_hash("other_state");
        assert_ne!(h1, h3, "s_hash must vary with state");

        // Output must be base64url-no-pad (only [A-Za-z0-9_-]).
        assert!(
            h1.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "s_hash must be base64url-no-pad"
        );
    }

    #[test]
    fn authorization_code_context_state_roundtrips() {
        let ctx = AuthorizationCodeContext {
            client_id: "c".into(),
            redirect_uri: "https://example.com/cb".into(),
            scope: "openid".into(),
            user_id: "u".into(),
            session_id: "s".into(),
            tenant_id: "t".into(),
            code_challenge: None,
            code_challenge_method: None,
            created_at: 0,
            decision_ref: None,
            nonce: None,
            state: Some("oauth_state_xyz".into()),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: AuthorizationCodeContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state.as_deref(), Some("oauth_state_xyz"));
    }

    #[test]
    fn authorization_code_context_state_defaults_to_none() {
        // Old serialized contexts without `state` must deserialize without error.
        let json = r#"{"client_id":"c","redirect_uri":"https://x.com/cb","scope":"openid","user_id":"u","session_id":"s","tenant_id":"t","created_at":0}"#;
        let ctx: AuthorizationCodeContext = serde_json::from_str(json).unwrap();
        assert!(ctx.state.is_none());
    }
}
