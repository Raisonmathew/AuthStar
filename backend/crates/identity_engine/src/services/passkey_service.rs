//! Passkey (WebAuthn) Service with Redis Session Storage
//!
//! Provides EIAA-compliant Passkey registration and authentication.
//! Uses `webauthn-rs` 0.5.4 for WebAuthn protocol handling.
//! Sessions are stored server-side in Redis with 5-minute TTL for security.

use std::sync::Arc;
use sqlx::PgPool;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use webauthn_rs::prelude::*;
use shared_types::{AppError, Result, generate_id};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session TTL in seconds (5 minutes)
const SESSION_TTL_SECONDS: u64 = 300;

/// Redis key prefix for passkey sessions
const REDIS_KEY_PREFIX: &str = "passkey_session:";

/// Thread-safe Passkey service with Redis session storage
#[derive(Clone)]
pub struct PasskeyService {
    db: PgPool,
    redis: ConnectionManager,
    webauthn: Arc<Webauthn>,
}

/// Internal session data stored in Redis
#[derive(Debug, Serialize, Deserialize)]
struct PasskeySession {
    user_id: String,
    session_type: SessionType,
    state_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum SessionType {
    Registration,
    Authentication,
}

/// Response from `start_registration`
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    /// Session ID (opaque key referencing Redis)
    pub session_id: String,
    /// Challenge to send to client
    pub options: CreationChallengeResponse,
}

/// Response from `start_authentication`
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartResponse {
    /// Session ID (opaque key referencing Redis)
    pub session_id: String,
    /// Challenge to send to client
    pub options: RequestChallengeResponse,
}

/// EIAA-Compliant Passkey Verification Result
/// 
/// Contains AAL (Authenticator Assurance Level) data for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyVerificationResult {
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Was user verification performed (biometrics, PIN, etc.)
    pub user_verified: bool,
    /// Authenticator Assurance Level (AAL1, AAL2, AAL3)
    pub aal: String,
    /// Counter value (for replay detection)
    pub counter: u32,
}

impl PasskeyService {
    /// Create a new PasskeyService with Redis session storage
    ///
    /// # Arguments
    /// * `db` - PostgreSQL connection pool
    /// * `redis` - Redis connection manager
    /// * `rpid` - Relying Party ID (e.g., "example.com")
    /// * `origin` - Origin URL (e.g., "https://example.com")
    pub fn new(db: PgPool, redis: ConnectionManager, rpid: &str, origin: &str) -> std::result::Result<Self, String> {
        let url_origin = Url::parse(origin)
            .map_err(|e| format!("Invalid origin URL: {}", e))?;

        let builder = WebauthnBuilder::new(rpid, &url_origin)
            .map_err(|e| format!("Invalid WebAuthn configuration: {:?}", e))?;

        let webauthn = Arc::new(
            builder.build()
                .map_err(|e| format!("Failed to build WebAuthn instance: {:?}", e))?
        );

        Ok(Self { db, redis, webauthn })
    }

    /// Store session in Redis with TTL
    async fn store_session(&self, session: &PasskeySession) -> Result<String> {
        let session_id = generate_id("pks"); // passkey session
        let key = format!("{}{}", REDIS_KEY_PREFIX, session_id);
        
        let session_json = serde_json::to_string(session)
            .map_err(|e| AppError::Internal(format!("Session serialization error: {}", e)))?;
        
        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(&key, &session_json, SESSION_TTL_SECONDS)
            .await
            .map_err(|e| AppError::Internal(format!("Redis error: {}", e)))?;
        
        tracing::debug!(session_id = %session_id, "Passkey session stored in Redis");
        Ok(session_id)
    }

    /// Retrieve and delete session from Redis (one-time use)
    async fn get_and_delete_session(&self, session_id: &str) -> Result<PasskeySession> {
        let key = format!("{}{}", REDIS_KEY_PREFIX, session_id);
        
        let mut conn = self.redis.clone();
        
        // Get the session
        let session_json: Option<String> = conn.get(&key)
            .await
            .map_err(|e| AppError::Internal(format!("Redis error: {}", e)))?;
        
        let session_json = session_json
            .ok_or_else(|| AppError::BadRequest("Session expired or invalid".to_string()))?;
        
        // Delete immediately (one-time use)
        let _: () = conn.del(&key)
            .await
            .map_err(|e| AppError::Internal(format!("Redis delete error: {}", e)))?;
        
        let session: PasskeySession = serde_json::from_str(&session_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid session data: {}", e)))?;
        
        tracing::debug!(session_id = %session_id, "Passkey session retrieved and deleted");
        Ok(session)
    }

    /// Start passkey registration for a user
    pub async fn start_registration(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<RegistrationStartResponse> {
        // Get existing passkeys for exclusion list
        let existing_creds = self.get_user_passkeys(user_id).await?;
        let exclude_credentials: Option<Vec<CredentialID>> = if existing_creds.is_empty() {
            None
        } else {
            Some(existing_creds.iter().map(|p| p.cred_id().clone()).collect())
        };

        // MEDIUM-5: Stable WebAuthn user handle — derive deterministically from user_id
        // so the same user always gets the same handle across registrations.
        // We use a UUID v5 (SHA-1 namespace hash) seeded with a fixed namespace + user_id.
        // This prevents the authenticator from creating duplicate resident keys for the same user.
        let webauthn_namespace = Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
            .unwrap_or(Uuid::nil()); // DNS namespace UUID
        let webauthn_user_id = Uuid::new_v5(&webauthn_namespace, user_id.as_bytes());

        // Start registration
        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            webauthn_user_id,
            email,
            email,
            exclude_credentials,
        )
        .map_err(|e| AppError::Internal(format!("WebAuthn registration error: {:?}", e)))?;

        // Serialize state for Redis storage
        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| AppError::Internal(format!("State serialization error: {}", e)))?;

        // Store in Redis
        let session = PasskeySession {
            user_id: user_id.to_string(),
            session_type: SessionType::Registration,
            state_json,
        };
        let session_id = self.store_session(&session).await?;

        Ok(RegistrationStartResponse {
            session_id,
            options: ccr,
        })
    }

    /// Complete passkey registration
    pub async fn finish_registration(
        &self,
        user_id: &str,
        session_id: &str,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
    ) -> Result<String> {
        // Get session from Redis (one-time use)
        let session = self.get_and_delete_session(session_id).await?;
        
        // Verify user matches
        if session.user_id != user_id {
            return Err(AppError::Forbidden("Session user mismatch".to_string()));
        }
        
        // Verify session type
        if !matches!(session.session_type, SessionType::Registration) {
            return Err(AppError::BadRequest("Invalid session type".to_string()));
        }
        
        // Deserialize state
        let reg_state: PasskeyRegistration = serde_json::from_str(&session.state_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid session state: {}", e)))?;

        // Complete registration
        let passkey = self.webauthn.finish_passkey_registration(response, &reg_state)
            .map_err(|e| AppError::BadRequest(format!("Registration verification failed: {:?}", e)))?;

        // Store credential in database
        let credential_id = generate_id("pkc");
        let passkey_name = name.unwrap_or_else(|| "My Passkey".to_string());
        
        let passkey_bytes = serde_json::to_vec(&passkey)
            .map_err(|e| AppError::Internal(format!("Passkey serialization error: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO passkey_credentials (
                id, user_id, credential_id, public_key, counter, transports, name, created_at
            ) VALUES ($1, $2, $3, $4, 0, $5, $6, NOW())
            "#
        )
        .bind(&credential_id)
        .bind(user_id)
        .bind(passkey.cred_id().as_slice())
        .bind(&passkey_bytes)
        .bind(serde_json::json!([]))
        .bind(&passkey_name)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;

        tracing::info!(
            user_id = user_id,
            credential_id = credential_id,
            "Passkey registered successfully"
        );

        Ok(credential_id)
    }

    /// Start passkey authentication for a user
    pub async fn start_authentication(&self, user_id: &str) -> Result<AuthenticationStartResponse> {
        let passkeys = self.get_user_passkeys(user_id).await?;
        
        if passkeys.is_empty() {
            return Err(AppError::BadRequest("No passkeys registered for this user".to_string()));
        }

        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::Internal(format!("WebAuthn authentication error: {:?}", e)))?;

        // Serialize state for Redis storage
        let state_json = serde_json::to_string(&auth_state)
            .map_err(|e| AppError::Internal(format!("State serialization error: {}", e)))?;

        // Store in Redis
        let session = PasskeySession {
            user_id: user_id.to_string(),
            session_type: SessionType::Authentication,
            state_json,
        };
        let session_id = self.store_session(&session).await?;

        Ok(AuthenticationStartResponse {
            session_id,
            options: rcr,
        })
    }

    /// Complete passkey authentication
    /// Returns rich verification result with AAL data for capsule evaluation.
    pub async fn finish_authentication(
        &self,
        user_id: &str,
        session_id: &str,
        response: &PublicKeyCredential,
    ) -> Result<PasskeyVerificationResult> {
        // Get session from Redis (one-time use)
        let session = self.get_and_delete_session(session_id).await?;
        
        // Verify user matches
        if session.user_id != user_id {
            return Err(AppError::Forbidden("Session user mismatch".to_string()));
        }
        
        // Verify session type
        if !matches!(session.session_type, SessionType::Authentication) {
            return Err(AppError::BadRequest("Invalid session type".to_string()));
        }
        
        // Deserialize state
        let auth_state: PasskeyAuthentication = serde_json::from_str(&session.state_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid session state: {}", e)))?;

        // Complete authentication
        let auth_result = self.webauthn.finish_passkey_authentication(response, &auth_state)
            .map_err(|e| AppError::BadRequest(format!("Authentication verification failed: {:?}", e)))?;

        // Update credential if needed
        if auth_result.needs_update() {
            let mut passkeys = self.get_user_passkeys(user_id).await?;
            for passkey in passkeys.iter_mut() {
                if let Some(_updated) = passkey.update_credential(&auth_result) {
                    let passkey_bytes = serde_json::to_vec(&passkey)
                        .map_err(|e| AppError::Internal(format!("Passkey serialization error: {}", e)))?;
                    
                    sqlx::query(
                        r#"
                        UPDATE passkey_credentials 
                        SET public_key = $1, counter = $2, last_used_at = NOW()
                        WHERE user_id = $3 AND credential_id = $4
                        "#
                    )
                    .bind(&passkey_bytes)
                    .bind(auth_result.counter() as i64)
                    .bind(user_id)
                    .bind(passkey.cred_id().as_slice())
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;
                    break;
                }
            }
        } else {
            sqlx::query(
                "UPDATE passkey_credentials SET last_used_at = NOW() WHERE user_id = $1 AND credential_id = $2"
            )
            .bind(user_id)
            .bind(auth_result.cred_id().as_ref())
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;
        }

        tracing::info!(
            user_id = user_id,
            "Passkey authentication successful"
        );

        // Extract UV (User Verified) flag from auth result
        // In webauthn-rs 0.5.x, we check if user verification was performed
        let user_verified = auth_result.user_verified();

        // MEDIUM-4: Correct AAL classification per NIST SP 800-63B:
        //
        // AAL1 = Single factor (password only) — not applicable here
        // AAL2 = Two factors: something you know + something you have (passkey without UV,
        //        or passkey with UV where the authenticator is software-bound / not FIDO2 L2+)
        // AAL3 = Hardware-bound authenticator with UV + physical presence proof
        //        (requires FIDO2 L2+ certification attestation, which webauthn-rs passkeys
        //        do NOT attest by default — `start_passkey_registration` uses
        //        AttestationConveyancePreference::None)
        //
        // Since we use `start_passkey_registration` (no attestation), we CANNOT verify
        // hardware binding. Therefore the maximum achievable AAL is AAL2, regardless of UV.
        //
        // UV=true  → AAL2 (user-verified passkey: biometric/PIN on device)
        // UV=false → AAL1 (presence-only passkey: just "tap" without PIN/biometric)
        //
        // To achieve AAL3, the system would need to use `start_attested_passkey_registration`
        // with FIDO2 L2+ metadata validation — a future enhancement.
        let aal = if user_verified {
            "AAL2"  // UV performed — strong second factor, but not hardware-attested AAL3
        } else {
            "AAL1"  // Presence-only — equivalent to single factor
        };
        
        // Return verification result with AAL data for capsule evaluation
        Ok(PasskeyVerificationResult {
            credential_id: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, auth_result.cred_id().as_ref()),
            user_verified,
            aal: aal.to_string(),
            counter: auth_result.counter(),
        })
    }

    /// List all passkeys for a user
    pub async fn list_passkeys(&self, user_id: &str) -> Result<Vec<PasskeyInfo>> {
        let rows = sqlx::query_as::<_, PasskeyRow>(
            r#"
            SELECT id, name, created_at, last_used_at
            FROM passkey_credentials
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;

        Ok(rows.into_iter().map(|r| PasskeyInfo {
            id: r.id,
            name: r.name,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        }).collect())
    }

    /// Delete a passkey
    pub async fn delete_passkey(&self, user_id: &str, credential_id: &str) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2"
        )
        .bind(credential_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Passkey not found".to_string()));
        }

        tracing::info!(
            user_id = user_id,
            credential_id = credential_id,
            "Passkey deleted"
        );

        Ok(())
    }

    /// Get user's passkeys from database
    async fn get_user_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT public_key FROM passkey_credentials WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?;

        let mut passkeys = Vec::with_capacity(rows.len());
        for (pk_bytes,) in rows {
            let passkey: Passkey = serde_json::from_slice(&pk_bytes)
                .map_err(|e| AppError::Internal(format!("Corrupt passkey data: {}", e)))?;
            passkeys.push(passkey);
        }

        Ok(passkeys)
    }
}

/// Database row for passkey listing
#[derive(sqlx::FromRow)]
struct PasskeyRow {
    id: String,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Public passkey information (without crypto material)
#[derive(Debug, Serialize)]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}
