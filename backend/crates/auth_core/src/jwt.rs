use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared_types::{AppError, Result};

/// EIAA-Compliant JWT Claims
///
/// JWTs are IDENTITY TOKENS ONLY. They must NEVER contain:
/// - roles
/// - permissions
/// - scopes
/// - entitlements
///
/// Authorization is determined by EIAA Capsule execution, not JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at (Unix timestamp)
    pub iat: i64,

    /// Not before (Unix timestamp)
    pub nbf: i64,

    /// Session ID (links to sessions table)
    pub sid: String,

    /// Tenant ID (organization context)
    pub tenant_id: String,

    /// Session type: "end_user" | "admin" | "flow" | "service"
    pub session_type: String,
}

/// Session types for EIAA compliance
pub mod session_types {
    pub const END_USER: &str = "end_user";
    pub const ADMIN: &str = "admin";
    pub const FLOW: &str = "flow";
    pub const SERVICE: &str = "service";
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    public_key_pem: String,
    key_id: String,
    issuer: String,
    audience: String,
    expiration_seconds: i64,
}

impl JwtService {
    /// Create a new JWT service with ES256 (ECDSA with SHA-256)
    ///
    /// For production use with asymmetric keys.
    pub fn new(
        private_key_pem: &str,
        public_key_pem: &str,
        issuer: String,
        audience: String,
        expiration_seconds: i64,
    ) -> Result<Self> {
        // Normalize newlines: convert escaped \n to actual newlines, remove \r, trim
        let private_key_pem = private_key_pem
            .replace("\\n", "\n")
            .replace("\r", "")
            .trim()
            .to_string();
        let public_key_pem = public_key_pem
            .replace("\\n", "\n")
            .replace("\r", "")
            .trim()
            .to_string();

        let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid private key: {e}")))?;

        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("Invalid public key: {e}")))?;

        // Derive kid from SHA-256 thumbprint of the public key PEM (first 16 hex chars)
        let thumbprint = Sha256::digest(public_key_pem.as_bytes());
        let key_id = hex::encode(&thumbprint[..8]);

        Ok(Self {
            encoding_key,
            decoding_key,
            public_key_pem,
            key_id,
            issuer,
            audience,
            expiration_seconds,
        })
    }

    /// Explicitly named constructor for clarity (alias to new)
    pub fn new_ec(
        private_key_pem: &str,
        public_key_pem: &str,
        issuer: String,
        audience: String,
        expiration_seconds: i64,
    ) -> Result<Self> {
        Self::new(
            private_key_pem,
            public_key_pem,
            issuer,
            audience,
            expiration_seconds,
        )
    }

    /// Generate a new JWT token (EIAA-compliant)
    ///
    /// # Arguments
    /// * `user_id` - The user's ID (sub claim)
    /// * `session_id` - The session ID (sid claim, links to sessions table)
    /// * `tenant_id` - The tenant/organization ID
    /// * `session_type` - One of: "end_user", "admin", "flow", "service"
    pub fn generate_token(
        &self,
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        session_type: &str,
    ) -> Result<String> {
        self.generate_token_with_expiry(
            user_id,
            session_id,
            tenant_id,
            session_type,
            self.expiration_seconds,
        )
    }

    /// Generate a new JWT token with custom expiration
    pub fn generate_token_with_expiry(
        &self,
        user_id: &str,
        session_id: &str,
        tenant_id: &str,
        session_type: &str,
        expiration_seconds: i64,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            sid: session_id.to_string(),
            tenant_id: tenant_id.to_string(),
            session_type: session_type.to_string(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to encode JWT: {e}")))
    }

    /// Verify and decode a JWT token
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_nbf = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::Unauthorized("Token expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::Unauthorized("Invalid token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AppError::Unauthorized("Invalid token signature".to_string())
                }
                _ => AppError::Unauthorized(format!("Token verification failed: {e}")),
            }
        })?;

        Ok(token_data.claims)
    }

    /// Verify and decode a JWT into an arbitrary claims type.
    ///
    /// Unlike `verify_token`, this skips audience validation since OAuth tokens
    /// use `aud = client_id` (not the platform audience). Issuer and signature
    /// are still verified.
    pub fn verify_token_as<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        // Skip audience check — OAuth tokens have aud=client_id
        validation.validate_aud = false;
        validation.validate_nbf = true;

        let token_data =
            decode::<T>(token, &self.decoding_key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::Unauthorized("Token expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::Unauthorized("Invalid token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AppError::Unauthorized("Invalid token signature".to_string())
                }
                _ => AppError::Unauthorized(format!("Token verification failed: {e}")),
            })?;

        Ok(token_data.claims)
    }

    /// Get the expiration duration
    pub fn get_expiration_seconds(&self) -> i64 {
        self.expiration_seconds
    }

    /// Get the key ID (kid) for the JWT header.
    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the issuer.
    pub fn get_issuer(&self) -> &str {
        &self.issuer
    }

    /// Sign arbitrary claims with the service's ES256 key.
    /// Used by the OAuth AS to sign OAuthAccessTokenClaims.
    pub fn sign_claims<T: serde::Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to encode JWT: {e}")))
    }

    /// Get the PEM-encoded public key for JWKS endpoint.
    pub fn get_public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    fn create_test_service() -> JwtService {
        // Use the actual generated keys for testing to ensure they work
        // Path is relative to this source file (crates/auth_core/src/jwt.rs)
        // ../../../.keys/ points to backend/.keys/
        let private_key = include_str!("../../../.keys/private.pem");
        let public_key = include_str!("../../../.keys/public.pem");

        JwtService::new_ec(
            private_key,
            public_key,
            "https://auth.test.com".to_string(),
            "https://api.test.com".to_string(),
            60,
        )
        .expect("Failed to create test service with keys")
    }

    #[test]
    fn test_generate_and_verify_token() {
        let service = create_test_service();

        let token = service
            .generate_token("user_123", "sess_456", "tnt_789", session_types::END_USER)
            .unwrap();

        let claims = service.verify_token(&token).unwrap();

        assert_eq!(claims.sub, "user_123");
        assert_eq!(claims.sid, "sess_456");
        assert_eq!(claims.tenant_id, "tnt_789");
        assert_eq!(claims.session_type, session_types::END_USER);
    }

    #[test]
    fn test_claims_do_not_contain_authority() {
        // This test documents the EIAA invariant:
        // Claims struct must NOT have role/permission fields
        let claims = Claims {
            sub: "user_123".to_string(),
            iss: "test".to_string(),
            aud: "test".to_string(),
            exp: 0,
            iat: 0,
            nbf: 0,
            sid: "sess_123".to_string(),
            tenant_id: "tnt_123".to_string(),
            session_type: "end_user".to_string(),
        };

        // Serialize and check there are no authority fields
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("role"));
        assert!(!json.contains("permission"));
        assert!(!json.contains("scope"));
        assert!(!json.contains("entitlement"));
    }

    #[test]
    fn test_verify_token_wrong_issuer() {
        let private_key = include_str!("../../../.keys/private.pem");
        let public_key = include_str!("../../../.keys/public.pem");

        let service1 = JwtService::new_ec(
            private_key,
            public_key,
            "https://auth.issuer1.com".to_string(),
            "https://api.test.com".to_string(),
            60,
        )
        .unwrap();

        let service2 = JwtService::new_ec(
            private_key,
            public_key,
            "https://auth.issuer2.com".to_string(),
            "https://api.test.com".to_string(),
            60,
        )
        .unwrap();

        let token = service1
            .generate_token("user", "sess", "tnt", "end_user")
            .unwrap();

        // Verify with different issuer should fail
        let result = service2.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_wrong_audience() {
        let private_key = include_str!("../../../.keys/private.pem");
        let public_key = include_str!("../../../.keys/public.pem");

        let service1 = JwtService::new(
            private_key,
            public_key,
            "https://auth.test.com".to_string(),
            "https://api.audience1.com".to_string(),
            60,
        )
        .unwrap();

        let service2 = JwtService::new(
            private_key,
            public_key,
            "https://auth.test.com".to_string(),
            "https://api.audience2.com".to_string(),
            60,
        )
        .unwrap();

        let token = service1
            .generate_token("user", "sess", "tnt", "end_user")
            .unwrap();

        // Verify with different audience should fail
        let result = service2.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_empty_string() {
        let service = create_test_service();
        let result = service.verify_token("");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_malformed() {
        let service = create_test_service();
        let result = service.verify_token("not.a.valid.token");
        assert!(result.is_err());

        let result2 = service.verify_token("random-garbage-string");
        assert!(result2.is_err());
    }

    #[test]
    fn test_token_claims_special_chars() {
        let service = create_test_service();

        // Unicode and special characters in claims
        let token = service
            .generate_token(
                "user_日本語_123",
                "sess_émoji_🔐",
                "tnt_special!@#$%",
                session_types::END_USER,
            )
            .unwrap();

        let claims = service.verify_token(&token).unwrap();

        assert_eq!(claims.sub, "user_日本語_123");
        assert_eq!(claims.sid, "sess_émoji_🔐");
        assert_eq!(claims.tenant_id, "tnt_special!@#$%");
    }

    #[test]
    fn test_all_session_types() {
        let service = create_test_service();

        for session_type in [
            session_types::END_USER,
            session_types::ADMIN,
            session_types::FLOW,
            session_types::SERVICE,
        ] {
            let token = service
                .generate_token("user", "sess", "tnt", session_type)
                .unwrap();
            let claims = service.verify_token(&token).unwrap();
            assert_eq!(claims.session_type, session_type);
        }
    }

    #[test]
    fn test_expired_token() {
        let private_key = include_str!("../../../.keys/private.pem");
        let public_key = include_str!("../../../.keys/public.pem");

        // Service with negative expiration (already expired by 2 mins)
        // This overcomes the default 60s leeway in jsonwebtoken validation
        let service = JwtService::new_ec(
            private_key,
            public_key,
            "https://auth.test.com".to_string(),
            "https://api.test.com".to_string(),
            -120,
        )
        .unwrap();

        let token = service
            .generate_token("user", "sess", "tnt", "end_user")
            .unwrap();

        let result = service.verify_token(&token);
        match result {
            Err(shared_types::AppError::Unauthorized(msg)) => assert_eq!(msg, "Token expired"),
            _ => panic!("Expected Unauthorized('Token expired'), got {result:?}"),
        }
    }

    #[test]
    fn test_algorithm_mismatch_attack() {
        let service = create_test_service();

        // Create an HS256 token manually (simulating an attack)
        // Note: In a real attack, the attacker might try to use the public key as an HMAC secret
        // or just force the header to be HS256.
        let claims = Claims {
            sub: "user_123".to_string(),
            iss: "https://auth.test.com".to_string(),
            aud: "https://api.test.com".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            nbf: Utc::now().timestamp(),
            sid: "sess_456".to_string(),
            tenant_id: "tnt_789".to_string(),
            session_type: "end_user".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        let secret = b"secret"; // Attacker uses some secret
        let token = encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();

        // Service is hardcoded to expect ES256, so it should fail validation
        // Validation will see "HS256" in header but expect "ES256"
        let result = service.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_public_key() {
        // Since we only have one valid pair checked in, we can skip "Wrong Key" test
        // OR rely on the fact that verification checks signature.
        // Let's create a token and tamper with the signature part.

        let service = create_test_service();
        let token = service
            .generate_token("user", "sess", "tnt", "end_user")
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        // Tamper with signature (last part)
        parts[2] = "tampered_signature_blob_12345";
        let tampered_token = parts.join(".");

        let result = service.verify_token(&tampered_token);
        assert!(
            result.is_err(),
            "Tampered signature should not pass verification"
        );
    }

    #[test]
    fn test_jwt_kid_header_present() {
        let service = create_test_service();
        let token = service
            .generate_token("user_1", "sess_1", "tnt_1", "end_user")
            .unwrap();

        // Decode the JOSE header (first segment, base64url)
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("decode header");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        // kid must be present and non-empty
        let kid = header["kid"].as_str().expect("kid field must exist");
        assert!(!kid.is_empty(), "kid must not be empty");
        assert_eq!(header["alg"].as_str().unwrap(), "ES256");
    }

    #[test]
    fn test_jwt_kid_is_deterministic() {
        // Same key pair always produces the same kid
        let s1 = create_test_service();
        let s2 = create_test_service();
        assert_eq!(
            s1.key_id, s2.key_id,
            "kid must be deterministic for same key pair"
        );
    }
}
