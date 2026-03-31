use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,

    pub stripe: StripeConfig,
    pub eiaa: EIAAConfig,
    pub email: EmailConfig,
    /// Comma-separated list of allowed CORS origins (e.g. "https://app.example.com,https://admin.example.com")
    pub allowed_origins: Vec<String>,
    /// Frontend URL for OAuth/SAML redirects (e.g. "https://app.example.com")
    pub frontend_url: String,
    /// WebAuthn Relying Party ID (e.g. "auth.example.com")
    pub passkey_rp_id: String,
    /// WebAuthn origin URL (e.g. "https://auth.example.com")
    pub passkey_origin: String,
    /// Default: require email verification for login policies
    pub require_email_verification: bool,
    /// Deployment environment: "production", "staging", or "development" (default).
    /// Set via `APP_ENV` environment variable.
    /// In production mode, missing critical secrets cause a hard startup failure
    /// rather than a warning — preventing accidental insecure deployments.
    pub app_env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    /// Seconds to wait for a connection from the pool before returning 503.
    /// Default: 5 seconds. Set via `DB_ACQUIRE_TIMEOUT_SECS`.
    pub acquire_timeout_secs: u64,
    /// Minimum idle connections to keep open. Default: 2.
    pub min_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Private key for ES256 signing (PEM format)
    pub private_key: String,
    /// Public key for ES256 verification (PEM format)
    pub public_key: String,
    pub issuer: String,
    pub audience: String,
    pub expiration_seconds: i64,
}



#[derive(Debug, Clone, Deserialize)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EIAAConfig {
    pub runtime_grpc_addr: String,
    pub compiler_sk_b64: Option<String>,
    // IPLocate.io configuration
    pub iplocate_api_key: Option<String>,
    pub iplocate_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub sendgrid_api_key: String,
    pub from_email: String,
    pub from_name: String,
}

impl Config {
    /// Returns `true` when `APP_ENV` is `"production"` or `"prod"`.
    ///
    /// Used by `validate_startup()` to decide whether missing critical secrets
    /// should cause a hard startup failure (production) or a warning (development).
    pub fn is_production(&self) -> bool {
        matches!(self.app_env.to_lowercase().as_str(), "production" | "prod")
    }

    /// Returns `true` when `APP_ENV` is `"staging"`.
    ///
    /// Staging enforces the same hard-fail rules as production so that
    /// pre-production environments catch missing secrets before they reach prod.
    pub fn is_staging(&self) -> bool {
        self.app_env.to_lowercase() == "staging"
    }

    /// Returns `true` when production-level security enforcement should apply.
    /// This is `true` for both `"production"` and `"staging"` environments.
    pub fn is_production_like(&self) -> bool {
        self.is_production() || self.is_staging()
    }

    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let server_host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let server_port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;

        // Passkey defaults: derive from server host if not explicitly set
        let default_rp_id = if server_host == "0.0.0.0" { "localhost".to_string() } else { server_host.clone() };
        let default_origin = format!("http://{default_rp_id}:{server_port}");

        let config = Config {
            server: ServerConfig {
                host: server_host,
                port: server_port,
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                acquire_timeout_secs: env::var("DB_ACQUIRE_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "2".to_string())
                    .parse()?,
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL")?,
            },
            jwt: JwtConfig {
                private_key: env::var("JWT_PRIVATE_KEY")
                    .map(|k| k.replace("\\n", "\n"))
                    .map_err(|_| anyhow::anyhow!("JWT_PRIVATE_KEY is required"))?,
                public_key: env::var("JWT_PUBLIC_KEY")
                    .map(|k| k.replace("\\n", "\n"))
                    .map_err(|_| anyhow::anyhow!("JWT_PUBLIC_KEY is required"))?,
                issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "idaas".to_string()),
                audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "idaas-api".to_string()),
                expiration_seconds: env::var("JWT_EXPIRATION_SECONDS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
            },
            stripe: StripeConfig {
                secret_key: env::var("STRIPE_SECRET_KEY")
                    .unwrap_or_default(),
                webhook_secret: env::var("STRIPE_WEBHOOK_SECRET")
                    .unwrap_or_default(),
            },
            eiaa: EIAAConfig {
                runtime_grpc_addr: env::var("RUNTIME_GRPC_ADDR").unwrap_or_else(|_| "http://127.0.0.1:50061".to_string()),
                compiler_sk_b64: env::var("COMPILER_SK_B64").ok(),
                iplocate_api_key: env::var("IPLOCATE_API_KEY").ok(),
                iplocate_enabled: env::var("IPLOCATE_ENABLED")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(true),
            },
            email: EmailConfig {
                sendgrid_api_key: env::var("SENDGRID_API_KEY").unwrap_or_default(),
                from_email: env::var("SENDGRID_FROM_EMAIL").unwrap_or_else(|_| "noreply@example.com".to_string()),
                from_name: env::var("SENDGRID_FROM_NAME").unwrap_or_else(|_| "IDaaS Platform".to_string()),
            },
            allowed_origins: env::var("ALLOWED_ORIGINS")
                .map(|s| s.split(',').map(|o| o.trim().to_string()).filter(|o| !o.is_empty()).collect())
                .unwrap_or_default(),
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| format!("http://localhost:{}", 5173)),
            passkey_rp_id: env::var("PASSKEY_RP_ID")
                .unwrap_or(default_rp_id),
            passkey_origin: env::var("PASSKEY_ORIGIN")
                .unwrap_or(default_origin),
            require_email_verification: env::var("REQUIRE_EMAIL_VERIFICATION")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
        };

        // Startup validation: hard-fail in production, warn in development.
        config.validate_startup()?;

        Ok(config)
    }

    /// Validate critical configuration at startup.
    ///
    /// ## Production / Staging (hard-fail)
    ///
    /// Missing secrets that would cause a security vulnerability in production
    /// cause an immediate startup failure with a clear error message. This
    /// prevents accidental insecure deployments where an operator forgot to
    /// set a required secret in the K8s SecretKeyRef.
    ///
    /// Secrets that trigger hard-fail:
    /// - `FACTOR_ENCRYPTION_KEY` — TOTP secrets stored in plaintext without this (R-2)
    /// - `COMPILER_SK_B64` — EIAA capsule attestations become unverifiable after restart (R-3)
    /// - `ALLOWED_ORIGINS` — CORS allows all origins without this
    /// - `PASSKEY_RP_ID` — WebAuthn RP ID must be the production domain
    ///
    /// ## Development (warn only)
    ///
    /// The same checks emit `tracing::warn!` in development so that local
    /// development still works without a full secrets setup.
    fn validate_startup(&self) -> anyhow::Result<()> {
        let prod = self.is_production_like();

        // ── Stripe ──────────────────────────────────────────────────────────
        if self.stripe.secret_key.is_empty() {
            tracing::warn!("⚠️  STRIPE_SECRET_KEY not set — billing features will fail");
        }
        if self.stripe.webhook_secret.is_empty() {
            tracing::warn!("⚠️  STRIPE_WEBHOOK_SECRET not set — webhook verification disabled");
        }

        // ── Email ────────────────────────────────────────────────────────────
        if self.email.sendgrid_api_key.is_empty() {
            tracing::warn!("⚠️  SENDGRID_API_KEY not set — email features will fail");
        }
        if self.email.from_email == "noreply@example.com" {
            tracing::warn!("⚠️  SENDGRID_FROM_EMAIL is placeholder — update for production");
        }

        // ── R-2: FACTOR_ENCRYPTION_KEY ───────────────────────────────────────
        // Without this key, TOTP secrets are stored in plaintext. A database
        // breach would expose every user's TOTP secret, allowing an attacker
        // to generate valid MFA codes for all users indefinitely.
        //
        // In production/staging: hard-fail — do not start without this key.
        // In development: warn — allows local dev without a full secrets setup.
        let factor_key_set = env::var("FACTOR_ENCRYPTION_KEY").is_ok();
        if !factor_key_set {
            if prod {
                return Err(anyhow::anyhow!(
                    "FATAL: FACTOR_ENCRYPTION_KEY is not set in {} environment. \
                     TOTP secrets would be stored in plaintext — this is a critical \
                     security vulnerability. Set FACTOR_ENCRYPTION_KEY to a 32-byte \
                     base64url-encoded secret in your K8s SecretKeyRef before starting \
                     the server. To generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='",
                    self.app_env
                ));
            } else {
                tracing::warn!(
                    "⚠️  FACTOR_ENCRYPTION_KEY not set — TOTP secrets stored in plaintext. \
                     Set FACTOR_ENCRYPTION_KEY (32 bytes, base64url) for production. \
                     Generate: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='"
                );
            }
        } else {
            tracing::info!("✅ FACTOR_ENCRYPTION_KEY is set — TOTP secrets will be encrypted at rest");
        }

        // ── R-3: COMPILER_SK_B64 ─────────────────────────────────────────────
        // Without a persistent Ed25519 signing key, the capsule compiler generates
        // an ephemeral key at startup. All EIAA attestations become unverifiable
        // after a restart (or across replicas), breaking the entire EIAA trust chain
        // for all active sessions.
        //
        // In production/staging: hard-fail — do not start without this key.
        // In development: warn — ephemeral keys are acceptable for local testing.
        if self.eiaa.compiler_sk_b64.is_none() {
            if prod {
                return Err(anyhow::anyhow!(
                    "FATAL: COMPILER_SK_B64 is not set in {} environment. \
                     EIAA capsule attestations would use an ephemeral signing key that \
                     is lost on every restart, invalidating all active sessions and \
                     breaking the EIAA trust chain. Set COMPILER_SK_B64 to a persistent \
                     Ed25519 private key (base64url-encoded) in your K8s SecretKeyRef. \
                     To generate: openssl genpkey -algorithm ed25519 | openssl pkey -outform DER | \
                     base64 | tr '+/' '-_' | tr -d '='",
                    self.app_env
                ));
            } else {
                tracing::warn!(
                    "⚠️  COMPILER_SK_B64 not set — using ephemeral keys \
                     (attestations will not survive restart)"
                );
            }
        } else {
            tracing::info!("✅ COMPILER_SK_B64 is set — capsule signing key is persistent");
        }

        // ── CORS ─────────────────────────────────────────────────────────────
        if self.allowed_origins.is_empty() {
            if prod {
                return Err(anyhow::anyhow!(
                    "FATAL: ALLOWED_ORIGINS is not set in {} environment. \
                     CORS would allow all origins, enabling cross-origin attacks. \
                     Set ALLOWED_ORIGINS to a comma-separated list of allowed origins \
                     (e.g. 'https://app.example.com,https://admin.example.com').",
                    self.app_env
                ));
            } else {
                tracing::warn!(
                    "⚠️  ALLOWED_ORIGINS not set — CORS will allow all origins \
                     (insecure for production)"
                );
            }
        }

        // ── WebAuthn ─────────────────────────────────────────────────────────
        if self.passkey_rp_id == "localhost" {
            if prod {
                return Err(anyhow::anyhow!(
                    "FATAL: PASSKEY_RP_ID is 'localhost' in {} environment. \
                     WebAuthn passkeys registered against 'localhost' will not work \
                     on the production domain. Set PASSKEY_RP_ID to the production \
                     domain (e.g. 'auth.example.com').",
                    self.app_env
                ));
            } else {
                tracing::warn!(
                    "⚠️  PASSKEY_RP_ID defaults to 'localhost' — set for production domain"
                );
            }
        }

        // ── Frontend URL ─────────────────────────────────────────────────────
        if self.frontend_url.contains("localhost") {
            if prod {
                tracing::warn!(
                    "⚠️  FRONTEND_URL contains 'localhost' in {} environment — \
                     SSO redirects will fail. Set FRONTEND_URL to the production URL.",
                    self.app_env
                );
                // Warn only (not hard-fail) — some deployments use localhost for
                // internal service-to-service redirects even in production.
            } else {
                tracing::warn!(
                    "⚠️  FRONTEND_URL contains 'localhost' — set to production URL \
                     for SSO redirects"
                );
            }
        }

        tracing::info!(
            "✅ Startup validation complete (env: {})",
            self.app_env
        );

        Ok(())
    }
}
