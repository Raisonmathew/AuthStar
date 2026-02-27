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
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let server_host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let server_port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;

        // Passkey defaults: derive from server host if not explicitly set
        let default_rp_id = if server_host == "0.0.0.0" { "localhost".to_string() } else { server_host.clone() };
        let default_origin = format!("http://{}:{}", default_rp_id, server_port);

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
        };

        // Startup validation: warn about missing critical config
        config.validate_startup();

        Ok(config)
    }

    /// Log warnings for missing or placeholder configuration
    fn validate_startup(&self) {
        if self.stripe.secret_key.is_empty() {
            tracing::warn!("⚠️  STRIPE_SECRET_KEY not set — billing features will fail");
        }
        if self.stripe.webhook_secret.is_empty() {
            tracing::warn!("⚠️  STRIPE_WEBHOOK_SECRET not set — webhook verification disabled");
        }
        if self.email.sendgrid_api_key.is_empty() {
            tracing::warn!("⚠️  SENDGRID_API_KEY not set — email features will fail");
        }
        if self.email.from_email == "noreply@example.com" {
            tracing::warn!("⚠️  SENDGRID_FROM_EMAIL is placeholder — update for production");
        }
        if self.eiaa.compiler_sk_b64.is_none() {
            tracing::warn!("⚠️  COMPILER_SK_B64 not set — using ephemeral keys (attestations will not survive restart)");
        }
        if self.allowed_origins.is_empty() {
            tracing::warn!("⚠️  ALLOWED_ORIGINS not set — CORS will allow all origins (insecure for production)");
        }
        if self.passkey_rp_id == "localhost" {
            tracing::warn!("⚠️  PASSKEY_RP_ID defaults to 'localhost' — set for production domain");
        }
        if self.frontend_url.contains("localhost") {
            tracing::warn!("⚠️  FRONTEND_URL contains 'localhost' — set to production URL for SSO redirects");
        }
    }
}
