//! Email Service Configuration

use serde::Deserialize;

/// Main email service configuration
#[derive(Clone, Debug)]
pub struct EmailServiceConfig {
    /// Sender email address
    pub from_email: String,
    /// Sender display name
    pub from_name: String,
    
    /// SendGrid configuration (primary provider)
    pub sendgrid: Option<SendGridConfig>,
    /// AWS SES configuration (fallback)
    pub ses: Option<SesConfig>,
    /// SMTP configuration (fallback)
    pub smtp: Option<SmtpConfig>,
    
    /// Maximum retry attempts per provider (default: 3)
    pub max_retries: u32,
    /// Base delay for exponential backoff in ms (default: 1000)
    pub retry_base_delay_ms: u64,
    /// Provider timeout in seconds (default: 30)
    pub provider_timeout_secs: u64,
    /// Enable automatic fallback to next provider on failure
    pub fallback_enabled: bool,
}

impl Default for EmailServiceConfig {
    fn default() -> Self {
        Self {
            from_email: "noreply@example.com".to_string(),
            from_name: "IDaaS Platform".to_string(),
            sendgrid: None,
            ses: None,
            smtp: None,
            max_retries: 3,
            retry_base_delay_ms: 1000,
            provider_timeout_secs: 30,
            fallback_enabled: true,
        }
    }
}

/// SendGrid provider configuration
#[derive(Clone, Debug, Deserialize)]
pub struct SendGridConfig {
    /// SendGrid API key
    pub api_key: String,
}

impl SendGridConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
        }
    }

    /// Check if the config is valid (has non-empty API key and not a placeholder)
    pub fn is_valid(&self) -> bool {
        !self.api_key.is_empty() && 
        !self.api_key.contains("placeholder") && 
        !self.api_key.contains("change_me")
    }
}

/// AWS SES provider configuration
#[derive(Clone, Debug, Deserialize)]
pub struct SesConfig {
    /// AWS region (e.g., "us-east-1")
    pub region: String,
    /// Optional explicit access key ID (uses default credentials if not set)
    pub access_key_id: Option<String>,
    /// Optional explicit secret access key
    pub secret_access_key: Option<String>,
}

impl SesConfig {
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            access_key_id: None,
            secret_access_key: None,
        }
    }

    pub fn with_credentials(
        region: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            access_key_id: Some(access_key_id.into()),
            secret_access_key: Some(secret_access_key.into()),
        }
    }

    /// Check if the config is valid (has region)
    pub fn is_valid(&self) -> bool {
        !self.region.is_empty()
    }
}

/// SMTP provider configuration
#[derive(Clone, Debug, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname
    pub host: String,
    /// SMTP server port (typically 587 for TLS, 465 for SSL)
    pub port: u16,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
    /// Use TLS (default: true)
    pub tls: bool,
}

impl SmtpConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            username: None,
            password: None,
            tls: true,
        }
    }

    pub fn with_auth(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: Some(username.into()),
            password: Some(password.into()),
            tls: true,
        }
    }

    /// Check if the config is valid (has host)
    pub fn is_valid(&self) -> bool {
        !self.host.is_empty()
    }
}

/// Builder for EmailServiceConfig
impl EmailServiceConfig {
    pub fn builder() -> EmailServiceConfigBuilder {
        EmailServiceConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct EmailServiceConfigBuilder {
    config: EmailServiceConfig,
}

impl EmailServiceConfigBuilder {
    pub fn from_email(mut self, email: impl Into<String>) -> Self {
        self.config.from_email = email.into();
        self
    }

    pub fn from_name(mut self, name: impl Into<String>) -> Self {
        self.config.from_name = name.into();
        self
    }

    pub fn sendgrid(mut self, config: SendGridConfig) -> Self {
        self.config.sendgrid = Some(config);
        self
    }

    pub fn ses(mut self, config: SesConfig) -> Self {
        self.config.ses = Some(config);
        self
    }

    pub fn smtp(mut self, config: SmtpConfig) -> Self {
        self.config.smtp = Some(config);
        self
    }

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    pub fn retry_base_delay_ms(mut self, delay: u64) -> Self {
        self.config.retry_base_delay_ms = delay;
        self
    }

    pub fn provider_timeout_secs(mut self, timeout: u64) -> Self {
        self.config.provider_timeout_secs = timeout;
        self
    }

    pub fn fallback_enabled(mut self, enabled: bool) -> Self {
        self.config.fallback_enabled = enabled;
        self
    }

    pub fn build(self) -> EmailServiceConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EmailServiceConfig::default();
        assert_eq!(config.from_email, "noreply@example.com");
        assert_eq!(config.max_retries, 3);
        assert!(config.fallback_enabled);
    }

    #[test]
    fn test_builder() {
        let config = EmailServiceConfig::builder()
            .from_email("test@example.com")
            .from_name("Test Sender")
            .sendgrid(SendGridConfig::new("test-api-key"))
            .max_retries(5)
            .build();

        assert_eq!(config.from_email, "test@example.com");
        assert_eq!(config.from_name, "Test Sender");
        assert!(config.sendgrid.is_some());
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_sendgrid_config_valid() {
        let valid = SendGridConfig::new("api-key");
        assert!(valid.is_valid());

        let invalid = SendGridConfig::new("");
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_ses_config_valid() {
        let valid = SesConfig::new("us-east-1");
        assert!(valid.is_valid());

        let invalid = SesConfig::new("");
        assert!(!invalid.is_valid());
    }
}
