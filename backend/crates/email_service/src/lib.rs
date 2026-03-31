//! Email Service - Production-Ready
//!
//! Multi-provider email service with:
//! - Provider abstraction (SendGrid, AWS SES, SMTP)
//! - Automatic failover between providers
//! - HTML template engine with organization branding
//! - Rate limiting and retry with exponential backoff
//! - Email address validation
//!
//! # Example
//!
//! ```rust,no_run
//! use email_service::{EmailService, EmailServiceConfig, SendGridConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = EmailServiceConfig::builder()
//!     .from_email("noreply@myapp.com")
//!     .from_name("My App")
//!     .sendgrid(SendGridConfig::new("your-api-key"))
//!     .build();
//!
//! let service = EmailService::new(config);
//!
//! // Send verification code
//! service.send_verification_code("user@example.com", "123456").await?;
//!
//! // Send password reset
//! service.send_password_reset("user@example.com", "https://app.com/reset?token=xxx").await?;
//! # Ok(())
//! # }
//! ```

mod config;
mod error;
mod providers;
mod service;
mod templates;

// Re-export main types
pub use config::{
    EmailServiceConfig, EmailServiceConfigBuilder,
    SendGridConfig, SesConfig, SmtpConfig,
};
pub use error::{EmailError, Result};
pub use providers::{EmailMessage, EmailProvider};
pub use service::EmailService;
pub use templates::{EmailBranding, EmailTemplate, TemplateEngine};

// Legacy compatibility: re-export EmailServiceConfig with old field names for state.rs
impl EmailServiceConfig {
    /// Create from legacy config structure (for backwards compatibility)
    pub fn from_legacy(
        sendgrid_api_key: String,
        from_email: String,
        from_name: String,
        max_retries: u32,
        retry_base_delay_ms: u64,
    ) -> Self {
        let sendgrid = if sendgrid_api_key.is_empty() {
            None
        } else {
            Some(SendGridConfig::new(sendgrid_api_key))
        };

        Self {
            from_email,
            from_name,
            max_retries,
            retry_base_delay_ms,
            sendgrid,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_config_compat() {
        let config = EmailServiceConfig::from_legacy(
            "test-key".to_string(),
            "test@example.com".to_string(),
            "Test Sender".to_string(),
            3,
            1000,
        );

        assert_eq!(config.from_email, "test@example.com");
        assert_eq!(config.from_name, "Test Sender");
        assert!(config.sendgrid.is_some());
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_legacy_config_no_key() {
        let config = EmailServiceConfig::from_legacy(
            "".to_string(),
            "test@example.com".to_string(),
            "Test Sender".to_string(),
            3,
            1000,
        );

        // No SendGrid when key is empty
        assert!(config.sendgrid.is_none());
    }
}
