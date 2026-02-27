//! Email Service Error Types

use thiserror::Error;

/// Email service error types
#[derive(Error, Debug)]
pub enum EmailError {
    /// Provider-specific error
    #[error("Provider '{provider}' error: {message}")]
    Provider { provider: String, message: String },

    /// All configured providers failed
    #[error("All providers failed. Last error: {0}")]
    AllProvidersFailed(String),

    /// Rate limited by provider
    #[error("Rate limited by {provider}: retry after {retry_after_secs}s")]
    RateLimited {
        provider: String,
        retry_after_secs: u64,
    },

    /// Invalid email address
    #[error("Invalid email address: {0}")]
    InvalidEmail(String),

    /// Template not found
    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    /// Template rendering error
    #[error("Template render error: {0}")]
    TemplateRender(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// No providers configured
    #[error("No email providers configured")]
    NoProvidersConfigured,
}

/// Result type for email operations
pub type Result<T> = std::result::Result<T, EmailError>;

impl From<reqwest::Error> for EmailError {
    fn from(e: reqwest::Error) -> Self {
        EmailError::Network(e.to_string())
    }
}

impl From<handlebars::RenderError> for EmailError {
    fn from(e: handlebars::RenderError) -> Self {
        EmailError::TemplateRender(e.to_string())
    }
}

impl From<handlebars::TemplateError> for EmailError {
    fn from(e: handlebars::TemplateError) -> Self {
        EmailError::TemplateRender(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = EmailError::Provider {
            provider: "SendGrid".to_string(),
            message: "API key invalid".to_string(),
        };
        assert!(err.to_string().contains("SendGrid"));
        assert!(err.to_string().contains("API key invalid"));
    }

    #[test]
    fn test_rate_limited_display() {
        let err = EmailError::RateLimited {
            provider: "SES".to_string(),
            retry_after_secs: 60,
        };
        assert!(err.to_string().contains("60"));
    }
}
