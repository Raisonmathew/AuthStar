//! Email Provider Abstraction and Implementations
//!
//! Provides a unified interface for sending emails via multiple providers.

mod sendgrid;
mod ses;
mod smtp;

pub use sendgrid::SendGridProvider;
pub use ses::SesProvider;
pub use smtp::SmtpProvider;

use async_trait::async_trait;
use crate::error::Result;

/// Email message ready for sending
#[derive(Clone, Debug)]
pub struct EmailMessage {
    /// Recipient email address
    pub to: String,
    /// Optional recipient name
    pub to_name: Option<String>,
    /// Email subject
    pub subject: String,
    /// HTML body content
    pub html_body: String,
    /// Optional plain text body (for multi-part messages)
    pub text_body: Option<String>,
}

impl EmailMessage {
    /// Create a new email message
    pub fn new(to: impl Into<String>, subject: impl Into<String>, html_body: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            to_name: None,
            subject: subject.into(),
            html_body: html_body.into(),
            text_body: None,
        }
    }

    /// Add recipient name
    pub fn with_to_name(mut self, name: impl Into<String>) -> Self {
        self.to_name = Some(name.into());
        self
    }

    /// Add plain text body
    pub fn with_text_body(mut self, text: impl Into<String>) -> Self {
        self.text_body = Some(text.into());
        self
    }
}

/// Provider abstraction for sending emails
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Provider name for logging and metrics
    fn name(&self) -> &'static str;

    /// Check if provider is configured and available
    fn is_available(&self) -> bool;

    /// Send an email message
    ///
    /// # Arguments
    /// * `from` - Sender email address
    /// * `from_name` - Sender display name
    /// * `message` - The email message to send
    async fn send(&self, from: &str, from_name: &str, message: &EmailMessage) -> Result<()>;

    /// Health check for circuit breaker patterns
    async fn health_check(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_message_builder() {
        let msg = EmailMessage::new("test@example.com", "Test Subject", "<p>Hello</p>")
            .with_to_name("Test User")
            .with_text_body("Hello");

        assert_eq!(msg.to, "test@example.com");
        assert_eq!(msg.to_name, Some("Test User".to_string()));
        assert_eq!(msg.subject, "Test Subject");
        assert_eq!(msg.html_body, "<p>Hello</p>");
        assert_eq!(msg.text_body, Some("Hello".to_string()));
    }
}
