//! SMTP Email Provider
//!
//! Production implementation using Lettre's async transport for SMTP delivery.

use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    Message,
    AsyncSmtpTransport,
    AsyncTransport,
    Tokio1Executor,
    transport::smtp::authentication::Credentials,
};

use crate::config::SmtpConfig;
use crate::error::{EmailError, Result};
use super::{EmailMessage, EmailProvider};

/// SMTP email provider using Lettre's async transport
pub struct SmtpProvider {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    config: SmtpConfig,
}

impl SmtpProvider {
    /// Create a new SMTP provider
    pub fn new(config: SmtpConfig) -> Self {
        Self {
            transport: None,
            config,
        }
    }

    /// Initialize the SMTP transport
    pub fn initialize(&mut self) -> Result<()> {
        if !self.config.is_valid() {
            return Err(EmailError::Configuration("Invalid SMTP configuration".to_string()));
        }

        // Build transport based on TLS and auth settings
        let builder = if self.config.tls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.host)
                .map_err(|e| EmailError::Configuration(format!("SMTP relay error: {e}")))?
                .port(self.config.port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                .port(self.config.port)
        };

        // Add credentials if provided
        let transport = if let (Some(username), Some(password)) = 
            (&self.config.username, &self.config.password) 
        {
            builder
                .credentials(Credentials::new(username.clone(), password.clone()))
                .build()
        } else {
            builder.build()
        };

        self.transport = Some(transport);
        tracing::info!(
            host = %self.config.host,
            port = %self.config.port,
            tls = %self.config.tls,
            "SMTP transport initialized"
        );

        Ok(())
    }

    /// Create and initialize in one step
    pub fn create_and_init(config: SmtpConfig) -> Result<Self> {
        let mut provider = Self::new(config);
        provider.initialize()?;
        Ok(provider)
    }
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    fn name(&self) -> &'static str {
        "SMTP"
    }

    fn is_available(&self) -> bool {
        self.transport.is_some() && self.config.is_valid()
    }

    async fn send(&self, from: &str, from_name: &str, message: &EmailMessage) -> Result<()> {
        let transport = self.transport.as_ref().ok_or_else(|| {
            EmailError::Configuration("SMTP transport not initialized".to_string())
        })?;

        // Build from mailbox
        let from_mailbox: Mailbox = if from_name.is_empty() {
            from.parse().map_err(|e| EmailError::InvalidEmail(format!("From address: {e}")))?
        } else {
            format!("{from_name} <{from}>")
                .parse()
                .map_err(|e| EmailError::InvalidEmail(format!("From address: {e}")))?
        };

        // Build to mailbox
        let to_mailbox: Mailbox = match &message.to_name {
            Some(name) => format!("{} <{}>", name, message.to)
                .parse()
                .map_err(|e| EmailError::InvalidEmail(format!("To address: {e}")))?,
            None => message.to
                .parse()
                .map_err(|e| EmailError::InvalidEmail(format!("To address: {e}")))?,
        };

        // Build message body (multipart if both HTML and text provided)
        let email = if let Some(ref text_body) = message.text_body {
            Message::builder()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(&message.subject)
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(text_body.clone())
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(message.html_body.clone())
                        )
                )
                .map_err(|e| EmailError::Provider {
                    provider: self.name().to_string(),
                    message: e.to_string(),
                })?
        } else {
            Message::builder()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(&message.subject)
                .header(ContentType::TEXT_HTML)
                .body(message.html_body.clone())
                .map_err(|e| EmailError::Provider {
                    provider: self.name().to_string(),
                    message: e.to_string(),
                })?
        };

        // Send email via async transport
        match transport.send(email).await {
            Ok(response) => {
                tracing::info!(
                    provider = "SMTP",
                    to = %message.to,
                    subject = %message.subject,
                    response = ?response,
                    "Email sent successfully"
                );
                Ok(())
            }
            Err(e) => {
                let error_string = e.to_string();
                tracing::error!(
                    provider = "SMTP",
                    error = %error_string,
                    "SMTP send failed"
                );

                // Check for common SMTP errors
                if error_string.contains("451") || error_string.contains("421") {
                    // Server temporarily unavailable / rate limiting
                    return Err(EmailError::RateLimited {
                        provider: self.name().to_string(),
                        retry_after_secs: 60,
                    });
                }

                Err(EmailError::Provider {
                    provider: self.name().to_string(),
                    message: error_string,
                })
            }
        }
    }

    async fn health_check(&self) -> bool {
        if let Some(transport) = &self.transport {
            transport.test_connection().await.unwrap_or(false)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_not_initialized() {
        let config = SmtpConfig::new("smtp.example.com", 587);
        let provider = SmtpProvider::new(config);
        assert!(!provider.is_available());
        assert_eq!(provider.name(), "SMTP");
    }

    #[test]
    fn test_smtp_config() {
        let config = SmtpConfig::with_auth(
            "smtp.gmail.com",
            587,
            "user@gmail.com",
            "app-password",
        );
        assert!(config.is_valid());
        assert_eq!(config.host, "smtp.gmail.com");
        assert_eq!(config.port, 587);
        assert!(config.tls);
    }
}
