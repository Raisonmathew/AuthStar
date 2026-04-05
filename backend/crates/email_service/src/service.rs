//! Main Email Service
//!
//! Orchestrates email sending across multiple providers with automatic failover.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::EmailServiceConfig;
use crate::error::{EmailError, Result};
use crate::providers::{EmailMessage, EmailProvider, SendGridProvider, SesProvider, SmtpProvider};
use crate::templates::{EmailBranding, EmailTemplate, TemplateEngine};

struct InnerEmailService {
    config: EmailServiceConfig,
    providers: Vec<Box<dyn EmailProvider>>,
    template_engine: TemplateEngine,
}

/// Production-ready email service with multi-provider support
/// Uses Arc internally to share state between clones cheaply
pub struct EmailService {
    inner: Arc<InnerEmailService>,
}

impl EmailService {
    /// Create a new email service (sync initialization for SendGrid/SMTP)
    pub fn new(config: EmailServiceConfig) -> Self {
        let mut providers: Vec<Box<dyn EmailProvider>> = Vec::new();

        // Add SendGrid provider if configured
        if let Some(ref sg_config) = config.sendgrid {
            if sg_config.is_valid() {
                providers.push(Box::new(SendGridProvider::new(
                    sg_config.clone(),
                    config.provider_timeout_secs,
                )));
                tracing::info!("SendGrid provider configured");
            }
        }

        // Note: SES requires async initialization, use with_ses() or initialize_ses()

        // Add SMTP provider if configured
        if let Some(ref smtp_config) = config.smtp {
            if smtp_config.is_valid() {
                match SmtpProvider::create_and_init(smtp_config.clone()) {
                    Ok(provider) => {
                        providers.push(Box::new(provider));
                        tracing::info!("SMTP provider configured");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to initialize SMTP provider: {}", e);
                    }
                }
            }
        }

        Self::with_providers(config, providers)
    }

    /// Internal/Testing: Create service with specific providers
    pub fn with_providers(
        config: EmailServiceConfig,
        providers: Vec<Box<dyn EmailProvider>>,
    ) -> Self {
        Self {
            inner: Arc::new(InnerEmailService {
                config,
                providers,
                template_engine: TemplateEngine::new(),
            }),
        }
    }

    /// Initialize SES provider (must be called if SES is configured)
    /// Note: This replaces the inner Arc content, so other clones won't see this change unless they re-clone/sync.
    /// This design assumes initialization happens BEFORE cloning/distribution.
    pub async fn initialize_ses(&mut self) -> Result<()> {
        // Because of Arc, we need to handle mutability carefully.
        // We only modify during initialization. If we are shared, we'd need a Mutex.
        // Assuming this is called at startup before high concurrency.
        // HOWEVER, since we're replacing the whole inner, we need to be careful.
        // For simplicity in this `Arc` refactor, let's clone inner, modify, and replace.
        // This is expensive but only happens once at startup.

        if let Some(ref ses_config) = self.inner.config.ses {
            if ses_config.is_valid() {
                let provider = SesProvider::create_and_init(ses_config.clone()).await?;

                // Need to reconstruct Inner to inject provider
                // This is a bit tricky with Box<dyn> cloning, which isn't auto-derived.
                // But we only need this for `initialize_ses`.
                // Actually, `providers` store Box<dyn EmailProvider>, which isn't Clone.
                // This suggests `initialize_ses` mutating `self` is problematic with `Arc`.
                // BUT, `initialize_ses` is typically called on the "master" instance before cloning.
                // We'll use `Arc::get_mut` if possible, or fail if already shared.

                if let Some(inner_mut) = Arc::get_mut(&mut self.inner) {
                    // We possess the only reference
                    // Insert SES after SendGrid (index 1) or at start if no SendGrid
                    let insert_pos =
                        if inner_mut.providers.first().map(|p| p.name()) == Some("SendGrid") {
                            1
                        } else {
                            0
                        };
                    inner_mut.providers.insert(insert_pos, Box::new(provider));
                    tracing::info!("AWS SES provider initialized");
                } else {
                    return Err(EmailError::Configuration(
                        "Cannot initialize SES on shared EmailService".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Create email service with SES already initialized
    pub async fn new_with_ses(config: EmailServiceConfig) -> Result<Self> {
        let mut service = Self::new(config);
        service.initialize_ses().await?;
        Ok(service)
    }

    /// Set custom branding for email templates
    pub fn with_branding(mut self, branding: EmailBranding) -> Self {
        if let Some(inner_mut) = Arc::get_mut(&mut self.inner) {
            inner_mut.template_engine = TemplateEngine::with_branding(branding);
        } else {
            // Fallback: This is expensive/impossible if TemplateEngine !Clone or providers !Clone.
            // But branding is usually set at startup.
            // For now, assume single ownership context.
            tracing::warn!("Cannot apply branding to shared EmailService");
        }
        self
    }

    /// Check if any providers are available
    pub fn has_providers(&self) -> bool {
        self.inner.providers.iter().any(|p| p.is_available())
    }

    /// Get list of available provider names
    pub fn available_providers(&self) -> Vec<&'static str> {
        self.inner
            .providers
            .iter()
            .filter(|p| p.is_available())
            .map(|p| p.name())
            .collect()
    }

    /// Send a templated email with automatic provider failover
    pub async fn send_template(&self, to_email: &str, template: EmailTemplate) -> Result<()> {
        // Validate email address
        if !Self::is_valid_email(to_email) {
            return Err(EmailError::InvalidEmail(to_email.to_string()));
        }

        // Render template
        let html_content = self.inner.template_engine.render(&template)?;
        let subject = template.subject();

        // Create message
        let message = EmailMessage::new(to_email, subject, html_content);

        // Send with retry and failover
        self.send_with_failover(&message).await
    }

    /// Send a raw HTML email (for custom content)
    pub async fn send_raw(&self, to_email: &str, subject: &str, html_body: &str) -> Result<()> {
        if !Self::is_valid_email(to_email) {
            return Err(EmailError::InvalidEmail(to_email.to_string()));
        }

        let message = EmailMessage::new(to_email, subject, html_body);
        self.send_with_failover(&message).await
    }

    /// Convenience method: send verification code
    pub async fn send_verification_code(&self, to_email: &str, code: &str) -> Result<()> {
        self.send_template(
            to_email,
            EmailTemplate::VerificationCode {
                code: code.to_string(),
            },
        )
        .await
    }

    /// Convenience method: send password reset
    pub async fn send_password_reset(&self, to_email: &str, reset_link: &str) -> Result<()> {
        self.send_template(
            to_email,
            EmailTemplate::PasswordReset {
                reset_link: reset_link.to_string(),
                expires_in: "1 hour".to_string(),
            },
        )
        .await
    }

    /// Convenience method: send welcome email
    pub async fn send_welcome(
        &self,
        to_email: &str,
        user_name: &str,
        login_url: &str,
    ) -> Result<()> {
        self.send_template(
            to_email,
            EmailTemplate::WelcomeEmail {
                user_name: user_name.to_string(),
                login_url: login_url.to_string(),
            },
        )
        .await
    }

    /// Convenience method: send MFA backup codes
    pub async fn send_backup_codes(&self, to_email: &str, codes: Vec<String>) -> Result<()> {
        self.send_template(to_email, EmailTemplate::MfaBackupCodes { codes })
            .await
    }

    /// Convenience method: send login alert
    pub async fn send_login_alert(
        &self,
        to_email: &str,
        ip: &str,
        location: &str,
        time: &str,
        device: &str,
    ) -> Result<()> {
        self.send_template(
            to_email,
            EmailTemplate::LoginAlert {
                ip_address: ip.to_string(),
                location: location.to_string(),
                time: time.to_string(),
                device: device.to_string(),
            },
        )
        .await
    }

    /// Internal: send with retry and automatic failover between providers
    async fn send_with_failover(&self, message: &EmailMessage) -> Result<()> {
        let available_providers: Vec<_> = self
            .inner
            .providers
            .iter()
            .filter(|p| p.is_available())
            .collect();

        if available_providers.is_empty() {
            // GAP-3 FIX: In production, fail loudly when no email providers are configured.
            // Without this, the calling service (auth_flow, signup) receives Ok(()) and
            // assumes the OTP/verification email was sent — the user is permanently stuck.
            let is_dev = std::env::var("APP_ENV")
                .map(|v| v.to_lowercase() != "production")
                .unwrap_or(true);

            if is_dev {
                // Dev mode: log email instead of sending
                tracing::warn!(
                    to = %message.to,
                    subject = %message.subject,
                    "No email providers configured - email not sent (dev mode)"
                );
                tracing::debug!(
                    html_body = %message.html_body,
                    "Email content (dev mode)"
                );
                return Ok(());
            }

            return Err(EmailError::Send(
                "No email providers configured — cannot send email in production. \
                 Configure SENDGRID_API_KEY, SES, or SMTP."
                    .into(),
            ));
        }

        let mut last_error = None;

        for provider in &available_providers {
            match self.send_with_retry(provider.as_ref(), message).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(
                        provider = provider.name(),
                        error = %e,
                        "Provider failed, trying next"
                    );
                    last_error = Some(e);

                    // Don't try other providers if fallback is disabled
                    if !self.inner.config.fallback_enabled {
                        break;
                    }
                }
            }
        }

        Err(EmailError::AllProvidersFailed(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }

    /// Internal: send with exponential backoff retry
    async fn send_with_retry(
        &self,
        provider: &dyn EmailProvider,
        message: &EmailMessage,
    ) -> Result<()> {
        let mut last_error = None;

        for attempt in 0..=self.inner.config.max_retries {
            match provider
                .send(
                    &self.inner.config.from_email,
                    &self.inner.config.from_name,
                    message,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // Don't retry on configuration errors
                    if matches!(
                        e,
                        EmailError::Configuration(_) | EmailError::InvalidEmail(_)
                    ) {
                        return Err(e);
                    }

                    last_error = Some(e);

                    if attempt < self.inner.config.max_retries {
                        let delay_ms = self.inner.config.retry_base_delay_ms * 2u64.pow(attempt);
                        tracing::debug!(
                            provider = provider.name(),
                            attempt = attempt + 1,
                            delay_ms = delay_ms,
                            "Retrying after delay"
                        );
                        sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(EmailError::Provider {
            provider: provider.name().to_string(),
            message: "Max retries exceeded".to_string(),
        }))
    }

    /// Validate email address format
    fn is_valid_email(email: &str) -> bool {
        email_address::EmailAddress::is_valid(email)
    }
}

// Clone now just clones the Arc - CHEAP and NO LOGGING!
impl Clone for EmailService {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SendGridConfig;

    #[test]
    fn test_no_providers_dev_mode() {
        let config = EmailServiceConfig::default();
        let service = EmailService::new(config);
        assert!(!service.has_providers());
        assert!(service.available_providers().is_empty());
    }

    #[test]
    fn test_sendgrid_provider_added() {
        let config = EmailServiceConfig::builder()
            .sendgrid(SendGridConfig::new("test-api-key"))
            .build();
        let service = EmailService::new(config);
        assert!(service.has_providers());
        assert!(service.available_providers().contains(&"SendGrid"));
    }

    #[test]
    fn test_email_validation() {
        assert!(EmailService::is_valid_email("test@example.com"));
        assert!(EmailService::is_valid_email("user.name+tag@domain.co.uk"));
        assert!(!EmailService::is_valid_email("invalid"));
        assert!(!EmailService::is_valid_email("@nodomain.com"));
        assert!(!EmailService::is_valid_email("noat.com"));
    }

    #[tokio::test]
    async fn test_send_without_providers_dev_mode() {
        let config = EmailServiceConfig::default();
        let service = EmailService::new(config);

        // Should succeed in dev mode (just logs)
        let result = service
            .send_verification_code("test@example.com", "123456")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_invalid_email() {
        let config = EmailServiceConfig::builder()
            .sendgrid(SendGridConfig::new("test-key"))
            .build();
        let service = EmailService::new(config);

        let result = service
            .send_verification_code("invalid-email", "123456")
            .await;
        assert!(matches!(result, Err(EmailError::InvalidEmail(_))));
    }
}
