//! AWS SES Email Provider
//!
//! Production implementation using AWS SES v2 API.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sesv2::{
    config::{Credentials, Region},
    types::{Body, Content, Destination, EmailContent, Message},
    Client,
};

use crate::config::SesConfig;
use crate::error::{EmailError, Result};
use super::{EmailMessage, EmailProvider};

/// AWS SES email provider
pub struct SesProvider {
    client: Option<Client>,
    config: SesConfig,
}

impl SesProvider {
    /// Create a new SES provider (must be initialized async)
    pub fn new(config: SesConfig) -> Self {
        Self {
            client: None,
            config,
        }
    }

    /// Initialize the SES client (call this during service startup)
    pub async fn initialize(&mut self) -> Result<()> {
        if !self.config.is_valid() {
            return Err(EmailError::Configuration("Invalid SES configuration".to_string()));
        }

        let region = Region::new(self.config.region.clone());

        let sdk_config = if let (Some(access_key), Some(secret_key)) = 
            (&self.config.access_key_id, &self.config.secret_access_key) 
        {
            // Use explicit credentials
            let credentials = Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "idaas-email-service",
            );
            
            aws_config::defaults(BehaviorVersion::latest())
                .region(region)
                .credentials_provider(credentials)
                .load()
                .await
        } else {
            // Use default credential chain (IAM roles, env vars, etc.)
            aws_config::defaults(BehaviorVersion::latest())
                .region(region)
                .load()
                .await
        };

        self.client = Some(Client::new(&sdk_config));
        tracing::info!(region = %self.config.region, "AWS SES client initialized");
        
        Ok(())
    }

    /// Create and initialize in one step
    pub async fn create_and_init(config: SesConfig) -> Result<Self> {
        let mut provider = Self::new(config);
        provider.initialize().await?;
        Ok(provider)
    }
}

#[async_trait]
impl EmailProvider for SesProvider {
    fn name(&self) -> &'static str {
        "AWS-SES"
    }

    fn is_available(&self) -> bool {
        self.client.is_some() && self.config.is_valid()
    }

    async fn send(&self, from: &str, from_name: &str, message: &EmailMessage) -> Result<()> {
        let client = self.client.as_ref().ok_or_else(|| {
            EmailError::Configuration("SES client not initialized".to_string())
        })?;

        // Build the formatted from address
        let from_address = if from_name.is_empty() {
            from.to_string()
        } else {
            format!("{from_name} <{from}>")
        };

        // Build to address
        let to_address = match &message.to_name {
            Some(name) => format!("{} <{}>", name, message.to),
            None => message.to.clone(),
        };

        // Build email body
        let mut body_builder = Body::builder();
        
        // Add HTML content
        body_builder = body_builder.html(
            Content::builder()
                .data(&message.html_body)
                .charset("UTF-8")
                .build()
                .map_err(|e| EmailError::Provider {
                    provider: self.name().to_string(),
                    message: e.to_string(),
                })?
        );

        // Add plain text if available
        if let Some(ref text) = message.text_body {
            body_builder = body_builder.text(
                Content::builder()
                    .data(text)
                    .charset("UTF-8")
                    .build()
                    .map_err(|e| EmailError::Provider {
                        provider: self.name().to_string(),
                        message: e.to_string(),
                    })?
            );
        }

        let email_content = EmailContent::builder()
            .simple(
                Message::builder()
                    .subject(
                        Content::builder()
                            .data(&message.subject)
                            .charset("UTF-8")
                            .build()
                            .map_err(|e| EmailError::Provider {
                                provider: self.name().to_string(),
                                message: e.to_string(),
                            })?
                    )
                    .body(body_builder.build())
                    .build()
            )
            .build();

        let result = client
            .send_email()
            .from_email_address(&from_address)
            .destination(
                Destination::builder()
                    .to_addresses(&to_address)
                    .build()
            )
            .content(email_content)
            .send()
            .await;

        match result {
            Ok(output) => {
                tracing::info!(
                    provider = "AWS-SES",
                    to = %message.to,
                    subject = %message.subject,
                    message_id = ?output.message_id(),
                    "Email sent successfully"
                );
                Ok(())
            }
            Err(e) => {
                let error_message = e.to_string();
                
                // Check for throttling
                if error_message.contains("Throttling") || error_message.contains("rate exceeded") {
                    return Err(EmailError::RateLimited {
                        provider: self.name().to_string(),
                        retry_after_secs: 60, // Default backoff
                    });
                }

                tracing::error!(
                    provider = "AWS-SES",
                    error = %error_message,
                    "SES send failed"
                );

                Err(EmailError::Provider {
                    provider: self.name().to_string(),
                    message: error_message,
                })
            }
        }
    }

    async fn health_check(&self) -> bool {
        if let Some(client) = &self.client {
            // Try to get account details as a health check
            match client.get_account().send().await {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(provider = "AWS-SES", error = %e, "Health check failed");
                    false
                }
            }
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
        let config = SesConfig::new("us-east-1");
        let provider = SesProvider::new(config);
        // Not available until initialized
        assert!(!provider.is_available());
        assert_eq!(provider.name(), "AWS-SES");
    }

    #[test]
    fn test_ses_config() {
        let config = SesConfig::with_credentials(
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert!(config.is_valid());
        assert_eq!(config.region, "us-east-1");
        assert!(config.access_key_id.is_some());
    }
}
