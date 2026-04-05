//! SendGrid Email Provider
//!
//! Production implementation using SendGrid v3 API.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::time::Duration;

use super::{EmailMessage, EmailProvider};
use crate::config::SendGridConfig;
use crate::error::{EmailError, Result};

/// SendGrid email provider
pub struct SendGridProvider {
    client: Client,
    config: SendGridConfig,
}

// SendGrid API request types
#[derive(Serialize)]
struct SendGridRequest {
    personalizations: Vec<SendGridPersonalization>,
    from: SendGridEmail,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    content: Vec<SendGridContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_id: Option<String>,
}

#[derive(Serialize)]
struct SendGridPersonalization {
    to: Vec<SendGridEmail>,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_template_data: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct SendGridEmail {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize)]
struct SendGridContent {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

impl SendGridProvider {
    const API_URL: &'static str = "https://api.sendgrid.com/v3/mail/send";

    /// Create a new SendGrid provider
    pub fn new(config: SendGridConfig, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { client, config }
    }
}

#[async_trait]
impl EmailProvider for SendGridProvider {
    fn name(&self) -> &'static str {
        "SendGrid"
    }

    fn is_available(&self) -> bool {
        self.config.is_valid()
    }

    async fn send(&self, from: &str, from_name: &str, message: &EmailMessage) -> Result<()> {
        // Build content array
        let mut content = vec![SendGridContent {
            content_type: "text/html".to_string(),
            value: message.html_body.clone(),
        }];

        // Add plain text if provided
        if let Some(ref text) = message.text_body {
            content.insert(
                0,
                SendGridContent {
                    content_type: "text/plain".to_string(),
                    value: text.clone(),
                },
            );
        }

        let request = SendGridRequest {
            personalizations: vec![SendGridPersonalization {
                to: vec![SendGridEmail {
                    email: message.to.clone(),
                    name: message.to_name.clone(),
                }],
                subject: message.subject.clone(),
                dynamic_template_data: None,
            }],
            from: SendGridEmail {
                email: from.to_string(),
                name: Some(from_name.to_string()),
            },
            content,
            template_id: None,
        };

        let response = self
            .client
            .post(Self::API_URL)
            .bearer_auth(&self.config.api_key)
            .json(&request)
            .send()
            .await
            .map_err(|e| EmailError::Provider {
                provider: self.name().to_string(),
                message: e.to_string(),
            })?;

        match response.status() {
            status if status.is_success() => {
                tracing::info!(
                    provider = "SendGrid",
                    to = %message.to,
                    subject = %message.subject,
                    "Email sent successfully"
                );
                Ok(())
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60);

                Err(EmailError::RateLimited {
                    provider: self.name().to_string(),
                    retry_after_secs: retry_after,
                })
            }
            StatusCode::UNAUTHORIZED => Err(EmailError::Configuration(
                "Invalid SendGrid API key".to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                tracing::error!(
                    provider = "SendGrid",
                    status = %status,
                    body = %body,
                    "SendGrid API error"
                );
                Err(EmailError::Provider {
                    provider: self.name().to_string(),
                    message: format!("HTTP {status}: {body}"),
                })
            }
        }
    }

    async fn health_check(&self) -> bool {
        // SendGrid doesn't have a dedicated health endpoint
        // We just check if API key is configured
        self.is_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_available() {
        let config = SendGridConfig::new("test-api-key");
        let provider = SendGridProvider::new(config, 30);
        assert!(provider.is_available());
        assert_eq!(provider.name(), "SendGrid");
    }

    #[test]
    fn test_provider_not_available() {
        let config = SendGridConfig::new("");
        let provider = SendGridProvider::new(config, 30);
        assert!(!provider.is_available());
    }
}
