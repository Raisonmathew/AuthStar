use async_trait::async_trait;
use email_service::{
    EmailError, EmailMessage, EmailProvider, EmailService, EmailServiceConfig, Result,
};
use std::sync::{Arc, Mutex};

// --- Mock Provider ---

#[derive(Clone)]
struct MockProvider {
    name: &'static str,
    should_fail: bool,
    calls: Arc<Mutex<Vec<String>>>, // Track calls by recording "to" address
}

impl MockProvider {
    fn new(name: &'static str, should_fail: bool) -> Self {
        Self {
            name,
            should_fail,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl EmailProvider for MockProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn send(&self, _from: &str, _from_name: &str, message: &EmailMessage) -> Result<()> {
        self.calls.lock().unwrap().push(message.to.clone());
        if self.should_fail {
            Err(EmailError::Provider {
                provider: self.name.to_string(),
                message: "Mock failure".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

// --- Tests ---

#[tokio::test]
async fn test_provider_failover_success() {
    // Setup: Provider 1 fails, Provider 2 succeeds
    let p1 = MockProvider::new("Provider1", true); // Fails
    let p2 = MockProvider::new("Provider2", false); // Succeeds

    let config = EmailServiceConfig {
        fallback_enabled: true,
        max_retries: 0,
        ..Default::default()
    };

    let service = EmailService::with_providers(
        config,
        vec![Box::new(p1.clone()), Box::new(p2.clone())], // Register in order
    );

    // Act
    let result = service
        .send_raw("test@example.com", "Subject", "Body")
        .await;

    // Assert
    assert!(result.is_ok(), "Email should succeed via failover");
    assert_eq!(p1.call_count(), 1, "Provider 1 should be called");
    assert_eq!(p2.call_count(), 1, "Provider 2 should be called");
}

#[tokio::test]
async fn test_provider_priority_success() {
    // Setup: Provider 1 succeeds, Provider 2 should NOT be called
    let p1 = MockProvider::new("Provider1", false); // Succeeds
    let p2 = MockProvider::new("Provider2", false); // Succeeds (but unused)

    let config = EmailServiceConfig {
        fallback_enabled: true,
        max_retries: 0,
        ..Default::default()
    };

    let service =
        EmailService::with_providers(config, vec![Box::new(p1.clone()), Box::new(p2.clone())]);

    // Act
    let result = service
        .send_raw("test@example.com", "Subject", "Body")
        .await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(p1.call_count(), 1, "Provider 1 should be called");
    assert_eq!(p2.call_count(), 0, "Provider 2 should NOT be called");
}

#[tokio::test]
async fn test_all_providers_fail() {
    // Setup: Both providers fail
    let p1 = MockProvider::new("Provider1", true);
    let p2 = MockProvider::new("Provider2", true);

    let config = EmailServiceConfig {
        fallback_enabled: true,
        max_retries: 0,
        ..Default::default()
    };

    let service =
        EmailService::with_providers(config, vec![Box::new(p1.clone()), Box::new(p2.clone())]);

    // Act
    let result = service
        .send_raw("test@example.com", "Subject", "Body")
        .await;

    // Assert
    assert!(result.is_err(), "Should fail if all providers fail");
    match result.unwrap_err() {
        EmailError::AllProvidersFailed(_) => (), // Expected
        e => panic!("Unexpected error type: {e}"),
    }

    assert_eq!(p1.call_count(), 1);
    assert_eq!(p2.call_count(), 1);
}

#[tokio::test]
async fn test_fallback_disabled() {
    // Setup: Provider 1 fails, Fallback DISABLED
    let p1 = MockProvider::new("Provider1", true);
    let p2 = MockProvider::new("Provider2", false); // Succeeds (but shouldn't be reached)

    let config = EmailServiceConfig {
        fallback_enabled: false,
        max_retries: 0,
        ..Default::default()
    };

    let service =
        EmailService::with_providers(config, vec![Box::new(p1.clone()), Box::new(p2.clone())]);

    // Act
    let result = service
        .send_raw("test@example.com", "Subject", "Body")
        .await;

    // Assert
    assert!(
        result.is_err(),
        "Should fail immediately if fallback is disabled"
    );
    assert_eq!(p1.call_count(), 1);
    assert_eq!(
        p2.call_count(),
        0,
        "Provider 2 should not be called when fallback is disabled"
    );
}
