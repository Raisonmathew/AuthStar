//! Email Template Engine
//!
//! Handlebars-based templating with built-in email templates.

use handlebars::Handlebars;
use once_cell::sync::Lazy;

use crate::error::{EmailError, Result};

/// Global template registry (initialized once)
static TEMPLATES: Lazy<Handlebars<'static>> = Lazy::new(|| {
    let mut hbs = Handlebars::new();
    hbs.set_strict_mode(true);
    
    // Register all built-in templates
    register_templates(&mut hbs);
    
    hbs
});

/// Email template types
#[derive(Clone, Debug)]
pub enum EmailTemplate {
    /// Email verification code
    VerificationCode { code: String },
    /// Password reset link
    PasswordReset { reset_link: String, expires_in: String },
    /// Welcome email for new users
    WelcomeEmail { user_name: String, login_url: String },
    /// MFA backup codes
    MfaBackupCodes { codes: Vec<String> },
    /// Login alert notification
    LoginAlert { ip_address: String, location: String, time: String, device: String },
    /// Account locked notification
    AccountLocked { unlock_link: String, reason: String },
    /// Password changed notification
    PasswordChanged { time: String },
    /// MFA enabled notification
    MfaEnabled { time: String, method: String },
    /// Custom template with dynamic data
    Custom { template_name: String, data: serde_json::Value },
}

impl EmailTemplate {
    /// Get the template name
    pub fn template_name(&self) -> &str {
        match self {
            Self::VerificationCode { .. } => "verification_code",
            Self::PasswordReset { .. } => "password_reset",
            Self::WelcomeEmail { .. } => "welcome",
            Self::MfaBackupCodes { .. } => "mfa_backup_codes",
            Self::LoginAlert { .. } => "login_alert",
            Self::AccountLocked { .. } => "account_locked",
            Self::PasswordChanged { .. } => "password_changed",
            Self::MfaEnabled { .. } => "mfa_enabled",
            Self::Custom { template_name, .. } => template_name,
        }
    }

    /// Get the email subject
    pub fn subject(&self) -> String {
        match self {
            Self::VerificationCode { .. } => "Your Verification Code".to_string(),
            Self::PasswordReset { .. } => "Reset Your Password".to_string(),
            Self::WelcomeEmail { user_name, .. } => format!("Welcome to IDaaS, {user_name}!"),
            Self::MfaBackupCodes { .. } => "Your MFA Backup Codes".to_string(),
            Self::LoginAlert { .. } => "New Login Detected".to_string(),
            Self::AccountLocked { .. } => "Account Security Alert".to_string(),
            Self::PasswordChanged { .. } => "Your Password Was Changed".to_string(),
            Self::MfaEnabled { .. } => "Two-Factor Authentication Enabled".to_string(),
            Self::Custom { .. } => "Notification".to_string(),
        }
    }
}

/// Template engine for rendering email content
pub struct TemplateEngine {
    /// Custom organization branding
    branding: EmailBranding,
}

/// Organization branding for emails
#[derive(Clone, Debug, Default)]
pub struct EmailBranding {
    /// Company/organization name
    pub company_name: String,
    /// Logo URL
    pub logo_url: Option<String>,
    /// Primary brand color (hex)
    pub primary_color: String,
    /// Support email
    pub support_email: Option<String>,
    /// Terms of service URL
    pub terms_url: Option<String>,
    /// Privacy policy URL
    pub privacy_url: Option<String>,
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self {
            branding: EmailBranding {
                company_name: "IDaaS".to_string(),
                primary_color: "#2563eb".to_string(),
                ..Default::default()
            },
        }
    }
}

impl TemplateEngine {
    /// Create a new template engine with default branding
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom branding
    pub fn with_branding(branding: EmailBranding) -> Self {
        Self { branding }
    }

    /// Render an email template to HTML
    pub fn render(&self, template: &EmailTemplate) -> Result<String> {
        let template_name = template.template_name();
        let data = self.build_template_data(template);

        TEMPLATES
            .render(template_name, &data)
            .map_err(|e| EmailError::TemplateRender(e.to_string()))
    }

    /// Build template data including branding
    fn build_template_data(&self, template: &EmailTemplate) -> serde_json::Value {
        let mut data = match template {
            EmailTemplate::VerificationCode { code } => {
                serde_json::json!({ "code": code })
            }
            EmailTemplate::PasswordReset { reset_link, expires_in } => {
                serde_json::json!({ 
                    "reset_link": reset_link,
                    "expires_in": expires_in
                })
            }
            EmailTemplate::WelcomeEmail { user_name, login_url } => {
                serde_json::json!({ 
                    "user_name": user_name,
                    "login_url": login_url
                })
            }
            EmailTemplate::MfaBackupCodes { codes } => {
                serde_json::json!({ "codes": codes })
            }
            EmailTemplate::LoginAlert { ip_address, location, time, device } => {
                serde_json::json!({ 
                    "ip_address": ip_address,
                    "location": location,
                    "time": time,
                    "device": device
                })
            }
            EmailTemplate::AccountLocked { unlock_link, reason } => {
                serde_json::json!({ 
                    "unlock_link": unlock_link,
                    "reason": reason
                })
            }
            EmailTemplate::PasswordChanged { time } => {
                serde_json::json!({ "time": time })
            }
            EmailTemplate::MfaEnabled { time, method } => {
                serde_json::json!({ 
                    "time": time,
                    "method": method
                })
            }
            EmailTemplate::Custom { data, .. } => {
                data.clone()
            }
        };

        // Add branding to all templates
        if let serde_json::Value::Object(ref mut map) = data {
            map.insert("company_name".to_string(), serde_json::json!(self.branding.company_name));
            map.insert("primary_color".to_string(), serde_json::json!(self.branding.primary_color));
            if let Some(ref logo) = self.branding.logo_url {
                map.insert("logo_url".to_string(), serde_json::json!(logo));
            }
            if let Some(ref email) = self.branding.support_email {
                map.insert("support_email".to_string(), serde_json::json!(email));
            }
            if let Some(ref url) = self.branding.terms_url {
                map.insert("terms_url".to_string(), serde_json::json!(url));
            }
            if let Some(ref url) = self.branding.privacy_url {
                map.insert("privacy_url".to_string(), serde_json::json!(url));
            }
        }

        data
    }
}

/// Register all built-in templates
fn register_templates(hbs: &mut Handlebars<'static>) {
    // Base layout partial
    hbs.register_template_string("base_layout", include_str!("base_layout.hbs"))
        .expect("Failed to register base_layout template");

    // Individual templates
    hbs.register_template_string("verification_code", include_str!("verification_code.hbs"))
        .expect("Failed to register verification_code template");

    hbs.register_template_string("password_reset", include_str!("password_reset.hbs"))
        .expect("Failed to register password_reset template");

    hbs.register_template_string("welcome", include_str!("welcome.hbs"))
        .expect("Failed to register welcome template");

    hbs.register_template_string("mfa_backup_codes", include_str!("mfa_backup_codes.hbs"))
        .expect("Failed to register mfa_backup_codes template");

    hbs.register_template_string("login_alert", include_str!("login_alert.hbs"))
        .expect("Failed to register login_alert template");

    hbs.register_template_string("account_locked", include_str!("account_locked.hbs"))
        .expect("Failed to register account_locked template");

    hbs.register_template_string("password_changed", include_str!("password_changed.hbs"))
        .expect("Failed to register password_changed template");

    hbs.register_template_string("mfa_enabled", include_str!("mfa_enabled.hbs"))
        .expect("Failed to register mfa_enabled template");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_code_subject() {
        let template = EmailTemplate::VerificationCode { code: "123456".to_string() };
        assert_eq!(template.subject(), "Your Verification Code");
        assert_eq!(template.template_name(), "verification_code");
    }

    #[test]
    fn test_welcome_subject() {
        let template = EmailTemplate::WelcomeEmail { 
            user_name: "John".to_string(),
            login_url: "https://app.example.com".to_string(),
        };
        assert_eq!(template.subject(), "Welcome to IDaaS, John!");
    }

    #[test]
    fn test_render_verification_code() {
        let engine = TemplateEngine::new();
        let template = EmailTemplate::VerificationCode { code: "123456".to_string() };
        let html = engine.render(&template).unwrap();
        
        assert!(html.contains("123456"));
        assert!(html.contains("IDaaS")); // Company name from branding
    }

    #[test]
    fn test_custom_branding() {
        let branding = EmailBranding {
            company_name: "My Company".to_string(),
            primary_color: "#ff0000".to_string(),
            logo_url: Some("https://example.com/logo.png".to_string()),
            ..Default::default()
        };
        let engine = TemplateEngine::with_branding(branding);
        let template = EmailTemplate::VerificationCode { code: "123456".to_string() };
        let html = engine.render(&template).unwrap();
        
        assert!(html.contains("My Company"));
        assert!(html.contains("#ff0000"));
    }
}
