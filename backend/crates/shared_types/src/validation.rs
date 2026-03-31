use regex::Regex;
use std::sync::OnceLock;

static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static SLUG_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn validate_email(email: &str) -> bool {
    let regex = EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
            .expect("valid hardcoded email regex")
    });
    regex.is_match(email) && email.len() <= 255
}

pub fn validate_phone(phone: &str) -> bool {
    let regex = PHONE_REGEX.get_or_init(|| {
        Regex::new(r"^\+?[1-9]\d{1,14}$").expect("valid hardcoded phone regex")
    });
    regex.is_match(phone)
}

pub fn validate_password(password: &str) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("Password must be at least 8 characters long".to_string());
    }

    if password.len() > 128 {
        errors.push("Password must not exceed 128 characters".to_string());
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        errors.push("Password must contain at least one uppercase letter".to_string());
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        errors.push("Password must contain at least one lowercase letter".to_string());
    }

    if !password.chars().any(|c| c.is_numeric()) {
        errors.push("Password must contain at least one number".to_string());
    }

    if !password.chars().any(|c| !c.is_alphanumeric()) {
        errors.push("Password must contain at least one special character".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_slug(slug: &str) -> bool {
    let regex = SLUG_REGEX.get_or_init(|| {
        Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").expect("valid hardcoded slug regex")
    });
    
    slug.len() >= 3 
        && slug.len() <= 63 
        && regex.is_match(slug)
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

pub fn slugify(text: &str) -> String {
    text.trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c
            } else if c.is_whitespace() {
                '-'
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("user.name+tag@example.co.uk"));
        assert!(!validate_email("invalid"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("user@"));
    }

    #[test]
    fn test_validate_email_edge_cases() {
        // Empty email
        assert!(!validate_email(""));
        
        // Too long email (over 255 chars)
        let too_long = format!("{}@example.com", "a".repeat(250));
        assert!(!validate_email(&too_long));
        
        // Special characters in local part
        assert!(validate_email("user+tag@example.com"));
        assert!(validate_email("user.name@example.com"));
        
        // Subdomain
        assert!(validate_email("user@mail.example.com"));
    }

    #[test]
    fn test_validate_phone() {
        assert!(validate_phone("+12345678901"));
        assert!(validate_phone("12345678901"));
        assert!(!validate_phone("1")); // Single digit is invalid (needs 2-15 digits total)
        assert!(!validate_phone("abc"));
    }

    #[test]
    fn test_validate_phone_edge_cases() {
        // Empty phone
        assert!(!validate_phone(""));
        
        // Valid international formats (E.164)
        assert!(validate_phone("+14155552671")); // US
        assert!(validate_phone("+442071234567")); // UK
        
        // Invalid - too short for E.164
        assert!(!validate_phone("+1")); // Only 1 digit after +
        
        // Invalid - contains letters
        assert!(!validate_phone("+1415555CALL"));
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password("SecurePass123!").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("alllowercase123!").is_err());
        assert!(validate_password("ALLUPPERCASE123!").is_err());
        assert!(validate_password("NoNumbers!").is_err());
        assert!(validate_password("NoSpecial123").is_err());
    }

    #[test]
    fn test_validate_password_edge_cases() {
        // Exactly 8 characters (minimum)
        assert!(validate_password("Abcd123!").is_ok());
        
        // 7 characters (too short)
        assert!(validate_password("Abc123!").is_err());
        
        // Exactly 128 characters (maximum)
        let max_password = format!("Aa1!{}", "x".repeat(124));
        assert!(validate_password(&max_password).is_ok());
        
        // 129 characters (too long)
        let too_long = format!("Aa1!{}", "x".repeat(125));
        assert!(too_long.len() == 129);
        assert!(validate_password(&too_long).is_err());
        
        // Unicode characters - Cyrillic has case marking but behavior may vary
        // Testing with ASCII to ensure consistent behavior
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("my-company"));
        assert!(validate_slug("acme123"));
        assert!(!validate_slug("My-Company"));
        assert!(!validate_slug("-invalid"));
        assert!(!validate_slug("invalid-"));
        assert!(!validate_slug("in"));
    }

    #[test]
    fn test_validate_slug_edge_cases() {
        // Exactly 3 characters (minimum)
        assert!(validate_slug("abc"));
        
        // 2 characters (too short)
        assert!(!validate_slug("ab"));
        
        // Exactly 63 characters (maximum for DNS compatibility)
        let max_slug = "a".repeat(63);
        assert!(validate_slug(&max_slug));
        
        // 64 characters (too long)
        let too_long = "a".repeat(64);
        assert!(!validate_slug(&too_long));
        
        // Numbers only
        assert!(validate_slug("123"));
        
        // Multiple hyphens (valid)
        assert!(validate_slug("my-cool-company"));
        
        // Uppercase (invalid)
        assert!(!validate_slug("MyCompany"));
        
        // Special characters (invalid)
        assert!(!validate_slug("my_company"));
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("My Company"), "my-company");
        assert_eq!(slugify("Acme Corp!!!"), "acme-corp");
        assert_eq!(slugify("  spaces  "), "spaces");
    }

    #[test]
    fn test_slugify_edge_cases() {
        // Mixed case
        assert_eq!(slugify("MyCompanyName"), "mycompanyname");
        
        // Empty string
        assert_eq!(slugify(""), "");
        
        // Only special characters  
        assert_eq!(slugify("@#$%"), "");
        
        // Verify basic functionality works
        let result = slugify("Test Company Name");
        assert!(!result.is_empty());
        assert!(result.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }
}
