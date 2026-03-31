use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Params, Version,
};
use shared_types::{AppError, Result};

const MEMORY_SIZE: u32 = 65536; // 64 MB
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 4;

/// Hash a password using Argon2id
/// 
/// Parameters:
/// - Memory: 64 MB
/// - Iterations: 3
/// - Parallelism: 4
/// - Algorithm: Argon2id
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    
    let params = Params::new(MEMORY_SIZE, ITERATIONS, PARALLELISM, None)
        .map_err(|e| AppError::Internal(format!("Failed to create Argon2 params: {e}")))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {e}")))?
        .to_string();
    
    Ok(password_hash)
}

/// Verify a password against its hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;
    
    let argon2 = Argon2::default();
    
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "SecurePassword123!";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_hash_produces_different_hashes() {
        let password = "SamePassword123!";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        
        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
        
        // But both should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_hash_empty_password() {
        // Empty password should still hash (policy enforcement is separate)
        let result = hash_password("");
        assert!(result.is_ok());
        
        let hash = result.unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("non-empty", &hash).unwrap());
    }

    #[test]
    fn test_hash_unicode_password() {
        let password = "密码🔐пароль";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        // Random garbage is not a valid Argon2 hash
        let result = verify_password("password", "random-garbage");
        // The function should return an error for unparseable hashes
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_old_hash_from_different_password() {
        // Hash one password, then try to verify a different password
        let hash = hash_password("original_password").unwrap();
        let result = verify_password("different_password", &hash).unwrap();
        assert!(!result); // Should return false, not error
    }

    #[test]
    fn test_hash_contains_argon2id() {
        let hash = hash_password("password").unwrap();
        // Verify it's using Argon2id algorithm
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_case_sensitive() {
        let password = "Password";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password("Password", &hash).unwrap());
        assert!(!verify_password("password", &hash).unwrap());
        assert!(!verify_password("PASSWORD", &hash).unwrap());
    }
}
