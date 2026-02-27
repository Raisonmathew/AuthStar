use identity_engine::services::UserService;
use shared_types::AppError;
use sqlx::PgPool;

// Helper to create a service instance with a clean test pool
fn create_service(pool: PgPool) -> UserService {
    UserService::new(pool)
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_create_user_success(pool: PgPool) {
    let service = create_service(pool);
    let email = "test_success@example.com";
    let password = "StrongPassword123!";

    // Action
    let user = service.create_user(email, password, Some("John"), Some("Doe"))
        .await
        .expect("Failed to create user");

    // Assert
    assert_eq!(user.first_name.as_deref(), Some("John"));
    assert_eq!(user.last_name.as_deref(), Some("Doe"));
    
    // Verify retrieval by ID
    let fetched = service.get_user(&user.id).await.expect("Failed to fetch user");
    assert_eq!(fetched.id, user.id);

    // Verify retrieval by Email
    let fetched_by_email = service.get_user_by_email(email).await.expect("Failed to fetch by email");
    assert_eq!(fetched_by_email.id, user.id);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_create_duplicate_email(pool: PgPool) {
    let service = create_service(pool);
    let email = "duplicate@example.com";
    let password = "StrongPassword123!";

    // Create first user
    service.create_user(email, password, None, None)
        .await
        .expect("Failed to create first user");

    // Attempt duplicate
    let result = service.create_user(email, "AnotherPassword123!", None, None).await;

    // Assert Conflict error
    match result {
        Err(AppError::Conflict(msg)) => assert_eq!(msg, "Email already registered"),
        _ => panic!("Expected Conflict error, got {:?}", result),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_create_user_invalid_email(pool: PgPool) {
    let service = create_service(pool);
    let email = "not-an-email";
    let password = "StrongPassword123!";

    let result = service.create_user(email, password, None, None).await;

    match result {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("Invalid email")),
        _ => panic!("Expected BadRequest for invalid email, got {:?}", result),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_create_user_weak_password(pool: PgPool) {
    let service = create_service(pool);
    let email = "weak@example.com";
    let password = "123"; // Too short

    let result = service.create_user(email, password, None, None).await;

    match result {
        Err(AppError::Validation(_)) => {}, // Expected
        _ => panic!("Expected Validation error for weak password, got {:?}", result),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_user_auth_success(pool: PgPool) {
    let service = create_service(pool);
    let email = "auth_valid@example.com";
    let password = "SecretPassword123!";

    let user = service.create_user(email, password, None, None).await.expect("Create user failed");

    // Verify correct password
    let valid = service.verify_user_password(&user.id, password).await.expect("Verification failed");
    assert!(valid, "Password should be valid");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_user_auth_wrong_password(pool: PgPool) {
    let service = create_service(pool);
    let email = "auth_invalid@example.com";
    let password = "SecretPassword123!";

    let user = service.create_user(email, password, None, None).await.expect("Create user failed");

    // Verify wrong password
    let invalid = service.verify_user_password(&user.id, "WrongPassword").await.expect("Verification check failed");
    assert!(!invalid, "Password should be invalid");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_get_user_not_found(pool: PgPool) {
    let service = create_service(pool);
    
    let result = service.get_user("non-existent-id").await;

    match result {
        Err(AppError::NotFound(_)) => {},
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}
