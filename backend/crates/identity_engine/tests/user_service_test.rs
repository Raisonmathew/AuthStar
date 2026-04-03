use identity_engine::services::{UserService, CreateSessionParams};
use shared_types::AppError;
use sqlx::PgPool;

// Helper to create a service instance with a clean test pool
fn create_service(pool: PgPool) -> UserService {
    UserService::new(pool)
}

/// Create a test user and return (user_id, email).
async fn seed_test_user(service: &UserService, email: &str) -> String {
    let user = service
        .create_user(email, "StrongPassword123!", Some("Test"), None, Some("org_test"))
        .await
        .expect("seed_test_user failed");
    user.id
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_user_success(pool: PgPool) {
    let service = create_service(pool.clone());
    let email = "test_success@example.com";
    let password = "StrongPassword123!";

    // Action
    let user = service.create_user(email, password, Some("John"), Some("Doe"), None)
        .await
        .expect("Failed to create user");

    // Assert
    assert_eq!(user.first_name.as_deref(), Some("John"));
    assert_eq!(user.last_name.as_deref(), Some("Doe"));
    
    // Verify retrieval by ID
    let fetched = service.get_user(&user.id).await.expect("Failed to fetch user");
    assert_eq!(fetched.id, user.id);

    // Mark email as verified for the test (get_user_by_email strictly requires verified=true)
    sqlx::query("UPDATE identities SET verified = true WHERE user_id = $1 AND type = 'email'")
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("Failed to manually verify email");

    // Verify retrieval by Email
    let fetched_by_email = service.get_user_by_email(email).await.expect("Failed to fetch by email");
    assert_eq!(fetched_by_email.id, user.id);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_duplicate_email(pool: PgPool) {
    let service = create_service(pool);
    let email = "duplicate@example.com";
    let password = "StrongPassword123!";

    // Create first user
    service.create_user(email, password, None, None, None)
        .await
        .expect("Failed to create first user");

    // Attempt duplicate
    let result = service.create_user(email, "AnotherPassword123!", None, None, None).await;

    // Assert Conflict error
    match result {
        Err(AppError::Conflict(msg)) => assert_eq!(msg, "Email already registered"),
        _ => panic!("Expected Conflict error, got {result:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_user_invalid_email(pool: PgPool) {
    let service = create_service(pool);
    let email = "not-an-email";
    let password = "StrongPassword123!";

    let result = service.create_user(email, password, None, None, None).await;

    match result {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("Invalid email")),
        _ => panic!("Expected BadRequest for invalid email, got {result:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_user_weak_password(pool: PgPool) {
    let service = create_service(pool);
    let email = "weak@example.com";
    let password = "123"; // Too short

    let result = service.create_user(email, password, None, None, None).await;

    match result {
        Err(AppError::Validation(_)) => {}, // Expected
        _ => panic!("Expected Validation error for weak password, got {result:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_user_auth_success(pool: PgPool) {
    let service = create_service(pool);
    let email = "auth_valid@example.com";
    let password = "SecretPassword123!";

    let user = service.create_user(email, password, None, None, None).await.expect("Create user failed");

    // Verify correct password
    let valid = service.verify_user_password(&user.id, password).await.expect("Verification failed");
    assert!(valid, "Password should be valid");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_user_auth_wrong_password(pool: PgPool) {
    let service = create_service(pool);
    let email = "auth_invalid@example.com";
    let password = "SecretPassword123!";

    let user = service.create_user(email, password, None, None, None).await.expect("Create user failed");

    // Verify wrong password
    let invalid = service.verify_user_password(&user.id, "WrongPassword").await.expect("Verification check failed");
    assert!(!invalid, "Password should be invalid");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_user_not_found(pool: PgPool) {
    let service = create_service(pool);
    
    let result = service.get_user("non-existent-id").await;

    match result {
        Err(AppError::NotFound(_)) => {},
        _ => panic!("Expected NotFound, got {result:?}"),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Org-Scoped Multi-Tenant Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_user_with_org_id(pool: PgPool) {
    let service = create_service(pool.clone());

    let user = service
        .create_user("org_user@example.com", "StrongPassword123!", Some("Alice"), None, Some("org_alpha"))
        .await
        .expect("Create user with org_id should succeed");

    // Identity should have organization_id set
    let row: (Option<String>,) = sqlx::query_as(
        "SELECT organization_id FROM identities WHERE user_id = $1 AND type = 'email'"
    )
    .bind(&user.id)
    .fetch_one(&pool)
    .await
    .expect("Should find identity");

    assert_eq!(row.0.as_deref(), Some("org_alpha"), "Identity should have org_alpha");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_same_email_different_orgs_allowed(pool: PgPool) {
    let service = create_service(pool.clone());
    let email = "shared@example.com";
    let password = "StrongPassword123!";

    // Create in org A
    let user_a = service
        .create_user(email, password, None, None, Some("org_a"))
        .await
        .expect("Create in org_a should succeed");

    // Create same email in org B — should NOT conflict
    let user_b = service
        .create_user(email, password, None, None, Some("org_b"))
        .await
        .expect("Create same email in org_b should succeed");

    assert_ne!(user_a.id, user_b.id, "Different users in different orgs");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_duplicate_email_in_same_org_rejected(pool: PgPool) {
    let service = create_service(pool);
    let email = "dup_org@example.com";
    let password = "StrongPassword123!";

    service
        .create_user(email, password, None, None, Some("org_x"))
        .await
        .expect("First create should succeed");

    let result = service
        .create_user(email, "AnotherPassword123!", None, None, Some("org_x"))
        .await;

    match result {
        Err(AppError::Conflict(msg)) => assert_eq!(msg, "Email already registered"),
        _ => panic!("Expected Conflict for duplicate in same org, got {result:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_user_by_email_in_org_returns_correct_user(pool: PgPool) {
    let service = create_service(pool.clone());
    let email = "lookup@example.com";
    let password = "StrongPassword123!";

    // Create in org_1 and org_2
    let user_1 = service
        .create_user(email, password, Some("Org1"), None, Some("org_1"))
        .await
        .expect("Create in org_1");

    let _user_2 = service
        .create_user(email, password, Some("Org2"), None, Some("org_2"))
        .await
        .expect("Create in org_2");

    // Mark both as verified
    sqlx::query("UPDATE identities SET verified = true WHERE type = 'email'")
        .execute(&pool)
        .await
        .unwrap();

    // Scoped lookup should return only the org_1 user
    let found = service
        .get_user_by_email_in_org(email, "org_1")
        .await
        .expect("Scoped lookup should succeed");

    assert_eq!(found.id, user_1.id, "Should return org_1 user");
    assert_eq!(found.first_name.as_deref(), Some("Org1"));
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_user_by_email_in_org_not_found_wrong_org(pool: PgPool) {
    let service = create_service(pool.clone());

    service
        .create_user("isolated@example.com", "StrongPassword123!", None, None, Some("org_real"))
        .await
        .expect("Create in org_real");

    sqlx::query("UPDATE identities SET verified = true WHERE type = 'email'")
        .execute(&pool)
        .await
        .unwrap();

    // Lookup in a different org should NOT find this user
    let result = service
        .get_user_by_email_in_org("isolated@example.com", "org_other")
        .await;

    match result {
        Err(AppError::NotFound(_)) => {},
        _ => panic!("Expected NotFound for wrong org, got {result:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_get_user_by_email_in_org_requires_verified(pool: PgPool) {
    let service = create_service(pool);

    // Create user but do NOT mark as verified
    service
        .create_user("unverified@example.com", "StrongPassword123!", None, None, Some("org_v"))
        .await
        .expect("Create user");

    // Scoped lookup for unverified email should fail
    let result = service
        .get_user_by_email_in_org("unverified@example.com", "org_v")
        .await;

    match result {
        Err(AppError::NotFound(_)) => {},
        _ => panic!("Expected NotFound for unverified email, got {result:?}"),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Account Lockout Tests (HIGH-1)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_account_lockout_after_max_failed_attempts(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "lockout@example.com").await;

    // 5 wrong attempts should lock the account
    for i in 0..5 {
        let result = service.verify_user_password(&user_id, "WrongPassword!").await;
        if i < 4 {
            // First 4 attempts: returns false (not locked yet)
            assert_eq!(result.unwrap(), false, "Attempt {i} should return false");
        } else {
            // 5th attempt: triggers lockout → returns Unauthorized
            assert!(result.is_err(), "5th attempt should lock the account");
        }
    }

    // 6th attempt on locked account → Unauthorized immediately
    let locked_result = service.verify_user_password(&user_id, "StrongPassword123!").await;
    match locked_result {
        Err(AppError::Unauthorized(msg)) => assert!(msg.contains("locked"), "Should mention locked: {msg}"),
        other => panic!("Expected Unauthorized for locked account, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_successful_login_resets_failed_attempts(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "reset_attempts@example.com").await;

    // 3 wrong attempts (below threshold)
    for _ in 0..3 {
        let _ = service.verify_user_password(&user_id, "WrongPassword!").await;
    }

    // Correct password resets the counter
    let valid = service.verify_user_password(&user_id, "StrongPassword123!").await.unwrap();
    assert!(valid, "Correct password should succeed");

    // Verify counter is reset: 5 more attempts before lockout possible
    let attempts_row: (i32,) = sqlx::query_as(
        "SELECT COALESCE(failed_login_attempts, 0) FROM users WHERE id = $1"
    )
    .bind(&user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attempts_row.0, 0, "Failed attempts should be reset to 0");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_admin_unlock_restores_access(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "unlock@example.com").await;

    // Lock account with 5 wrong attempts
    for _ in 0..5 {
        let _ = service.verify_user_password(&user_id, "WrongPassword!").await;
    }

    // Verify locked
    let locked_result = service.verify_user_password(&user_id, "StrongPassword123!").await;
    assert!(locked_result.is_err(), "Should be locked");

    // Admin unlock
    service.unlock_user(&user_id).await.expect("Unlock should succeed");

    // Verify access restored
    let unlocked_result = service.verify_user_password(&user_id, "StrongPassword123!").await;
    assert_eq!(unlocked_result.unwrap(), true, "Should be unlocked and password valid");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Password History Tests (HIGH-G)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_password_change_success(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "pwchange@example.com").await;

    service
        .change_password(&user_id, "StrongPassword123!", "NewStrongPass456!")
        .await
        .expect("Password change should succeed");

    // Verify new password works
    let valid = service.verify_user_password(&user_id, "NewStrongPass456!").await.unwrap();
    assert!(valid, "New password should work");

    // Verify old password no longer works
    let invalid = service.verify_user_password(&user_id, "StrongPassword123!").await.unwrap();
    assert!(!invalid, "Old password should not work");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_password_change_wrong_current_rejected(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "pwwrong@example.com").await;

    let result = service.change_password(&user_id, "WrongCurrent!", "NewPassword456!").await;
    match result {
        Err(AppError::Unauthorized(msg)) => assert!(msg.contains("incorrect"), "Error: {msg}"),
        other => panic!("Expected Unauthorized, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_password_reuse_rejected(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "pwreuse@example.com").await;
    let original = "StrongPassword123!";

    // Change to a different password
    service
        .change_password(&user_id, original, "SecondPassword456!")
        .await
        .expect("First change should succeed");

    // Try to reuse the original password → should be rejected
    let result = service.change_password(&user_id, "SecondPassword456!", original).await;
    match result {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("last"), "Should mention history: {msg}"),
        other => panic!("Expected BadRequest for password reuse, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_password_change_weak_new_password_rejected(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "pwweak@example.com").await;

    let result = service.change_password(&user_id, "StrongPassword123!", "123").await;
    match result {
        Err(AppError::Validation(_)) => {},
        other => panic!("Expected Validation error for weak password, got {other:?}"),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Session Management Tests (R-4 / EIAA)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_session_with_decision_ref(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "session@example.com").await;

    // Seed org for foreign key
    sqlx::query("INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ('org_test', 'Test Org', 'test-org', NOW(), NOW()) ON CONFLICT DO NOTHING")
        .execute(&pool)
        .await
        .unwrap();

    let session = service.create_session(CreateSessionParams {
        user_id: &user_id,
        tenant_id: "org_test",
        decision_ref: Some("dec_test_123"),
        assurance_level: "aal1",
        verified_capabilities: serde_json::json!(["password"]),
        is_provisional: false,
        session_type: "end_user",
        device_id: None,
        expires_in_secs: Some(3600),
    }).await.expect("Session creation should succeed");

    assert!(session.session_id.starts_with("sess_"), "Session ID should have prefix");
    assert!(session.session_token.starts_with("stok_"), "Token should have prefix");

    // Verify decision_ref is stored
    let row: (Option<String>,) = sqlx::query_as(
        "SELECT decision_ref FROM sessions WHERE id = $1"
    )
    .bind(&session.session_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0.as_deref(), Some("dec_test_123"), "decision_ref should be persisted");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_provisional_session(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "provisional@example.com").await;

    sqlx::query("INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ('org_test', 'Test Org', 'test-org', NOW(), NOW()) ON CONFLICT DO NOTHING")
        .execute(&pool)
        .await
        .unwrap();

    let session = service.create_session(CreateSessionParams {
        user_id: &user_id,
        tenant_id: "org_test",
        decision_ref: None,
        assurance_level: "aal1",
        verified_capabilities: serde_json::json!(["password"]),
        is_provisional: true,
        session_type: "end_user",
        device_id: Some("device_abc"),
        expires_in_secs: Some(300),
    }).await.expect("Provisional session creation should succeed");

    // Verify is_provisional and device_id stored
    let row: (bool, Option<String>) = sqlx::query_as(
        "SELECT is_provisional, device_id FROM sessions WHERE id = $1"
    )
    .bind(&session.session_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(row.0, "Session should be provisional");
    assert_eq!(row.1.as_deref(), Some("device_abc"), "device_id should be stored");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_invalidate_other_sessions_concurrent(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "concurrent@example.com").await;

    sqlx::query("INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ('org_test', 'Test Org', 'test-org', NOW(), NOW()) ON CONFLICT DO NOTHING")
        .execute(&pool)
        .await
        .unwrap();

    // Create 10 sessions
    let mut session_ids = Vec::new();
    for i in 0..10 {
        let sess = service.create_session(CreateSessionParams {
            user_id: &user_id,
            tenant_id: "org_test",
            decision_ref: Some(&format!("dec_{i}")),
            assurance_level: "aal1",
            verified_capabilities: serde_json::json!(["password"]),
            is_provisional: false,
            session_type: "end_user",
            device_id: None,
            expires_in_secs: Some(3600),
        }).await.unwrap();
        session_ids.push(sess.session_id);
    }

    // Keep the last session, invalidate everything else
    let current = session_ids.last().unwrap();
    let revoked_count = service.invalidate_other_sessions(&user_id, current).await.unwrap();
    assert_eq!(revoked_count, 9, "Should revoke 9 of 10 sessions");

    // Verify the kept session is not revoked
    let kept: (bool,) = sqlx::query_as("SELECT revoked FROM sessions WHERE id = $1")
        .bind(current)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!kept.0, "Current session should NOT be revoked");

    // Verify all others are revoked
    let revoked: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked = TRUE"
    )
    .bind(&user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked.0, 9, "9 sessions should be revoked");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Soft Delete & Edge Cases
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_soft_delete_excludes_from_lookup(pool: PgPool) {
    let service = create_service(pool.clone());
    let user_id = seed_test_user(&service, "softdel@example.com").await;

    // Soft delete
    service.delete_user(&user_id).await.expect("Delete should succeed");

    // Lookup by ID should fail
    let result = service.get_user(&user_id).await;
    match result {
        Err(AppError::NotFound(_)) => {},
        other => panic!("Expected NotFound after soft delete, got {other:?}"),
    }

    // Double delete should fail
    let result2 = service.delete_user(&user_id).await;
    match result2 {
        Err(AppError::NotFound(_)) => {},
        other => panic!("Expected NotFound for double delete, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_update_nonexistent_user_returns_not_found(pool: PgPool) {
    let service = create_service(pool);

    let result = service.update_user("nonexistent_id", Some("Name"), None, None).await;
    match result {
        Err(AppError::NotFound(_)) => {},
        other => panic!("Expected NotFound, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_user_response_contains_identity_info(pool: PgPool) {
    let service = create_service(pool.clone());
    let email = "response_test@example.com";
    let user = service
        .create_user(email, "StrongPassword123!", Some("Alice"), Some("Smith"), Some("org_resp"))
        .await
        .unwrap();

    // Mark email as verified
    sqlx::query("UPDATE identities SET verified = true WHERE user_id = $1")
        .execute(&pool)
        .await
        .unwrap();

    let response = service.to_user_response(&user).await.unwrap();

    assert_eq!(response.email.as_deref(), Some(email));
    assert!(response.email_verified, "Email should be verified");
    assert!(!response.mfa_enabled, "MFA should not be enabled by default");
    assert_eq!(response.first_name.as_deref(), Some("Alice"));
    assert_eq!(response.last_name.as_deref(), Some("Smith"));
}
