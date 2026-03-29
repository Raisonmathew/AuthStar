use org_manager::services::OrganizationService;
use sqlx::PgPool;
use shared_types::AppError;

// Helper to seed user
async fn seed_user(pool: &PgPool, user_id: &str) {
    sqlx::query("INSERT INTO users (id, created_at, updated_at) VALUES ($1, NOW(), NOW())")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed user");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_organization(pool: PgPool) {
    let service = OrganizationService::new(pool.clone());
    seed_user(&pool, "user_1").await;
    
    let org = service.create_organization("user_1", "Acme Corp", None).await.expect("create org");
    
    assert_eq!(org.name, "Acme Corp");
    assert_eq!(org.slug, "acme-corp");
    
    // Check membership created
    let membership = service.get_membership(&org.id, "user_1").await.expect("get membership");
    assert!(membership.is_some());
    assert_eq!(membership.unwrap().role, "admin");
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_create_duplicate_slug(pool: PgPool) {
    let service = OrganizationService::new(pool.clone());
    seed_user(&pool, "user_1").await;
    seed_user(&pool, "user_2").await;
    
    service.create_organization("user_1", "Acme Corp", Some("acme")).await.expect("create org 1");
    
    let result = service.create_organization("user_2", "Acme Inc", Some("acme")).await;
    
    match result {
        Err(AppError::Conflict(msg)) => assert_eq!(msg, "Organization slug already exists"),
        _ => panic!("Expected Conflict error, got {:?}", result),
    }
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_add_remove_member(pool: PgPool) {
    let service = OrganizationService::new(pool.clone());
    seed_user(&pool, "user_1").await;
    seed_user(&pool, "user_2").await;

    let org = service.create_organization("user_1", "Acme Corp", None).await.expect("create org");
    
    // Add new member
    let member = service.add_member(&org.id, "user_2", "member").await.expect("add member");
    assert_eq!(member.user_id, "user_2");
    assert_eq!(member.role, "member");
    
    // Verify list
    let members = service.list_members(&org.id).await.expect("list members");
    assert_eq!(members.len(), 2);
    
    // Remove member
    service.remove_member(&org.id, "user_2").await.expect("remove member");
    
    let members_after = service.list_members(&org.id).await.expect("list members after");
    assert_eq!(members_after.len(), 1);
}

#[sqlx::test(migrations = "../db_migrations/migrations")]
#[ignore = "Requires DATABASE_URL to be set"]
async fn test_cannot_remove_last_admin(pool: PgPool) {
    let service = OrganizationService::new(pool.clone());
    seed_user(&pool, "user_1").await;
    seed_user(&pool, "user_2").await;

    let org = service.create_organization("user_1", "Acme Corp", None).await.expect("create org");
    
    // Try to remove the only admin (user_1)
    let result = service.remove_member(&org.id, "user_1").await;
    
    match result {
        Err(AppError::BadRequest(msg)) => assert_eq!(msg, "Cannot remove the last admin from organization"),
        _ => panic!("Expected BadRequest error, got {:?}", result),
    }
    
    // Add another admin
    service.add_member(&org.id, "user_2", "admin").await.expect("add admin");
    
    // Now removal should succeed
    service.remove_member(&org.id, "user_1").await.expect("remove admin");
}
