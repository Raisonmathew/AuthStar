use org_manager::services::InvitationService;
use sqlx::PgPool;

#[sqlx::test(migrations = "../db_migrations/migrations")]
async fn test_create_invitation(pool: PgPool) {
    let service = InvitationService::new(pool.clone());
    
    // Create dummy org
    let org_id = "org_test";
    sqlx::query("INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1, 'Test Org', 'test-org', NOW(), NOW())")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("create dummy org");
        
    // Seed inviter user
    let inviter_id = "inviter_1";
    sqlx::query("INSERT INTO users (id, created_at, updated_at) VALUES ($1, NOW(), NOW())")
        .bind(inviter_id)
        .execute(&pool)
        .await
        .expect("seed user");

    let invitation = service.create_invitation(
        org_id, 
        "test@example.com", 
        "member", 
        inviter_id
    ).await.expect("create invitation");
    
    assert_eq!(invitation.email_address, "test@example.com");
    assert_eq!(invitation.role, "member");
    assert_eq!(invitation.organization_id, org_id);
    assert!(invitation.token.len() > 10);
}
