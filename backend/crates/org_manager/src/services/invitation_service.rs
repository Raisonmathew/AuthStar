use crate::models::Invitation;
use shared_types::{Result, generate_id};
use sqlx::PgPool;
use chrono::{Duration, Utc};

pub struct InvitationService {
    db: PgPool,
}

impl InvitationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create_invitation(
        &self,
        org_id: &str,
        email: &str,
        role: &str,
        inviter_user_id: &str,
    ) -> Result<Invitation> {
        let token = self.generate_token();
        let expires_at = Utc::now() + Duration::days(7);

        let invitation = sqlx::query_as::<_, Invitation>(
            "INSERT INTO org_invitations 
             (id, organization_id, email_address, role, inviter_user_id, token, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
             RETURNING *"
        )
        .bind(generate_id("inv"))
        .bind(org_id)
        .bind(email)
        .bind(role)
        .bind(inviter_user_id)
        .bind(&token)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await?;

        Ok(invitation)
    }

    fn generate_token(&self) -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }
}
