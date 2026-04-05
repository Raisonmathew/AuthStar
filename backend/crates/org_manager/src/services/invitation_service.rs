use crate::models::Invitation;
use chrono::{Duration, Utc};
use shared_types::{generate_id, AppError, Result};
use sqlx::PgPool;

#[derive(Clone)]
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

    /// Look up a pending invitation by its unique token.
    /// Returns None if the token doesn't exist, is expired, or already accepted/revoked.
    pub async fn get_by_token(&self, token: &str) -> Result<Option<Invitation>> {
        let invitation = sqlx::query_as::<_, Invitation>(
            "SELECT * FROM org_invitations WHERE token = $1 AND status = 'pending' AND expires_at > NOW()"
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?;

        Ok(invitation)
    }

    /// Accept an invitation: update status, create membership, return the invitation.
    /// The caller must provide the accepting user's ID.
    pub async fn accept_invitation(
        &self,
        token: &str,
        accepting_user_id: &str,
    ) -> Result<Invitation> {
        // 1. Fetch and validate the invitation
        let invitation = self.get_by_token(token).await?.ok_or_else(|| {
            AppError::NotFound("Invitation not found, expired, or already used".into())
        })?;

        // 2. Check if user is already a member
        let already_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id = $1 AND user_id = $2)",
        )
        .bind(&invitation.organization_id)
        .bind(accepting_user_id)
        .fetch_one(&self.db)
        .await?;

        if already_member {
            // Mark invitation as accepted even though they're already a member
            sqlx::query(
                "UPDATE org_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = $1",
            )
            .bind(&invitation.id)
            .execute(&self.db)
            .await?;

            return Err(AppError::Conflict(
                "You are already a member of this organization".into(),
            ));
        }

        // 3. Create the membership + mark invitation accepted in a transaction
        let mut tx = self.db.begin().await?;

        sqlx::query(
            "INSERT INTO memberships (id, organization_id, user_id, role, created_at)
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(generate_id("mem"))
        .bind(&invitation.organization_id)
        .bind(accepting_user_id)
        .bind(&invitation.role)
        .execute(&mut *tx)
        .await?;

        let updated = sqlx::query_as::<_, Invitation>(
            "UPDATE org_invitations SET status = 'accepted', accepted_at = NOW()
             WHERE id = $1 RETURNING *",
        )
        .bind(&invitation.id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(updated)
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
