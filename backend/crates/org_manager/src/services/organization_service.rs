use crate::models::{Organization, Membership, Role};
use shared_types::{AppError, Result, generate_id, validation};
use sqlx::PgPool;

#[derive(Clone)]
pub struct OrganizationService {
    db: PgPool,
}

impl OrganizationService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new organization
    pub async fn create_organization(
        &self,
        user_id: &str,
        name: &str,
        slug: Option<&str>,
    ) -> Result<Organization> {
        // Generate or validate slug
        let slug = if let Some(s) = slug {
            if !validation::validate_slug(s) {
                return Err(AppError::BadRequest("Invalid slug format".to_string()));
            }
            s.to_string()
        } else {
            validation::slugify(name)
        };

        // Check if slug is available
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)"
        )
        .bind(&slug)
        .fetch_one(&self.db)
        .await?;

        if exists {
            return Err(AppError::Conflict("Organization slug already exists".to_string()));
        }

        // Start transaction
        let mut tx = self.db.begin().await?;

        // Create organization
        let org_id = generate_id("org");
        let org = sqlx::query_as::<_, Organization>(
            "INSERT INTO organizations (id, name, slug, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             RETURNING *"
        )
        .bind(&org_id)
        .bind(name)
        .bind(&slug)
        .fetch_one(&mut *tx)
        .await?;

        // Create membership for creator as admin
        sqlx::query(
            "INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
             VALUES ($1, $2, $3, 'admin', NOW(), NOW())"
        )
        .bind(generate_id("memb"))
        .bind(&org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(org)
    }

    /// Get organization by ID
    pub async fn get_organization(&self, org_id: &str) -> Result<Organization> {
        let org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL"
        )
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        Ok(org)
    }

    /// Get organization by slug
    pub async fn get_organization_by_slug(&self, slug: &str) -> Result<Organization> {
        let org = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE slug = $1 AND deleted_at IS NULL"
        )
        .bind(slug)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        Ok(org)
    }

    /// List user's organizations
    pub async fn list_user_organizations(&self, user_id: &str) -> Result<Vec<Organization>> {
        let orgs = sqlx::query_as::<_, Organization>(
            "SELECT o.* FROM organizations o
             INNER JOIN memberships m ON m.organization_id = o.id
             WHERE m.user_id = $1 AND o.deleted_at IS NULL
             ORDER BY o.created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        Ok(orgs)
    }

    /// Update organization
    pub async fn update_organization(
        &self,
        org_id: &str,
        name: Option<&str>,
        logo_url: Option<&str>,
        branding_config: Option<serde_json::Value>,
    ) -> Result<Organization> {
        let org = sqlx::query_as::<_, Organization>(
            "UPDATE organizations
             SET name = COALESCE($2, name),
                 logo_url = COALESCE($3, logo_url),
                 branding_config = COALESCE($4, branding_config),
                 updated_at = NOW()
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING *"
        )
        .bind(org_id)
        .bind(name)
        .bind(logo_url)
        .bind(branding_config)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        Ok(org)
    }

    /// Delete organization (soft delete)
    pub async fn delete_organization(&self, org_id: &str) -> Result<()> {
        let result = sqlx::query(
            "UPDATE organizations SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL"
        )
        .bind(org_id)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Organization not found".to_string()));
        }

        Ok(())
    }

    /// Get organization membership for user
    pub async fn get_membership(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<Membership>> {
        let membership = sqlx::query_as::<_, Membership>(
            "SELECT * FROM memberships WHERE organization_id = $1 AND user_id = $2"
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(membership)
    }

    /// List organization members
    pub async fn list_members(&self, org_id: &str) -> Result<Vec<Membership>> {
        let members = sqlx::query_as::<_, Membership>(
            "SELECT * FROM memberships WHERE organization_id = $1 ORDER BY created_at ASC"
        )
        .bind(org_id)
        .fetch_all(&self.db)
        .await?;

        Ok(members)
    }

    /// Add a member to organization by user_id
    /// Returns the new membership, or error if user is already a member
    pub async fn add_member(
        &self,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<Membership> {
        // Check if already a member
        let existing = self.get_membership(org_id, user_id).await?;
        if existing.is_some() {
            return Err(AppError::Conflict("User is already a member of this organization".to_string()));
        }

        // Create membership
        let membership = sqlx::query_as::<_, Membership>(
            "INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             RETURNING *"
        )
        .bind(generate_id("memb"))
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .fetch_one(&self.db)
        .await?;

        Ok(membership)
    }


    /// Remove member from organization
    pub async fn remove_member(&self, org_id: &str, user_id: &str) -> Result<()> {
        // Check if this is the last admin
        let admin_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM memberships WHERE organization_id = $1 AND role = 'admin'"
        )
        .bind(org_id)
        .fetch_one(&self.db)
        .await?;

        let is_admin: bool = sqlx::query_scalar(
            "SELECT role = 'admin' FROM memberships WHERE organization_id = $1 AND user_id = $2"
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await?;

        if is_admin && admin_count <= 1 {
            return Err(AppError::BadRequest(
                "Cannot remove the last admin from organization".to_string()
            ));
        }

        let result = sqlx::query(
            "DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2"
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Membership not found".to_string()));
        }

        Ok(())
    }

    /// Update member role
    pub async fn update_member_role(
        &self,
        org_id: &str,
        user_id: &str,
        new_role: &str,
    ) -> Result<Membership> {
        let membership = sqlx::query_as::<_, Membership>(
            "UPDATE memberships
             SET role = $3, updated_at = NOW()
             WHERE organization_id = $1 AND user_id = $2
             RETURNING *"
        )
        .bind(org_id)
        .bind(user_id)
        .bind(new_role)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

        Ok(membership)
    }

    // Role Management

    /// Create a new custom role
    pub async fn create_role(
        &self,
        org_id: &str,
        name: &str,
        description: Option<&str>,
        permissions: Vec<String>,
    ) -> Result<Role> {
        let role_id = generate_id("role");
        let permissions_json = serde_json::to_value(permissions)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let role = sqlx::query_as::<_, Role>(
            "INSERT INTO roles (id, organization_id, name, description, permissions, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             RETURNING *"
        )
        .bind(role_id)
        .bind(org_id)
        .bind(name)
        .bind(description)
        .bind(permissions_json)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("unique constraint") {
                AppError::Conflict("Role name already exists".to_string())
            } else {
                AppError::from(e)
            }
        })?;

        Ok(role)
    }

    /// List roles for an organization
    pub async fn get_roles(&self, org_id: &str) -> Result<Vec<Role>> {
        let roles = sqlx::query_as::<_, Role>(
            "SELECT * FROM roles WHERE organization_id = $1 ORDER BY name ASC"
        )
        .bind(org_id)
        .fetch_all(&self.db)
        .await?;

        Ok(roles)
    }

    /// Delete a custom role
    pub async fn delete_role(&self, org_id: &str, role_id: &str) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM roles WHERE id = $1 AND organization_id = $2 AND is_system_role = FALSE"
        )
        .bind(role_id)
        .bind(org_id)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Role not found or is a system role".to_string()));
        }

        Ok(())
    }
}
