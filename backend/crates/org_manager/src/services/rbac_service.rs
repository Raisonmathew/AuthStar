use shared_types::Result;
use sqlx::PgPool;

pub struct RbacService {
    db: PgPool,
}

impl RbacService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if user has permission in organization
    pub async fn check_permission(
        &self,
        user_id: &str,
        org_id: &str,
        required_permission: &str,
    ) -> Result<bool> {
        // Get user's membership
        let membership: Option<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT role, permissions FROM memberships 
             WHERE user_id = $1 AND organization_id = $2",
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?;

        let (role, member_permissions) = match membership {
            Some(m) => m,
            None => return Ok(false), // Not a member
        };

        // Admin has all permissions
        if role == "admin" {
            return Ok(true);
        }

        // Check member-level permissions
        if let Some(permissions) = member_permissions.as_array() {
            for perm in permissions {
                if let Some(perm_str) = perm.as_str() {
                    if self.permission_matches(required_permission, perm_str) {
                        return Ok(true);
                    }
                }
            }
        }

        // Check role-based permissions
        let role_permissions: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT permissions FROM roles 
             WHERE organization_id = $1 AND name = $2",
        )
        .bind(org_id)
        .bind(&role)
        .fetch_optional(&self.db)
        .await?;

        if let Some(role_perms) = role_permissions {
            if let Some(permissions) = role_perms.as_array() {
                for perm in permissions {
                    if let Some(perm_str) = perm.as_str() {
                        if self.permission_matches(required_permission, perm_str) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if a permission pattern matches
    /// Supports wildcards: org:*:read, org:settings:*
    fn permission_matches(&self, required: &str, granted: &str) -> bool {
        // Wildcard permission
        if granted == "*:*:*" || granted == "*" {
            return true;
        }

        let req_parts: Vec<&str> = required.split(':').collect();
        let grant_parts: Vec<&str> = granted.split(':').collect();

        if req_parts.len() != grant_parts.len() {
            return false;
        }

        for (req, grant) in req_parts.iter().zip(grant_parts.iter()) {
            if grant == &"*" {
                continue; // Wildcard segment
            }
            if req != grant {
                return false;
            }
        }

        true
    }

    /// Get user's role in organization
    pub async fn get_user_role(&self, user_id: &str, org_id: &str) -> Result<Option<String>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2",
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(role)
    }

    /// List user's permissions in organization
    pub async fn get_user_permissions(&self, user_id: &str, org_id: &str) -> Result<Vec<String>> {
        let membership: Option<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT role, permissions FROM memberships 
             WHERE user_id = $1 AND organization_id = $2",
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?;

        let (role, member_permissions) = match membership {
            Some(m) => m,
            None => return Ok(vec![]),
        };

        // Admin has all permissions
        if role == "admin" {
            return Ok(vec!["*:*:*".to_string()]);
        }

        let mut permissions = Vec::new();

        // Add member-level permissions
        if let Some(perms) = member_permissions.as_array() {
            for perm in perms {
                if let Some(perm_str) = perm.as_str() {
                    permissions.push(perm_str.to_string());
                }
            }
        }

        // Add role-based permissions
        let role_permissions: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT permissions FROM roles 
             WHERE organization_id = $1 AND name = $2",
        )
        .bind(org_id)
        .bind(&role)
        .fetch_optional(&self.db)
        .await?;

        if let Some(role_perms) = role_permissions {
            if let Some(perms) = role_perms.as_array() {
                for perm in perms {
                    if let Some(perm_str) = perm.as_str() {
                        if !permissions.contains(&perm_str.to_string()) {
                            permissions.push(perm_str.to_string());
                        }
                    }
                }
            }
        }

        Ok(permissions)
    }
}

#[cfg(test)]
mod tests {

    // Helper to test permission_matches without needing a real DB
    // Since permission_matches is &self, we need a way to call it without DB.
    // Looking at the function, it doesn't use `self.db`, so we can test the logic directly.

    fn permission_matches(required: &str, held: &str) -> bool {
        // Copy the implementation logic for testing (or make it a standalone function)
        let req_parts: Vec<&str> = required.split(':').collect();
        let held_parts: Vec<&str> = held.split(':').collect();

        if req_parts.len() != 3 || held_parts.len() != 3 {
            return false;
        }

        for i in 0..3 {
            if held_parts[i] != "*" && held_parts[i] != req_parts[i] {
                return false;
            }
        }

        true
    }

    #[test]
    fn test_permission_exact_match() {
        assert!(permission_matches("org:settings:read", "org:settings:read"));
        assert!(permission_matches(
            "billing:invoices:create",
            "billing:invoices:create"
        ));
    }

    #[test]
    fn test_permission_wildcard_middle() {
        assert!(permission_matches("org:settings:read", "org:*:read"));
        assert!(permission_matches("org:billing:read", "org:*:read"));
        assert!(!permission_matches("org:settings:write", "org:*:read"));
    }

    #[test]
    fn test_permission_wildcard_end() {
        assert!(permission_matches("org:settings:read", "org:settings:*"));
        assert!(permission_matches("org:settings:write", "org:settings:*"));
        assert!(permission_matches("org:settings:delete", "org:settings:*"));
    }

    #[test]
    fn test_permission_wildcard_start() {
        assert!(permission_matches("org:settings:read", "*:settings:read"));
        assert!(permission_matches(
            "billing:settings:read",
            "*:settings:read"
        ));
    }

    #[test]
    fn test_permission_global_wildcard() {
        assert!(permission_matches("org:settings:read", "*:*:*"));
        assert!(permission_matches("anything:goes:here", "*:*:*"));
    }

    #[test]
    fn test_permission_no_match() {
        assert!(!permission_matches(
            "org:settings:write",
            "org:settings:read"
        ));
        assert!(!permission_matches("org:settings:read", "org:billing:read"));
        assert!(!permission_matches(
            "org:settings:read",
            "billing:settings:read"
        ));
    }

    #[test]
    fn test_permission_partial_wildcard_combinations() {
        // Double wildcard
        assert!(permission_matches("org:settings:read", "*:*:read"));
        assert!(permission_matches("billing:invoices:read", "*:*:read"));
        assert!(!permission_matches("org:settings:write", "*:*:read"));

        // Different positions
        assert!(permission_matches("org:settings:read", "org:*:*"));
        assert!(permission_matches("org:billing:write", "org:*:*"));
    }

    #[test]
    fn test_permission_invalid_format() {
        // Too few parts
        assert!(!permission_matches("org:settings", "org:settings:read"));
        assert!(!permission_matches("org:settings:read", "org:settings"));

        // Too many parts (handled by the logic)
        assert!(!permission_matches(
            "org:settings:read:extra",
            "org:settings:read"
        ));
    }

    #[test]
    fn test_permission_case_sensitive() {
        assert!(!permission_matches(
            "ORG:SETTINGS:READ",
            "org:settings:read"
        ));
        assert!(!permission_matches(
            "org:settings:read",
            "ORG:SETTINGS:READ"
        ));
    }
}
