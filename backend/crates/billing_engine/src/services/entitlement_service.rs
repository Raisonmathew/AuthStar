use serde_json::Value;
use shared_types::{AppError, Result};
use sqlx::PgPool;

#[derive(Clone)]
pub struct EntitlementService {
    db: PgPool,
}

impl EntitlementService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Retrieve the JSON entitlements for the organization's active plan.
    /// Falls back to default "free" entitlements if no active subscription exists.
    pub async fn get_active_entitlements(&self, org_id: &str) -> Result<Value> {
        let features: Option<Value> = sqlx::query_scalar(
            r#"
            SELECT p.features
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            WHERE s.organization_id = $1 AND s.status = 'active'
            ORDER BY s.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(format!("DB error fetching entitlements: {e}")))?;

        // Default Free Tier Limits
        Ok(features.unwrap_or_else(|| {
            serde_json::json!({
                "max_members": 5,
                "features": ["basic_auth", "basic_org"]
            })
        }))
    }

    /// Check if organization has access to a generic feature flag (e.g., "sso", "audit_logs").
    pub async fn can_use_feature(&self, org_id: &str, feature: &str) -> Result<bool> {
        let entitlements = self.get_active_entitlements(org_id).await?;

        // 1. Check "features" array
        if let Some(list) = entitlements.get("features").and_then(|v| v.as_array()) {
            if list.iter().any(|v| v.as_str() == Some(feature)) {
                return Ok(true);
            }
        }

        // 2. Check boolean keys (e.g. "sso": true)
        if let Some(val) = entitlements.get(feature).and_then(|v| v.as_bool()) {
            return Ok(val);
        }

        Ok(false)
    }

    /// Check if organization can add a new member based on "max_members" limit.
    pub async fn can_add_member(&self, org_id: &str) -> Result<bool> {
        let entitlements = self.get_active_entitlements(org_id).await?;

        let limit = entitlements
            .get("max_members")
            .and_then(|v| v.as_i64())
            .unwrap_or(5); // Default strict limit

        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM memberships WHERE organization_id = $1")
                .bind(org_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Internal(format!("DB error fetching count: {e}")))?;

        Ok(member_count < limit)
    }

    /// Get current plan tier name (e.g. "Pro", "Free")
    pub async fn get_plan_tier(&self, org_id: &str) -> Result<String> {
        let plan_name: Option<String> = sqlx::query_scalar(
            r#"
            SELECT p.name
            FROM subscriptions s
            JOIN plans p ON s.plan_id = p.id
            WHERE s.organization_id = $1 AND s.status = 'active'
            ORDER BY s.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .fetch_optional(&self.db)
        .await?;

        Ok(plan_name.unwrap_or_else(|| "Free".to_string()))
    }
}
