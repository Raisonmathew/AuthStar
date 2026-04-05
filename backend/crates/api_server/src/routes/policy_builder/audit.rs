//! Audit log query handlers.
//!
//! Two endpoints:
//! - `GET /policy-builder/configs/:id/audit` — audit for a specific config (TenantAdmin+)
//! - `GET /policy-builder/audit`             — all policy builder audit events for the tenant (TenantAdmin+)
//!
//! Both support cursor-based pagination via `?limit=` and `?before=` query params.

use super::permissions::{verify_config_ownership, Tier};
use super::types::*;
use crate::db::pool_manager::PoolType;
use crate::state::AppState;
use auth_core::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    Json,
};
use shared_types::AppError;

// ============================================================================
// Config-scoped audit
// ============================================================================

/// GET /policy-builder/configs/:id/audit
pub async fn get_config_audit(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(config_id): Path<String>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditPage>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;
    verify_config_ownership(&state.db, &config_id, &claims.tenant_id).await?;

    let limit = params.limit.unwrap_or(50).min(200) as i64;
    let read_pool = state.db_pools.get_pool(PoolType::Replica);

    let rows: Vec<AuditEntry> = if let Some(ref before) = params.before {
        sqlx::query!(
            r#"
            SELECT id, tenant_id, config_id, action_key, event_type,
                   actor_id, actor_ip, description, metadata, created_at
            FROM policy_builder_audit
            WHERE tenant_id = $1
              AND config_id = $2
              AND id < $3
            ORDER BY id DESC
            LIMIT $4
            "#,
            claims.tenant_id,
            config_id,
            before,
            limit
        )
        .fetch_all(read_pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
        .into_iter()
        .map(|r| AuditEntry {
            id: r.id,
            tenant_id: r.tenant_id,
            config_id: Some(r.config_id),
            action_key: Some(r.action_key),
            event_type: r.event_type,
            actor_id: r.actor_id,
            actor_ip: r.actor_ip,
            description: r.description,
            metadata: r.metadata,
            created_at: r.created_at,
        })
        .collect()
    } else {
        sqlx::query!(
            r#"
            SELECT id, tenant_id, config_id, action_key, event_type,
                   actor_id, actor_ip, description, metadata, created_at
            FROM policy_builder_audit
            WHERE tenant_id = $1
              AND config_id = $2
            ORDER BY id DESC
            LIMIT $3
            "#,
            claims.tenant_id,
            config_id,
            limit
        )
        .fetch_all(read_pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
        .into_iter()
        .map(|r| AuditEntry {
            id: r.id,
            tenant_id: r.tenant_id,
            config_id: Some(r.config_id),
            action_key: Some(r.action_key),
            event_type: r.event_type,
            actor_id: r.actor_id,
            actor_ip: r.actor_ip,
            description: r.description,
            metadata: r.metadata,
            created_at: r.created_at,
        })
        .collect()
    };

    let next_cursor = if rows.len() == limit as usize {
        rows.last().map(|r| r.id.clone())
    } else {
        None
    };

    Ok(Json(AuditPage {
        items: rows,
        next_cursor,
        limit: limit as u32,
    }))
}

// ============================================================================
// Tenant-wide audit
// ============================================================================

/// GET /policy-builder/audit
pub async fn get_tenant_audit(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditPage>, AppError> {
    Tier::from_user(&state.db, &claims).await?.require_admin()?;

    let limit = params.limit.unwrap_or(50).min(200) as i64;
    let read_pool = state.db_pools.get_pool(PoolType::Replica);

    // Optional filter by action_key
    let rows: Vec<AuditEntry> = if let Some(ref before) = params.before {
        if let Some(ref action_key) = params.action_key {
            sqlx::query!(
                r#"
                SELECT id, tenant_id, config_id, action_key, event_type,
                       actor_id, actor_ip, description, metadata, created_at
                FROM policy_builder_audit
                WHERE tenant_id = $1
                  AND action_key = $2
                  AND id < $3
                ORDER BY id DESC
                LIMIT $4
                "#,
                claims.tenant_id,
                action_key,
                before,
                limit
            )
            .fetch_all(read_pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
            .into_iter()
            .map(|r| AuditEntry {
                id: r.id,
                tenant_id: r.tenant_id,
                config_id: Some(r.config_id),
                action_key: Some(r.action_key),
                event_type: r.event_type,
                actor_id: r.actor_id,
                actor_ip: r.actor_ip,
                description: r.description,
                metadata: r.metadata,
                created_at: r.created_at,
            })
            .collect()
        } else {
            sqlx::query!(
                r#"
                SELECT id, tenant_id, config_id, action_key, event_type,
                       actor_id, actor_ip, description, metadata, created_at
                FROM policy_builder_audit
                WHERE tenant_id = $1
                  AND id < $2
                ORDER BY id DESC
                LIMIT $3
                "#,
                claims.tenant_id,
                before,
                limit
            )
            .fetch_all(read_pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
            .into_iter()
            .map(|r| AuditEntry {
                id: r.id,
                tenant_id: r.tenant_id,
                config_id: Some(r.config_id),
                action_key: Some(r.action_key),
                event_type: r.event_type,
                actor_id: r.actor_id,
                actor_ip: r.actor_ip,
                description: r.description,
                metadata: r.metadata,
                created_at: r.created_at,
            })
            .collect()
        }
    } else if let Some(ref action_key) = params.action_key {
        sqlx::query!(
            r#"
            SELECT id, tenant_id, config_id, action_key, event_type,
                   actor_id, actor_ip, description, metadata, created_at
            FROM policy_builder_audit
            WHERE tenant_id = $1
              AND action_key = $2
            ORDER BY id DESC
            LIMIT $3
            "#,
            claims.tenant_id,
            action_key,
            limit
        )
        .fetch_all(read_pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
        .into_iter()
        .map(|r| AuditEntry {
            id: r.id,
            tenant_id: r.tenant_id,
            config_id: Some(r.config_id),
            action_key: Some(r.action_key),
            event_type: r.event_type,
            actor_id: r.actor_id,
            actor_ip: r.actor_ip,
            description: r.description,
            metadata: r.metadata,
            created_at: r.created_at,
        })
        .collect()
    } else {
        sqlx::query!(
            r#"
            SELECT id, tenant_id, config_id, action_key, event_type,
                   actor_id, actor_ip, description, metadata, created_at
            FROM policy_builder_audit
            WHERE tenant_id = $1
            ORDER BY id DESC
            LIMIT $2
            "#,
            claims.tenant_id,
            limit
        )
        .fetch_all(read_pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch audit: {e}")))?
        .into_iter()
        .map(|r| AuditEntry {
            id: r.id,
            tenant_id: r.tenant_id,
            config_id: Some(r.config_id),
            action_key: Some(r.action_key),
            event_type: r.event_type,
            actor_id: r.actor_id,
            actor_ip: r.actor_ip,
            description: r.description,
            metadata: r.metadata,
            created_at: r.created_at,
        })
        .collect()
    };

    let next_cursor = if rows.len() == limit as usize {
        rows.last().map(|r| r.id.clone())
    } else {
        None
    };

    Ok(Json(AuditPage {
        items: rows,
        next_cursor,
        limit: limit as u32,
    }))
}
