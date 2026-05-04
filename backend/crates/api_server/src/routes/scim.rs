//! SCIM 2.0 HTTP Routes (RFC 7644)
//!
//! Base path: `/scim/v2` (tenant-specific, authenticated via SCIM Bearer token)
//!
//! ## Authentication
//! Every request must carry `Authorization: Bearer <scim_token>`.
//! The token is validated by `ScimService::validate_token()`, which SHA-256 hashes
//! the raw token and looks it up in `scim_tokens`. On success the `tenant_id` is
//! extracted and stored as a request extension for downstream handlers.
//!
//! ## Endpoints implemented
//! - `GET  /scim/v2/ServiceProviderConfig` — RFC 7644 §4 discovery (unauthenticated)
//! - `GET  /scim/v2/Schemas`              — RFC 7643 §7 schema catalog (unauthenticated)
//! - `GET  /scim/v2/Users`                — list users (filter + pagination)
//! - `POST /scim/v2/Users`                — create user
//! - `GET  /scim/v2/Users/:id`            — get user
//! - `PUT  /scim/v2/Users/:id`            — full replace
//! - `DELETE /scim/v2/Users/:id`          — deprovision (sets active=false)
//! - `GET  /scim/v2/Groups`               — list groups
//! - `POST /scim/v2/Groups`               — create group
//! - `GET  /scim/v2/Groups/:id`           — get group
//! - `PUT  /scim/v2/Groups/:id`           — full replace
//! - `DELETE /scim/v2/Groups/:id`         — delete group
//!
//! ## Admin token management (JWT-protected, nested under /api/admin/v1/scim)
//! - `GET  /api/admin/v1/scim/tokens`     — list tokens
//! - `POST /api/admin/v1/scim/tokens`     — create token
//! - `DELETE /api/admin/v1/scim/tokens/:id` — revoke token

use crate::services::scim_service::{
    ScimGroupWrite, ScimListQuery, ScimUserWrite,
};
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::json;
use shared_types::{AppError, Result};

// ─── Tenant-from-SCIM-token extractor ────────────────────────────────────────

/// Extracted from a valid SCIM Bearer token; injected as a request extension.
#[derive(Clone, Debug)]
pub struct ScimTenant(pub String);

/// Axum middleware: validates the SCIM Bearer token and injects `ScimTenant`.
pub async fn scim_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let raw_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let raw_token = match raw_token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(scim_error("Authentication required", StatusCode::UNAUTHORIZED)),
            )
                .into_response();
        }
    };

    match state.scim_service.validate_token(&raw_token).await {
        Ok(tenant_id) => {
            req.extensions_mut().insert(ScimTenant(tenant_id));
            next.run(req).await
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(scim_error("Invalid or expired SCIM token", StatusCode::UNAUTHORIZED)),
        )
            .into_response(),
    }
}

fn scim_error(detail: &str, status: StatusCode) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": status.as_u16()
    })
}

// ─── Discovery (public, no auth) ─────────────────────────────────────────────

pub fn discovery_router() -> Router<AppState> {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/Schemas", get(schemas))
}

async fn service_provider_config() -> Json<serde_json::Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.authstar.io/scim",
        "patch": { "supported": false },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "type": "oauthbearertoken",
                "primary": true
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig"
        }
    }))
}

async fn schemas() -> Json<serde_json::Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "itemsPerPage": 2,
        "startIndex": 1,
        "Resources": [
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                "name": "User",
                "description": "User Account",
                "attributes": [
                    { "name": "userName", "type": "string", "required": true, "uniqueness": "server" },
                    { "name": "name", "type": "complex", "required": false },
                    { "name": "emails", "type": "complex", "multiValued": true, "required": false },
                    { "name": "active", "type": "boolean", "required": false },
                    { "name": "externalId", "type": "string", "required": false }
                ]
            },
            {
                "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
                "name": "Group",
                "description": "Group",
                "attributes": [
                    { "name": "displayName", "type": "string", "required": true },
                    { "name": "members", "type": "complex", "multiValued": true, "required": false },
                    { "name": "externalId", "type": "string", "required": false }
                ]
            }
        ]
    }))
}

// ─── Authenticated SCIM resource router ──────────────────────────────────────

/// Router for SCIM resource endpoints. The SCIM Bearer auth middleware
/// (`scim_auth`) is applied in router.rs via `.layer(middleware::from_fn_with_state(...))`.
pub fn resource_router() -> Router<AppState> {
    Router::new()
        // Users
        .route("/Users", get(list_users).post(create_user))
        .route(
            "/Users/:id",
            get(get_user).put(replace_user).delete(delete_user),
        )
        // Groups
        .route("/Groups", get(list_groups).post(create_group))
        .route(
            "/Groups/:id",
            get(get_group).put(replace_group).delete(delete_group),
        )
}

// ─── User handlers ────────────────────────────────────────────────────────────

async fn list_users(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Query(query): Query<ScimListQuery>,
) -> Result<impl IntoResponse> {
    let result = state
        .scim_service
        .list_users(&tenant.0, &query)
        .await?;
    Ok((StatusCode::OK, Json(result)))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Json(body): Json<ScimUserWrite>,
) -> Result<impl IntoResponse> {
    let user = state.scim_service.create_user(&tenant.0, &body).await?;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let user = state.scim_service.get_user(&tenant.0, &id).await?;
    Ok(Json(user))
}

async fn replace_user(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
    Json(body): Json<ScimUserWrite>,
) -> Result<impl IntoResponse> {
    let user = state.scim_service.replace_user(&tenant.0, &id, &body).await?;
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    state.scim_service.delete_user(&tenant.0, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Group handlers ───────────────────────────────────────────────────────────

async fn list_groups(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Query(query): Query<ScimListQuery>,
) -> Result<impl IntoResponse> {
    let result = state.scim_service.list_groups(&tenant.0, &query).await?;
    Ok((StatusCode::OK, Json(result)))
}

async fn create_group(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Json(body): Json<ScimGroupWrite>,
) -> Result<impl IntoResponse> {
    let group = state.scim_service.create_group(&tenant.0, &body).await?;
    Ok((StatusCode::CREATED, Json(group)))
}

async fn get_group(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let group = state.scim_service.get_group(&tenant.0, &id).await?;
    Ok(Json(group))
}

async fn replace_group(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
    Json(body): Json<ScimGroupWrite>,
) -> Result<impl IntoResponse> {
    let group = state
        .scim_service
        .replace_group(&tenant.0, &id, &body)
        .await?;
    Ok(Json(group))
}

async fn delete_group(
    State(state): State<AppState>,
    Extension(tenant): Extension<ScimTenant>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    state.scim_service.delete_group(&tenant.0, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Admin token management (JWT-authed, no SCIM bearer) ─────────────────────

#[derive(serde::Deserialize)]
struct CreateTokenBody {
    description: Option<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/:id", delete(revoke_token))
        .route("/config", get(get_config))
        .route("/enable", post(enable_scim))
        .route("/disable", post(disable_scim))
        .route("/rotate-token", post(rotate_scim_token))
        .route("/events", get(list_events))
}

// ─── Config/enable/disable/rotate/events handlers ────────────────────────────

/// GET /api/admin/v1/scim/config
/// Returns derived SCIM config. 404 when SCIM has never been enabled.
async fn get_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    let tokens = state.scim_service.list_tokens(&claims.tenant_id).await?;
    if tokens.is_empty() {
        return Err(AppError::NotFound("SCIM not configured".to_string()));
    }
    let token = &tokens[0];
    Ok(Json(json!({
        "id": token.id,
        "enabled": true,
        "token_hint": "\u{2022}\u{2022}\u{2022}\u{2022}",
        "endpoint_url": "/scim/v2",
        "supported_resources": ["User", "Group"],
        "last_event_at": null,
        "event_count": 0
    })))
}

/// POST /api/admin/v1/scim/enable
/// Revokes any existing tokens, creates a fresh one, returns config + raw token.
async fn enable_scim(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    state.scim_service.revoke_all_tokens(&claims.tenant_id).await?;
    let created = state
        .scim_service
        .create_token(
            &claims.tenant_id,
            Some("SCIM provisioning token"),
            None,
            Some(&claims.sub),
        )
        .await?;
    let config = json!({
        "id": created.id,
        "enabled": true,
        "token_hint": "\u{2022}\u{2022}\u{2022}\u{2022}",
        "endpoint_url": "/scim/v2",
        "supported_resources": ["User", "Group"],
        "last_event_at": null,
        "event_count": 0
    });
    Ok(Json(json!({ "config": config, "token": created.token })))
}

/// POST /api/admin/v1/scim/disable
/// Revokes all active SCIM tokens for the tenant.
async fn disable_scim(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse> {
    state.scim_service.revoke_all_tokens(&claims.tenant_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/v1/scim/rotate-token
/// Revokes all existing tokens and issues a fresh one.
async fn rotate_scim_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    state.scim_service.revoke_all_tokens(&claims.tenant_id).await?;
    let created = state
        .scim_service
        .create_token(
            &claims.tenant_id,
            Some("SCIM provisioning token"),
            None,
            Some(&claims.sub),
        )
        .await?;
    Ok(Json(json!({ "token": created.token })))
}

/// GET /api/admin/v1/scim/events?limit=N
/// Returns recent SCIM provisioning events. No events table yet — returns empty list.
async fn list_events(
    Extension(_claims): Extension<Claims>,
) -> Json<serde_json::Value> {
    Json(json!([]))
}

async fn list_tokens(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    let tokens = state
        .scim_service
        .list_tokens(&claims.tenant_id)
        .await?;
    Ok(Json(json!({ "tokens": tokens })))
}

async fn create_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CreateTokenBody>,
) -> Result<impl IntoResponse> {
    let created = state
        .scim_service
        .create_token(
            &claims.tenant_id,
            body.description.as_deref(),
            body.expires_at,
            Some(&claims.sub),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn revoke_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    state
        .scim_service
        .revoke_token(&claims.tenant_id, &id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
