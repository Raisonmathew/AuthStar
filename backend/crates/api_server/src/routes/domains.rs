//! Custom Domain Routes
//!
//! API endpoints for managing custom domains for hosted pages.

use crate::routes::guards::ensure_org_access;
use crate::services::CustomDomainService;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_domains).post(add_domain))
        .route("/:id", get(get_domain).delete(delete_domain))
        .route("/:id/verify", post(verify_domain))
        .route("/:id/primary", post(set_primary))
}

// Request/Response types
#[derive(Deserialize)]
struct AddDomainReq {
    org_id: String,
    domain: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DomainResponse {
    id: String,
    domain: String,
    verification_status: String,
    ssl_status: String,
    is_primary: bool,
    is_active: bool,
    verification_instructions: Option<VerificationInstructions>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationInstructions {
    method: String,
    record_type: String,
    record_name: String,
    record_value: String,
}

#[derive(Deserialize)]
struct ListDomainsQuery {
    org_id: String,
}

// Handlers
async fn add_domain(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<AddDomainReq>,
) -> Result<Json<DomainResponse>> {
    ensure_org_access(&state, &claims, &req.org_id).await?;
    let service = CustomDomainService::new(state.db.clone());

    let domain = service
        .add_domain(&req.org_id, &req.domain)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let instructions = service.get_verification_instructions(&domain);

    Ok(Json(DomainResponse {
        id: domain.id,
        domain: domain.domain,
        verification_status: domain.verification_status,
        ssl_status: domain.ssl_status,
        is_primary: domain.is_primary,
        is_active: domain.is_active,
        verification_instructions: Some(VerificationInstructions {
            method: instructions.method,
            record_type: instructions.record_type,
            record_name: instructions.record_name,
            record_value: instructions.record_value,
        }),
    }))
}

async fn list_domains(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListDomainsQuery>,
) -> Result<Json<Vec<DomainResponse>>> {
    ensure_org_access(&state, &claims, &params.org_id).await?;
    let service = CustomDomainService::new(state.db.clone());

    let domains = service
        .list_domains(&params.org_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let responses: Vec<DomainResponse> = domains
        .into_iter()
        .map(|d| DomainResponse {
            id: d.id,
            domain: d.domain,
            verification_status: d.verification_status,
            ssl_status: d.ssl_status,
            is_primary: d.is_primary,
            is_active: d.is_active,
            verification_instructions: None,
        })
        .collect();

    Ok(Json(responses))
}

async fn get_domain(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<DomainResponse>> {
    // IDOR fix: verify the domain belongs to the caller's tenant
    if claims.tenant_id.is_empty() {
        return Err(AppError::Forbidden("Missing tenant context".into()));
    }
    let service = CustomDomainService::new(state.db.clone());

    let domain = service
        .get_domain(&id)
        .await
        .map_err(|e| AppError::NotFound(e.to_string()))?;

    // Verify ownership: domain must belong to caller's org
    if domain.organization_id != claims.tenant_id {
        return Err(AppError::Forbidden(
            "Domain does not belong to your organization".into(),
        ));
    }

    let instructions = service.get_verification_instructions(&domain);

    Ok(Json(DomainResponse {
        id: domain.id,
        domain: domain.domain,
        verification_status: domain.verification_status,
        ssl_status: domain.ssl_status,
        is_primary: domain.is_primary,
        is_active: domain.is_active,
        verification_instructions: Some(VerificationInstructions {
            method: instructions.method,
            record_type: instructions.record_type,
            record_name: instructions.record_name,
            record_value: instructions.record_value,
        }),
    }))
}

#[derive(Deserialize)]
struct OrgIdQuery {
    org_id: String,
}

async fn delete_domain(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Query(params): Query<OrgIdQuery>,
) -> Result<StatusCode> {
    ensure_org_access(&state, &claims, &params.org_id).await?;
    let service = CustomDomainService::new(state.db.clone());

    service
        .delete_domain(&id, &params.org_id)
        .await
        .map_err(|e| AppError::NotFound(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct VerifyResponse {
    verified: bool,
    status: String,
}

async fn verify_domain(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<VerifyResponse>> {
    if claims.tenant_id.is_empty() {
        return Err(AppError::Forbidden("Missing tenant context".into()));
    }
    let service = CustomDomainService::new(state.db.clone());

    // IDOR fix: verify ownership before triggering verification
    let domain = service
        .get_domain(&id)
        .await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    if domain.organization_id != claims.tenant_id {
        return Err(AppError::Forbidden(
            "Domain does not belong to your organization".into(),
        ));
    }

    let verified = service
        .verify_domain(&id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(VerifyResponse {
        verified,
        status: if verified { "verified" } else { "pending" }.to_string(),
    }))
}

async fn set_primary(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Query(params): Query<OrgIdQuery>,
) -> Result<StatusCode> {
    ensure_org_access(&state, &claims, &params.org_id).await?;
    let service = CustomDomainService::new(state.db.clone());

    service
        .set_primary(&id, &params.org_id)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(StatusCode::OK)
}

// Guard consolidated in routes::guards module
