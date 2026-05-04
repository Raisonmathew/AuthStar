use crate::middleware::{AuthenticatedUser, TenantId};
use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::services::sso_connection_service::{
    CreateConnectionParams, SsoConnection, UpdateConnectionParams,
};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use shared_types::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connections).post(create_connection))
        .route(
            "/:id",
            get(get_connection)
                .put(update_connection)
                .delete(delete_connection),
        )
        .route("/:id/test", post(test_connection))
        .route("/:id/toggle", put(toggle_connection))
        // SAML IdP metadata auto-import
        .route("/saml/import-metadata", post(import_saml_metadata))
}

async fn list_connections(
    State(state): State<AppState>,
    tenant: TenantId,
) -> Result<Json<Vec<SsoConnection>>, AppError> {
    let connections = state.sso_connection_service.list(tenant.as_str()).await?;
    Ok(Json(connections))
}

async fn create_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    user: AuthenticatedUser,
    Json(payload): Json<CreateConnectionParams>,
) -> Result<Json<SsoConnection>, AppError> {
    let conn = state
        .sso_connection_service
        .create(tenant.as_str(), &payload)
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_CREATED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(conn.id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"provider": &payload.provider, "name": &payload.name}),
        })
        .await;
    Ok(Json(conn))
}

async fn get_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<SsoConnection>, AppError> {
    let conn = state
        .sso_connection_service
        .get(&id, tenant.as_str())
        .await?;
    Ok(Json(conn))
}

async fn update_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<UpdateConnectionParams>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .update(&id, tenant.as_str(), &payload)
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_UPDATED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;
    Ok(StatusCode::OK)
}

async fn delete_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .delete(&id, tenant.as_str())
        .await?;
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant.as_str().to_string(),
            event_type: event_types::SSO_CONNECTION_DELETED,
            actor_id: Some(user.user_id.clone()),
            actor_email: None,
            target_type: Some("sso_connection"),
            target_id: Some(id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .sso_connection_service
        .test_connection(&id, tenant.as_str())
        .await?;
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
struct ToggleParams {
    enabled: bool,
}

async fn toggle_connection(
    State(state): State<AppState>,
    tenant: TenantId,
    Path(id): Path<String>,
    Json(payload): Json<ToggleParams>,
) -> Result<StatusCode, AppError> {
    state
        .sso_connection_service
        .toggle(&id, tenant.as_str(), payload.enabled)
        .await?;
    Ok(StatusCode::OK)
}

/// Parsed IdP metadata fields returned to the frontend
#[derive(serde::Serialize)]
struct SamlMetadataImportResult {
    entity_id: String,
    sso_url: String,
    slo_url: Option<String>,
    certificate: Option<String>,
    name_id_format: Option<String>,
}

#[derive(serde::Deserialize)]
struct ImportMetadataRequest {
    url: String,
}

/// Fetch and parse a SAML IdP metadata XML from a URL.
///
/// Returns the extracted entity_id, sso_url, slo_url, and first certificate —
/// the frontend pre-fills the SAML connection form with these values.
async fn import_saml_metadata(
    State(_state): State<AppState>,
    _tenant: crate::middleware::TenantId,
    Json(payload): Json<ImportMetadataRequest>,
) -> Result<Json<SamlMetadataImportResult>, AppError> {
    // Basic URL validation — must be https or http
    if !payload.url.starts_with("http://") && !payload.url.starts_with("https://") {
        return Err(AppError::Validation(
            "Metadata URL must start with http:// or https://".into(),
        ));
    }

    // Fetch the metadata document
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client init failed: {e}")))?;

    let response = client
        .get(&payload.url)
        .header("Accept", "application/xml, text/xml, */*")
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch metadata URL: {e}")))?;

    if !response.status().is_success() {
        return Err(AppError::Validation(format!(
            "Metadata URL returned HTTP {}",
            response.status()
        )));
    }

    let xml_text = response
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read metadata response: {e}")))?;

    // Parse with roxmltree
    let doc = roxmltree::Document::parse(&xml_text)
        .map_err(|e| AppError::Validation(format!("Invalid XML in metadata: {e}")))?;

    // Extract EntityDescriptor entityID
    let entity_id = doc
        .root_element()
        .attribute("entityID")
        .ok_or_else(|| AppError::Validation("Metadata missing entityID attribute".into()))?
        .to_string();

    // Find IDPSSODescriptor → SingleSignOnService with HTTP-POST or HTTP-Redirect binding
    let sso_url = doc
        .descendants()
        .filter(|n| n.has_tag_name("SingleSignOnService"))
        .find(|n| {
            let binding = n.attribute("Binding").unwrap_or("");
            binding.ends_with("HTTP-POST") || binding.ends_with("HTTP-Redirect")
        })
        .or_else(|| {
            doc.descendants()
                .find(|n| n.has_tag_name("SingleSignOnService"))
        })
        .and_then(|n| n.attribute("Location"))
        .ok_or_else(|| AppError::Validation("Metadata missing SingleSignOnService Location".into()))?
        .to_string();

    // Find SingleLogoutService (prefer POST, fallback Redirect)
    let slo_url = doc
        .descendants()
        .filter(|n| n.has_tag_name("SingleLogoutService"))
        .find(|n| {
            let binding = n.attribute("Binding").unwrap_or("");
            binding.ends_with("HTTP-POST") || binding.ends_with("HTTP-Redirect")
        })
        .and_then(|n| n.attribute("Location"))
        .map(|s| s.to_string());

    // Extract first X.509 certificate from IDPSSODescriptor KeyDescriptor
    let certificate = doc
        .descendants()
        .find(|n| n.has_tag_name("X509Certificate"))
        .and_then(|n| n.text())
        .map(|cert_b64| {
            // Re-wrap in PEM headers
            let cleaned: String = cert_b64.chars().filter(|c| !c.is_whitespace()).collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                cleaned
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(64)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        });

    // Extract NameIDFormat (first one)
    let name_id_format = doc
        .descendants()
        .find(|n| n.has_tag_name("NameIDFormat"))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string());

    Ok(Json(SamlMetadataImportResult {
        entity_id,
        sso_url,
        slo_url,
        certificate,
        name_id_format,
    }))
}
