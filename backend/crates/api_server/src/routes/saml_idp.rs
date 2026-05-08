use crate::services::audit_event_service::RecordEventParams;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use identity_engine::services::saml::{SamlIdpResponseParams, SamlService};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};
use std::net::IpAddr;

const EMAIL_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const PASSWORD_AUTHN_CONTEXT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/:tenant_id/metadata", get(metadata))
        .route("/:tenant_id/config", get(config_summary))
}

pub fn protected_router() -> Router<AppState> {
    Router::new().route("/:tenant_id/sso", get(sso_redirect_binding))
}

async fn metadata(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<impl IntoResponse> {
    let cert = saml_idp_signing_cert_pem()?;
    let entity_id = saml_idp_entity_id(&state, &tenant_id);
    let sso_url = saml_idp_sso_url(&state, &tenant_id);
    let metadata = SamlService::generate_idp_metadata(&entity_id, &sso_url, &cert);
    Ok(([(header::CONTENT_TYPE, "application/xml")], metadata))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SamlIdpConfigSummary {
    entity_id: String,
    sso_url: String,
    metadata_url: String,
    certificate_configured: bool,
}

async fn config_summary(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Json<SamlIdpConfigSummary> {
    Json(SamlIdpConfigSummary {
        entity_id: saml_idp_entity_id(&state, &tenant_id),
        sso_url: saml_idp_sso_url(&state, &tenant_id),
        metadata_url: saml_idp_metadata_url(&state, &tenant_id),
        certificate_configured: saml_idp_signing_cert_pem().is_ok(),
    })
}

#[derive(Debug, Deserialize)]
struct SamlIdpSsoQuery {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

async fn sso_redirect_binding(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SamlIdpSsoQuery>,
) -> Result<impl IntoResponse> {
    if claims.tenant_id != tenant_id {
        return Err(AppError::Forbidden(
            "SAML IdP request tenant does not match the active session".into(),
        ));
    }

    let saml = SamlService::new(
        state.db.clone(),
        saml_idp_entity_id(&state, &tenant_id),
        saml_idp_sso_url(&state, &tenant_id),
    );
    let authn_request = saml.parse_idp_authn_request(&query.saml_request)?;
    let expected_sso_url = saml_idp_sso_url(&state, &tenant_id);
    if let Some(destination) = authn_request.destination.as_deref() {
        if destination != expected_sso_url {
            return Err(AppError::Validation(
                "AuthnRequest Destination does not match this SAML IdP SSO URL".into(),
            ));
        }
    }
    let sp_app = load_saml_service_provider(
        &state,
        &tenant_id,
        &authn_request.issuer,
        &authn_request.assertion_consumer_service_url,
    )
    .await?;
    let subject = load_subject(&state, &tenant_id, &claims.sub).await?;

    let signing_key = saml_idp_signing_key_pem()?;
    let signing_cert = saml_idp_signing_cert_pem()?;
    let name_id_format = authn_request
        .name_id_format
        .as_deref()
        .or(sp_app.name_id_format.as_deref())
        .unwrap_or(EMAIL_NAME_ID_FORMAT);
    let session_index = format!("saml_{}", claims.sid);
    let saml_response = saml.generate_signed_idp_response(&SamlIdpResponseParams {
        issuer: &saml_idp_entity_id(&state, &tenant_id),
        audience: &authn_request.issuer,
        destination: &authn_request.assertion_consumer_service_url,
        subject_name_id: &subject.email,
        name_id_format,
        in_response_to: &authn_request.id,
        session_index: &session_index,
        authn_context_class_ref: PASSWORD_AUTHN_CONTEXT,
        email: &subject.email,
        first_name: subject.first_name.as_deref(),
        last_name: subject.last_name.as_deref(),
        signing_key_pem: &signing_key,
        signing_cert_pem: &signing_cert,
        ttl_seconds: 300,
    })?;

    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant_id.clone(),
            event_type: "saml.idp.assertion_issued",
            actor_id: Some(claims.sub.clone()),
            actor_email: Some(subject.email.clone()),
            target_type: Some("application"),
            target_id: Some(sp_app.id),
            ip_address: extract_ip(&headers),
            user_agent: extract_user_agent(&headers),
            metadata: serde_json::json!({
                "sp_entity_id": authn_request.issuer,
                "acs_url": authn_request.assertion_consumer_service_url,
                "application_name": sp_app.name,
            }),
        })
        .await;

    let encoded_response = BASE64.encode(saml_response.as_bytes());
    let html = post_response_form(
        &authn_request.assertion_consumer_service_url,
        &encoded_response,
        query.relay_state.as_deref(),
    );
    Ok(Html(html))
}

#[derive(Debug)]
struct SamlServiceProviderApp {
    id: String,
    name: String,
    name_id_format: Option<String>,
}

async fn load_saml_service_provider(
    state: &AppState,
    tenant_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
) -> Result<SamlServiceProviderApp> {
    let row: Option<(String, String, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT id, name, redirect_uris, public_config
        FROM applications
        WHERE tenant_id = $1
          AND type = 'saml'
          AND public_config->>'saml_sp_entity_id' = $2
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(sp_entity_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Load SAML SP application: {e}")))?;

    let Some((id, name, redirect_uris_json, public_config)) = row else {
        return Err(AppError::Validation(
            "SAML service provider is not registered for this tenant".into(),
        ));
    };

    let enabled = public_config
        .get("saml_idp_enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    if !enabled {
        return Err(AppError::Forbidden(
            "SAML IdP is disabled for this service provider".into(),
        ));
    }

    let redirect_uris: Vec<String> = serde_json::from_value(redirect_uris_json)
        .map_err(|e| AppError::Internal(format!("Invalid application redirect URIs: {e}")))?;
    if !redirect_uris.iter().any(|uri| uri == acs_url) {
        return Err(AppError::Validation(
            "AuthnRequest ACS URL is not registered for this service provider".into(),
        ));
    }

    let name_id_format = public_config
        .get("saml_name_id_format")
        .and_then(|value| value.as_str())
        .map(str::to_string);

    Ok(SamlServiceProviderApp {
        id,
        name,
        name_id_format,
    })
}

#[derive(Debug)]
struct SamlSubject {
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
}

async fn load_subject(state: &AppState, tenant_id: &str, user_id: &str) -> Result<SamlSubject> {
    let row: Option<(Option<String>, Option<String>, Option<String>, bool, bool)> = sqlx::query_as(
        r#"
        SELECT email.identifier, u.first_name, u.last_name, u.banned, u.locked
        FROM memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN identities email ON email.user_id = u.id
            AND email.type = 'email'
            AND email.organization_id = $1
            AND email.verified = TRUE
        WHERE m.organization_id = $1 AND m.user_id = $2 AND u.deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Load SAML IdP subject: {e}")))?;

    let Some((email, first_name, last_name, banned, locked)) = row else {
        return Err(AppError::Unauthorized(
            "Active session user is not a member of this tenant".into(),
        ));
    };
    if banned || locked {
        return Err(AppError::Forbidden(
            "Locked or banned users cannot issue SAML assertions".into(),
        ));
    }
    let email = email.ok_or_else(|| {
        AppError::Validation("SAML IdP subject requires a verified email identity".into())
    })?;

    Ok(SamlSubject {
        email,
        first_name,
        last_name,
    })
}

fn saml_idp_signing_key_pem() -> Result<String> {
    std::env::var("SAML_IDP_SIGNING_KEY_PEM")
        .or_else(|_| std::env::var("SAML_SP_SIGNING_KEY_PEM"))
        .map_err(|_| {
            AppError::Internal(
                "SAML_IDP_SIGNING_KEY_PEM or SAML_SP_SIGNING_KEY_PEM must be configured".into(),
            )
        })
}

fn saml_idp_signing_cert_pem() -> Result<String> {
    std::env::var("SAML_IDP_SIGNING_CERT_PEM")
        .or_else(|_| std::env::var("SAML_SP_SIGNING_CERT_PEM"))
        .map_err(|_| {
            AppError::Internal(
                "SAML_IDP_SIGNING_CERT_PEM or SAML_SP_SIGNING_CERT_PEM must be configured".into(),
            )
        })
}

fn saml_idp_entity_id(state: &AppState, tenant_id: &str) -> String {
    std::env::var("SAML_IDP_ENTITY_ID").unwrap_or_else(|_| {
        format!(
            "{}/api/saml/idp/{}/metadata",
            public_api_base_url(state),
            tenant_id
        )
    })
}

fn saml_idp_sso_url(state: &AppState, tenant_id: &str) -> String {
    std::env::var("SAML_IDP_SSO_URL").unwrap_or_else(|_| {
        format!(
            "{}/api/saml/idp/{}/sso",
            public_api_base_url(state),
            tenant_id
        )
    })
}

fn saml_idp_metadata_url(state: &AppState, tenant_id: &str) -> String {
    format!(
        "{}/api/saml/idp/{}/metadata",
        public_api_base_url(state),
        tenant_id
    )
}

fn public_api_base_url(state: &AppState) -> String {
    if let Ok(url) = std::env::var("PUBLIC_API_URL").or_else(|_| std::env::var("API_PUBLIC_URL")) {
        return url.trim_end_matches('/').to_string();
    }
    let host = if state.config.server.host == "0.0.0.0" {
        "localhost"
    } else {
        state.config.server.host.as_str()
    };
    format!("http://{}:{}", host, state.config.server.port)
}

fn post_response_form(acs_url: &str, saml_response: &str, relay_state: Option<&str>) -> String {
    let relay_state_input = relay_state
        .filter(|value| !value.is_empty())
        .map(|value| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                escape_html_attr(value)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>SAML sign-in</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{}">
<input type="hidden" name="SAMLResponse" value="{}"/>
{}
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>"#,
        escape_html_attr(acs_url),
        escape_html_attr(saml_response),
        relay_state_input
    )
}

fn escape_html_attr(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn extract_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
        })
        .and_then(|s| s.parse::<IpAddr>().ok())
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}
