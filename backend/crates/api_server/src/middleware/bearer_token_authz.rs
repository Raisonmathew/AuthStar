//! OAuth bearer-token resource authorization via EIAA.
//!
//! This middleware validates an OAuth access token, enforces token binding when
//! present, maps granted OAuth scopes to EIAA action strings, and executes the
//! capsule for each mapped action before the resource handler runs.

use crate::middleware::{
    evaluate_oauth_action, Action, EiaaDecisionArtifact, OAuthEiaaNetwork, OAuthEiaaRequest,
};
use crate::state::AppState;
use auth_core::OAuthAccessTokenClaims;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::BTreeSet;

pub async fn bearer_token_authz(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        Some(token) if !token.is_empty() => token.to_string(),
        _ => return oauth_bearer_error(StatusCode::UNAUTHORIZED, "Missing Bearer token"),
    };

    let claims: OAuthAccessTokenClaims = match state.jwt_service.verify_token_as(&token) {
        Ok(claims) => claims,
        Err(_) => return oauth_bearer_error(StatusCode::UNAUTHORIZED, "Invalid access token"),
    };

    if state
        .oauth_as_service
        .is_access_token_blocklisted(&token)
        .await
    {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "Access token has been revoked");
    }

    if claims.cnf.is_some() {
        let http_uri = absolute_htu(request.headers(), request.uri());
        let cert_pem = decoded_header(request.headers(), "x-ssl-client-cert")
            .or_else(|| decoded_header(request.headers(), "x-client-cert"));
        let chain = crate::services::TokenBindingChain::new(
            std::sync::Arc::new(crate::services::DpopBinding::new(state.nonce_store.clone())),
            std::sync::Arc::new(crate::services::MtlsBinding),
        );
        let binding_req = crate::services::BindingRequest {
            http_method: request.method().as_str(),
            http_uri: &http_uri,
            dpop_header: request.headers().get("dpop").and_then(|v| v.to_str().ok()),
            access_token: Some(&token),
            client_cert_pem: cert_pem.as_deref(),
        };
        if let Err(error) = chain.verify(&claims, &binding_req).await {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                format!("Token binding verification failed: {error}"),
            );
        }
    }

    let confirmation_jkt = claims.cnf.as_ref().and_then(|cnf| cnf.jkt.as_deref());
    // Issue 7: collect every per-scope decision so downstream handlers and
    // audit consumers see the full set, not just the last one.
    let mut artifacts: Vec<EiaaDecisionArtifact> = Vec::new();
    for action in scope_actions(&claims.scope) {
        let network = OAuthEiaaNetwork::from_headers(request.headers());
        match evaluate_oauth_action(
            &state,
            OAuthEiaaRequest {
                action: &action,
                subject_id: &claims.sub,
                tenant_id: &claims.tenant_id,
                session_id: if claims.sid.is_empty() {
                    None
                } else {
                    Some(&claims.sid)
                },
                session_type: if claims.sid.is_empty() {
                    auth_core::jwt::session_types::SERVICE
                } else {
                    auth_core::jwt::session_types::END_USER
                },
                client_id: &claims.client_id,
                scope: Some(&claims.scope),
                grant_type: Some("resource_access"),
                method: request.method().as_str(),
                path: request.uri().path(),
                network,
                confirmation_jkt,
                agent_model_id: None,
                agent_id_claim: None,
                agent_task_id: None,
                agent_delegation_chain: None,
            },
        )
        .await
        {
            Ok(artifact) => artifacts.push(artifact),
            Err(error) => {
                tracing::warn!(
                    action = %action,
                    client_id = %claims.client_id,
                    subject = %claims.sub,
                    error = %error,
                    "OAuth bearer EIAA authorization denied"
                );
                return oauth_bearer_error(StatusCode::FORBIDDEN, error.to_string());
            }
        }
    }

    request.extensions_mut().insert(claims);
    if !artifacts.is_empty() {
        // Insert both the full vector and the last artifact for backward compat
        // with handlers that only look up `EiaaDecisionArtifact`.
        if let Some(last) = artifacts.last().cloned() {
            request.extensions_mut().insert(last);
        }
        request.extensions_mut().insert(artifacts);
    }
    next.run(request).await
}

fn scope_actions(scope: &str) -> Vec<String> {
    let mut actions = BTreeSet::new();
    actions.insert(Action::OAuthResource.as_str().to_string());
    for scope in scope.split_whitespace() {
        match scope {
            // OIDC standard scopes don't translate to EIAA actions: they
            // describe identity-token claim sets, not resource permissions.
            "openid" | "profile" | "email" | "offline_access" => {}
            value if value.contains(':') => {
                actions.insert(value.to_string());
            }
            value if value.contains('.') => {
                actions.insert(value.replace('.', ":"));
            }
            // Issue 6: any plain scope (e.g. `read`, `admin`) still gets a
            // capsule evaluation under a stable `oauth:scope:<name>` namespace
            // so resource-server policies can deny unknown scopes explicitly
            // instead of silently treating them as no-ops.
            value => {
                actions.insert(format!("oauth:scope:{}", value));
            }
        }
    }
    actions.into_iter().collect()
}

fn absolute_htu(headers: &axum::http::HeaderMap, uri: &Uri) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{}://{}{}", scheme, host, uri.path())
}

fn decoded_header(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| urlencoding::decode(v).ok().map(|s| s.into_owned()))
}

fn oauth_bearer_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": "invalid_token",
            "error_description": message.into(),
        })),
    )
        .into_response()
}
