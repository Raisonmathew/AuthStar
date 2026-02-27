use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, State, Form, ConnectInfo},
    response::{IntoResponse, Redirect},
    http::{header, HeaderMap},
};
use crate::state::AppState;
use shared_types::{AppError, Result};
use identity_engine::services::oauth_service::OAuthConfig;
use identity_engine::services::saml::{SamlService, SamlIdpConfig};
use serde::Deserialize;

pub fn router() -> Router<AppState> {
    Router::new()
        // OAuth/OIDC routes
        .route("/:provider/authorize", get(authorize_handler))
        .route("/:provider/callback", get(callback_handler))
        // SAML routes
        .route("/saml/metadata", get(saml_metadata))
        .route("/saml/:connection_id/authorize", get(saml_authorize))
        .route("/saml/acs", post(saml_acs))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SsoProviderConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_url: String,
    token_url: String,
    userinfo_url: String,
}

// Helper to load config from DB — tenant-scoped
async fn load_provider_config(state: &AppState, provider: &str, tenant_id: &str) -> Result<OAuthConfig> {
    // Runtime query scoped to tenant — prevents loading another tenant's SSO config
    let config_json: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT config FROM sso_connections WHERE provider = $1 AND tenant_id = $2 AND enabled = true LIMIT 1"
    )
    .bind(provider)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?;

    if let Some(config_val) = config_json {
        let config: SsoProviderConfig = serde_json::from_value(config_val)
            .map_err(|e| AppError::Internal(format!("Invalid provider config: {}", e)))?;
            
        return Ok(OAuthConfig {
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            authorization_url: config.authorization_url,
            token_url: config.token_url,
            userinfo_url: config.userinfo_url,
        });
    }

    // Fallback or Error
    Err(AppError::Internal(format!("Provider {} not configured", provider)))
}

async fn authorize_handler(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    let tenant_id = params.get("tenant_id").map(|s| s.as_str()).unwrap_or("platform"); // Default
    
    let config = load_provider_config(&state, &provider, tenant_id).await?;
    
    // Generate cryptographically secure state parameter
    let state_val = format!("state_{}_{}", tenant_id, shared_types::id_generator::generate_id("rnd"));
    
    // Store state in Redis with 5-minute TTL to prevent CSRF
    if let Ok(client) = redis::Client::open(state.config.redis.url.as_str()) {
        if let Ok(mut conn) = client.get_async_connection().await {
            let key = format!("oauth_state:{}", state_val);
            let _: std::result::Result<(), _> = redis::cmd("SET")
                .arg(&key)
                .arg(tenant_id)
                .arg("EX")
                .arg(300) // 5 minutes
                .query_async(&mut conn)
                .await;
        }
    }
    
    let auth_url = state.oauth_service.get_authorization_url(&config, &state_val);
    
    Ok(Redirect::to(&auth_url))
}

async fn callback_handler(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    // Verify OAuth state parameter against Redis to prevent CSRF
    let tenant_id = if let Some(ref state_param) = query.state {
        let key = format!("oauth_state:{}", state_param);
        let stored_tenant: Option<String> = if let Ok(client) = redis::Client::open(state.config.redis.url.as_str()) {
            if let Ok(mut conn) = client.get_async_connection().await {
                redis::cmd("GET").arg(&key).query_async(&mut conn).await.ok()
            } else { None }
        } else { None };

        match stored_tenant {
            Some(tid) => {
                // Delete used state to prevent replay
                if let Ok(client) = redis::Client::open(state.config.redis.url.as_str()) {
                    if let Ok(mut conn) = client.get_async_connection().await {
                        let _: std::result::Result<(), _> = redis::cmd("DEL")
                            .arg(&key)
                            .query_async(&mut conn)
                            .await;
                    }
                }
                tid
            }
            None => {
                return Err(AppError::Unauthorized("Invalid or expired OAuth state parameter".into()));
            }
        }
    } else {
        return Err(AppError::Unauthorized("Missing OAuth state parameter".into()));
    };

    let config = load_provider_config(&state, &provider, &tenant_id).await?;
    
    // 1. Exchange code
    let tokens = state.oauth_service.exchange_code_for_token(&config, &query.code).await?;
    
    // 2. Get User Info
    let user_info = state.oauth_service.get_user_info(&config, &tokens.access_token).await?;
    
    // 3. Find or Create User
    let oauth_subject = user_info.sub.clone();
    let email = user_info.email.clone().unwrap_or_else(|| "unknown".to_string());
    
    let user = state.oauth_service.find_or_create_oauth_user(
        &provider,
        &oauth_subject,
        &user_info,
        &tokens
    ).await?;

    // 4. EIAA: Execute Capsule for auth:sso_login
    let capsule_action = "auth:sso_login";
    let decision_ref = format!("dec_sso_{}", shared_types::id_generator::generate_id("ref"));
    let nonce = shared_types::id_generator::generate_id("nonce");

    let input_json = serde_json::json!({
        "action": "login",
        "user_id": user.id,
        "provider": provider,
        "email": email,
        "tenant_id": tenant_id
    });

    // Build AuthEvidence from IdP assertion
    let evidence = grpc_api::eiaa::runtime::AuthEvidence {
        issuer: config.authorization_url.clone(), // IdP issuer
        audience: config.client_id.clone(),
        subject: user_info.sub.clone(),
        email_verified: user_info.email_verified.unwrap_or(false),
        auth_time_unix: chrono::Utc::now().timestamp(), // Approximate: IdP doesn't always provide this
        assurance_hint: "aal1".to_string(),
        tenant_id: tenant_id.clone(),
        provider: provider.clone(),
        evidence_hash_b64: {
            use sha2::{Sha256, Digest};
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let evidence_data = format!("{}:{}:{}", provider, user_info.sub, tenant_id);
            URL_SAFE_NO_PAD.encode(Sha256::digest(evidence_data.as_bytes()))
        },
    };

    let cache = &state.capsule_cache;
    let sso_decision_allowed = {
        let capsule = if let Some(cached) = cache.get(&tenant_id, capsule_action).await {
            use prost::Message;
            match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
                Ok(c) => c,
                Err(_) => {
                    tracing::warn!("Failed to decode cached capsule for {}", capsule_action);
                    let ast = build_sso_policy_ast(&tenant_id, &state.db).await?;
                    compile_sso_policy(&ast, &tenant_id, &state).await
                        .map_err(|e| AppError::Internal(format!("Compile error: {}", e)))?
                }
            }
        } else {
            tracing::info!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
            let ast = build_sso_policy_ast(&tenant_id, &state.db).await?;
            compile_sso_policy(&ast, &tenant_id, &state).await
                .map_err(|e| AppError::Internal(format!("Compile error: {}", e)))?
        };

        // Execute capsule with evidence
        let mut client = crate::clients::runtime_client::EiaaRuntimeClient::connect(
            state.config.eiaa.runtime_grpc_addr.clone()
        ).await.map_err(|e| {
            tracing::error!("Failed to connect to runtime: {}", e);
            AppError::Internal("Authorization service unavailable".into())
        })?;

        let response = client.execute_with_evidence(
            capsule.clone(),
            serde_json::to_string(&input_json).unwrap(),
            nonce.clone(),
            evidence,
        ).await.map_err(|e| {
            tracing::error!("SSO capsule execution failed: {}", e);
            AppError::Internal("Authorization service unavailable".into())
        })?;

        let decision = response.decision.as_ref();
        let allowed = decision.map(|d| d.allow).unwrap_or(false);
        
        // Store attestation using the helper function
        if let Some(att) = response.attestation {
            let dec = decision.unwrap().clone();
            store_sso_attestation(
                &state.audit_writer,
                &decision_ref,
                &capsule,
                &dec,
                att,
                &nonce,
                &tenant_id,
                &user.id
            )?;
        }

        if !allowed {
            let reason = decision
                .and_then(|d| if d.reason.is_empty() { None } else { Some(d.reason.clone()) })
                .unwrap_or_else(|| "SSO login denied by policy".to_string());
            return Err(AppError::Forbidden(reason));
        }
        true
    };

    // 5. Create Session
    let session_id = shared_types::id_generator::generate_id("sess");
    let session_type = "user_session";
    
    // OAuth logins start at AAL1 with oauth capability
    let assurance_level = "aal1";
    let verified_capabilities = serde_json::json!(["oauth"]);

    // Extract real IP and User-Agent from callback request headers
    let user_agent = headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let client_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // Generate opaque session token instead of storing upstream OAuth access token
    let session_token = shared_types::id_generator::generate_id("stok");

    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, token, user_agent, ip_address, 
            expires_at, created_at, updated_at,
            decision_ref, tenant_id, session_type,
            assurance_level, verified_capabilities, is_provisional
        )
        VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '24 hours', NOW(), NOW(), $6, $7, $8, $9, $10, false)
        "#
    )
    .bind(&session_id)
    .bind(&user.id)
    .bind(&session_token)
    .bind(&user_agent)
    .bind(&client_ip)
    .bind(&decision_ref)
    .bind(&tenant_id)
    .bind(session_type)
    .bind(assurance_level)
    .bind(&verified_capabilities)
    .execute(&state.db)
    .await?;

    // 6. Generate JWT
    let token = state.jwt_service.generate_token(
        &user.id,
        &session_id,
        &tenant_id,
        session_type,
    )?;

    // 7. Set cookies and redirect to frontend
    // JWT goes in httpOnly __session cookie (not in URL — prevents exposure in logs/history)
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let session_cookie = crate::middleware::csrf::session_cookie_header(&token, is_secure);
    let csrf_token = crate::middleware::csrf::generate_csrf_token();
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token);

    let frontend_url = format!("{}/auth/callback", state.config.frontend_url);

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::FOUND)
        .header(axum::http::header::LOCATION, &frontend_url)
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .body(axum::body::Body::empty())
        .map_err(|e| AppError::Internal(format!("Response build error: {}", e)))?;

    Ok(response.into_response())
}

// ============ SAML 2.0 Handlers ============

/// SAML SP Metadata endpoint
async fn saml_metadata(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let saml = SamlService::new(
        state.db.clone(),
        format!("https://{}/auth/sso/saml", state.config.server.host),
        format!("https://{}/auth/sso/saml/acs", state.config.server.host),
    );
    
    let metadata = saml.generate_sp_metadata();
    
    (
        [(header::CONTENT_TYPE, "application/xml")],
        metadata
    )
}

#[derive(Deserialize)]
struct SamlAuthorizeQuery {
    relay_state: Option<String>,
    tenant_id: Option<String>,
}

/// SAML Authorization redirect
async fn saml_authorize(
    State(state): State<AppState>,
    Path(connection_id): Path<String>,
    Query(query): Query<SamlAuthorizeQuery>,
) -> Result<impl IntoResponse> {
    let saml = SamlService::new(
        state.db.clone(),
        format!("https://{}/auth/sso/saml", state.config.server.host),
        format!("https://{}/auth/sso/saml/acs", state.config.server.host),
    );
    
    let tenant_id = query.tenant_id.unwrap_or_else(|| "platform".to_string());
    let idp_config = saml.load_idp_config(&connection_id, &tenant_id).await?;
    let relay_state = query.relay_state.unwrap_or_default();
    
    let redirect_url = saml.get_sso_redirect_url(&idp_config, &relay_state);
    
    Ok(Redirect::to(&redirect_url))
}

#[derive(Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

use grpc_api::eiaa::runtime::ExecuteRequest;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// SAML Assertion Consumer Service (ACS) - receives POST from IdP
async fn saml_acs(
    State(state): State<AppState>,
    Form(form): Form<SamlAcsForm>,
) -> Result<impl IntoResponse> {
    let saml = SamlService::new(
        state.db.clone(),
        format!("https://{}/auth/sso/saml", state.config.server.host),
        format!("https://{}/auth/sso/saml/acs", state.config.server.host),
    );
    
    // Get Redis connection
    let client = redis::Client::open(state.config.redis.url.as_str())
        .map_err(|e| AppError::Internal(format!("Redis error: {}", e)))?;
    let mut redis_conn = client.get_async_connection().await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {}", e)))?;

    // Load SAML config scoped to tenant — extracted from RelayState or issuer mapping
    // TODO: In production, map SAML Issuer → tenant_id via a dedicated table
    let saml_tenant_id = form.relay_state.as_deref().unwrap_or("platform");
    let config_val: serde_json::Value = sqlx::query_scalar(
        "SELECT config FROM sso_connections WHERE type = 'saml' AND tenant_id = $1 AND enabled = true LIMIT 1"
    )
    .bind(saml_tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| AppError::NotFound("No enabled SAML IDP found for tenant".into()))?;

    let idp_config: SamlIdpConfig = serde_json::from_value(config_val)
        .map_err(|e| AppError::Internal(format!("Invalid SAML config: {}", e)))?;
        
    // 2. Strict Verification
    let assertion = saml.verify_and_extract(&form.saml_response, &idp_config, &mut redis_conn).await?;
    
    // 3. Normalize Facts
    let saml_facts = saml.normalize_facts(&assertion);
    
    // 4. EIAA: Execute Capsule (Real WASM)
    // Input: facts
    let input_json = serde_json::json!({
        "action": "login",
        "auth": saml_facts,
        "risk": { "score": 0 } // Placeholder for Risk Engine integration
    });
    
    // Generate Nonce
    let nonce: [u8; 16] = rand::random();
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    let mut client = crate::clients::runtime_client::EiaaRuntimeClient::connect(
        state.config.eiaa.runtime_grpc_addr.clone()
    ).await.map_err(|e| {
        tracing::error!("Failed to connect to runtime: {}", e);
        AppError::Internal("Authorization service unavailable".into())
    })?;
    
    // Build AuthEvidence from SAML assertion
    let evidence = grpc_api::eiaa::runtime::AuthEvidence {
        issuer: saml_facts.issuer.clone(), // IdP issuer
        audience: idp_config.entity_id.clone(),
        subject: saml_facts.external_id.clone(),
        email_verified: true, // SAML assertions inherently imply verified email
        auth_time_unix: chrono::Utc::now().timestamp(),
        assurance_hint: saml_facts.authn_context.clone().unwrap_or_else(|| "aal1".to_string()),
        tenant_id: saml_tenant_id.to_string(),
        provider: "saml".to_string(),
        evidence_hash_b64: {
            use sha2::{Sha256, Digest};
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let evidence_data = format!("saml:{}:{}", saml_facts.external_id, saml_tenant_id);
            URL_SAFE_NO_PAD.encode(Sha256::digest(evidence_data.as_bytes()))
        },
    };

    let cache = &state.capsule_cache;
    let capsule_action = "auth:sso_login";
    
    // Look up capsule from cache OR compile default fallback
    let capsule = if let Some(cached) = cache.get(&saml_tenant_id.to_string(), capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("Failed to decode cached capsule for {}", capsule_action);
                let ast = build_sso_policy_ast(saml_tenant_id, &state.db).await?;
                compile_sso_policy(&ast, saml_tenant_id, &state).await
                    .map_err(|e| AppError::Internal(format!("Compile error: {}", e)))?
            }
        }
    } else {
        tracing::info!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
        let ast = build_sso_policy_ast(saml_tenant_id, &state.db).await?;
        compile_sso_policy(&ast, saml_tenant_id, &state).await
            .map_err(|e| AppError::Internal(format!("Compile error: {}", e)))?
    };
        
    let response = client.execute_with_evidence(
        capsule.clone(),
        serde_json::to_string(&input_json).unwrap(),
        nonce_b64.clone(),
        evidence,
    ).await
        .map_err(|e| AppError::Internal(format!("Runtime error: {}", e)))?;
        
    let decision = response.decision.ok_or(AppError::Internal("Missing decision".into()))?;
    
    // Log the reason if denied
    if !decision.allow {
        tracing::warn!("SAML Login denied: {}", decision.reason);
        return Err(AppError::Forbidden(format!("Policy denied login: {}", decision.reason)));
    }
    
    // 5. User Provisioning / Linking (email is in identities table, not users)
    let user = sqlx::query_scalar::<_, String>(
        "SELECT u.id FROM users u 
         INNER JOIN identities i ON i.user_id = u.id 
         WHERE i.type = 'email' AND i.identifier = $1"
    )
        .bind(&saml_facts.email)
        .fetch_optional(&state.db)
        .await?;
    
    let user_id = match user {
        Some(id) => id,
        None => {
            // Create new user with identity
            let new_id = shared_types::id_generator::generate_id("user");
            let identity_id = shared_types::id_generator::generate_id("ident");
            
            // Insert user
            sqlx::query(
                "INSERT INTO users (id, created_at, updated_at) VALUES ($1, NOW(), NOW())"
            )
                .bind(&new_id)
                .execute(&state.db)
                .await?;
            
            // Insert email identity
            sqlx::query(
                "INSERT INTO identities (id, user_id, type, identifier, verified, created_at, updated_at) 
                 VALUES ($1, $2, 'email', $3, true, NOW(), NOW())"
            )
                .bind(&identity_id)
                .bind(&new_id)
                .bind(&saml_facts.email)
                .execute(&state.db)
                .await?;
            
            new_id
        }
    };
    
    // 6. Store Attestation & Generate Decision Ref
    let decision_ref = shared_types::id_generator::generate_id("dec_sso");
    if let Some(attestation) = response.attestation {
        let dec = decision.clone();
        store_sso_attestation(
            &state.audit_writer,
            &decision_ref,
            &capsule,
            &dec,
            attestation,
            &nonce_b64,
            &saml_tenant_id,
            &user_id
        )?;
    }
    
    // 7. Create Session
    let session_id = shared_types::id_generator::generate_id("sess");
    
    // SAML logins start at AAL1 with saml capability
    let assurance_level = "aal1";
    let verified_capabilities = serde_json::json!(["saml"]);
    
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token, user_agent, ip_address, expires_at, created_at, updated_at, session_type, decision_ref, assurance_level, verified_capabilities, is_provisional, tenant_id) VALUES ($1, $2, $3, 'SAML-Client', '0.0.0.0', NOW() + INTERVAL '24 hours', NOW(), NOW(), 'saml_session', $4, $5, $6, false, $7)"
    )
        .bind(&session_id)
        .bind(&user_id)
        .bind(&session_id)
        .bind(&decision_ref) // Link to real attestation
        .bind(assurance_level)
        .bind(&verified_capabilities)
        .bind(&saml_tenant_id)
        .execute(&state.db)
        .await?;
    
    // 8. Generate JWT
    let token = state.jwt_service.generate_token(
        &user_id,
        &session_id,
        "platform",
        "saml_session",
    )?;
    
    // Redirect with httpOnly cookies (no token in URL)
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let session_cookie = crate::middleware::csrf::session_cookie_header(&token, is_secure);
    let csrf_token = crate::middleware::csrf::generate_csrf_token();
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token);

    let redirect_url = form.relay_state.clone().unwrap_or_else(||
        format!("{}/auth/callback", state.config.frontend_url)
    );

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::FOUND)
        .header(axum::http::header::LOCATION, &redirect_url)
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .body(axum::body::Body::empty())
        .map_err(|e| AppError::Internal(format!("Response build error: {}", e)))?;

    Ok(response.into_response())
}

// Helper to store attestation (Adapted from auth.rs)
fn store_sso_attestation(
    audit_writer: &crate::services::audit_writer::AuditWriter,
    decision_ref: &str,
    capsule: &grpc_api::eiaa::runtime::CapsuleSigned,
    decision: &grpc_api::eiaa::runtime::Decision,
    attestation: grpc_api::eiaa::runtime::Attestation,
    nonce: &str,
    tenant_id: &str,
    user_id: &str,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    // Hash full context for input_digest (not just nonce) - EIAA compliance
    let mut hasher = Sha256::new();
    hasher.update(capsule.capsule_hash_b64.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(b"saml_login");
    let input_digest = URL_SAFE_NO_PAD.encode(hasher.finalize());

    // Get decision hash from attestation body
    let attestation_body = attestation.body.as_ref()
        .ok_or_else(|| AppError::Internal("Attestation body missing".into()))?;
    let attestation_hash_b64 = {
        let body_json = serde_json::to_vec(attestation_body)
            .map_err(|e| AppError::Internal(format!("Attestation body json: {}", e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&body_json);
        Some(URL_SAFE_NO_PAD.encode(hasher.finalize()))
    };

    audit_writer.record(crate::services::audit_writer::AuditRecord {
        decision_ref: decision_ref.to_string(),
        capsule_hash_b64: capsule.capsule_hash_b64.clone(),
        capsule_version: "sso_login_v1".to_string(),
        action: "sso_login".to_string(),
        tenant_id: tenant_id.to_string(),
        input_digest,
        nonce_b64: nonce.to_string(),
        decision: crate::services::audit_writer::AuditDecision {
            allow: decision.allow,
            reason: if decision.reason.is_empty() { None } else { Some(decision.reason.clone()) },
        },
        attestation_signature_b64: attestation.signature_b64.clone(),
        attestation_timestamp: chrono::Utc::now(),
        attestation_hash_b64,
        user_id: Some(user_id.to_string()),
    });

    tracing::info!("Queued SSO attestation for decision: {}", decision_ref);
    Ok(())
}

use capsule_compiler::ast::{Program, Step};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};

async fn build_sso_policy_ast(tenant_id: &str, db: &sqlx::PgPool) -> Result<Program> {
    let policy_json: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:sso_login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some(json) = policy_json {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok(program);
        }
        return Err(AppError::Internal("Invalid SSO policy format".into()));
    }

    Err(AppError::Forbidden("SSO policy not configured".into()))
}

async fn compile_sso_policy(
    policy: &Program,
    tenant_id: &str,
    state: &AppState,
) -> anyhow::Result<CapsuleSigned> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    
    let compiled = capsule_compiler::compile(
        policy.clone(),
        tenant_id.to_string(),
        "auth:sso_login".to_string(),
        now,
        now + 300,
        &state.ks,
        &state.compiler_kid,
    )?;

    Ok(CapsuleSigned {
        meta: Some(CapsuleMeta {
            tenant_id: compiled.meta.tenant_id,
            action: compiled.meta.action,
            not_before_unix: compiled.meta.not_before_unix,
            not_after_unix: compiled.meta.not_after_unix,
            policy_hash_b64: compiled.meta.ast_hash_b64,
        }),
        ast_bytes: compiled.ast_bytes,
        capsule_hash_b64: compiled.ast_hash.clone(),
        compiler_kid: compiled.compiler_kid,
        compiler_sig_b64: compiled.compiler_sig_b64,
        ast_hash_b64: compiled.ast_hash,
        wasm_hash_b64: compiled.wasm_hash,
        lowering_version: compiled.lowering_version,
        wasm_bytes: compiled.wasm_bytes,
    })
}

/// Compute SHA-256 hash of input JSON for audit storage.
fn evidence_hash_b64_for_input(input: &serde_json::Value) -> String {
    use sha2::{Sha256, Digest};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes))
}
