#![allow(dead_code)]
use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, State, Form},
    response::{IntoResponse, Redirect},
    http::{header, HeaderMap},
};
use crate::state::AppState;
use crate::services::sso_encryption::SsoEncryption;
use shared_types::{AppError, Result};
use identity_engine::services::oauth_service::OAuthConfig;
use identity_engine::services::saml::SamlService;
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
            .map_err(|e| AppError::Internal(format!("Invalid provider config: {e}")))?;

        // MEDIUM-6 FIX: Decrypt client_secret before use.
        // Secrets are stored encrypted (enc:v1:<base64url>) by sso_mgmt.rs.
        // SsoEncryption::decrypt() transparently handles both encrypted and legacy plaintext.
        let enc = SsoEncryption::from_env();
        let plaintext_secret = enc.decrypt(&config.client_secret)
            .map_err(|e| AppError::Internal(format!("Failed to decrypt SSO client_secret: {e}")))?;
            
        return Ok(OAuthConfig {
            client_id: config.client_id,
            client_secret: plaintext_secret,
            redirect_uri: config.redirect_uri,
            authorization_url: config.authorization_url,
            token_url: config.token_url,
            userinfo_url: config.userinfo_url,
        });
    }

    // Fallback or Error
    Err(AppError::Internal(format!("Provider {provider} not configured")))
}

async fn authorize_handler(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    let tenant_id = params.get("tenant_id").map(|s| s.as_str()).unwrap_or("platform"); // Default
    
    let config = load_provider_config(&state, &provider, tenant_id).await?;
    
    // Delegate to OAuthService for state and PKCE generation
    let flow_init = state.oauth_service.initiate_flow(&config, tenant_id).await?;
    
    // Store tenant_id mapping in Redis so the callback knows which tenant this state belongs to
    if let Ok(client) = redis::Client::open(state.config.redis.url.as_str()) {
        if let Ok(mut conn) = client.get_async_connection().await {
            let key = format!("oauth_tenant:{}", flow_init.state);
            let _: std::result::Result<(), _> = redis::cmd("SETEX")
                .arg(&key).arg(600).arg(tenant_id) // 10 minutes
                .query_async(&mut conn).await;
        }
    }
    
    Ok(Redirect::to(&flow_init.authorization_url))
}

async fn callback_handler(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let state_param = query.state.as_deref().ok_or_else(|| AppError::Unauthorized("Missing OAuth state parameter".into()))?;

    // Retrieve tenant_id mapper from Redis
    let tenant_id: String = if let Ok(client) = redis::Client::open(state.config.redis.url.as_str()) {
        if let Ok(mut conn) = client.get_async_connection().await {
            let key = format!("oauth_tenant:{state_param}");
            let tid: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await.ok().flatten();
            let _: std::result::Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
            tid
        } else { None }
    } else { None }.ok_or_else(|| AppError::Unauthorized("Invalid or expired OAuth state parameter".into()))?;

    // Validate state and get PKCE verifier using OAuthService
    let code_verifier = state.oauth_service.validate_callback_state(&tenant_id, state_param).await?;

    let config = load_provider_config(&state, &provider, &tenant_id).await?;
    
    // 1. Exchange code (now with PKCE support)
    let tokens = state.oauth_service.exchange_code_for_token(&config, &query.code, &code_verifier).await?;
    
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
    let _sso_decision_allowed = {
        // Resolve capsule: Redis cache → compile fallback → write-back to cache
        // F-2 FIX: track policy_version so cache entry has a meaningful version field.
        let (capsule, from_cache, policy_version) = if let Some(cached) = cache.get(&tenant_id, capsule_action).await {
            use prost::Message;
            match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
                Ok(c) => (c, true, cached.version),
                Err(_) => {
                    tracing::warn!("Failed to decode cached capsule for {}, recompiling", capsule_action);
                    let (ast, ver) = build_sso_policy_ast(&tenant_id, &state.db).await?;
                    let c = compile_sso_policy(&ast, &tenant_id, &state).await
                        .map_err(|e| AppError::Internal(format!("Compile error: {e}")))?;
                    (c, false, ver)
                }
            }
        } else {
            tracing::info!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
            let (ast, ver) = build_sso_policy_ast(&tenant_id, &state.db).await?;
            let c = compile_sso_policy(&ast, &tenant_id, &state).await
                .map_err(|e| AppError::Internal(format!("Compile error: {e}")))?;
            (c, false, ver)
        };

        // Write compiled capsule back to Redis cache so subsequent requests are served from cache.
        // F-2 FIX: use real policy_version instead of sentinel 0.
        if !from_cache {
            use prost::Message;
            let mut capsule_bytes = Vec::new();
            if capsule.encode(&mut capsule_bytes).is_ok() {
                let cached = crate::services::capsule_cache::CachedCapsule {
                    tenant_id: tenant_id.clone(),
                    action: capsule_action.to_string(),
                    version: policy_version,
                    ast_hash: capsule.ast_hash_b64.clone(),
                    wasm_hash: capsule.wasm_hash_b64.clone(),
                    capsule_bytes,
                    cached_at: chrono::Utc::now().timestamp(),
                };
                if let Err(e) = cache.set(&cached).await {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        action = %capsule_action,
                        policy_version = %policy_version,
                        error = %e,
                        "OAuth SSO: failed to write compiled capsule to cache (non-fatal)"
                    );
                } else {
                    tracing::debug!(
                        tenant_id = %tenant_id,
                        action = %capsule_action,
                        policy_version = %policy_version,
                        "OAuth SSO: compiled capsule written to cache"
                    );
                }
            }
        }

        // F-3 FIX: Reuse the shared runtime client from AppState instead of creating
        // a new TCP connection per request. state.runtime_client is Arc-backed with
        // a circuit breaker and retry logic — cloning it is O(1) (Arc ref-count bump).
        let client = state.runtime_client.clone();

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
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token, is_secure);

    let frontend_url = format!("{}/auth/callback", state.config.frontend_url);

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::FOUND)
        .header(axum::http::header::LOCATION, &frontend_url)
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .body(axum::body::Body::empty())
        .map_err(|e| AppError::Internal(format!("Response build error: {e}")))?;

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
    tenant_id: Option<String>,
}

/// SAML Authorization redirect
///
/// Security design:
/// - `tenant_id` comes from the query parameter (set by the frontend after org selection).
/// - We generate a cryptographically random relay state token and store
///   `{tenant_id, connection_id}` in Redis under `saml:relay:<token>` (10-min TTL).
/// - The opaque token is sent to the IdP as RelayState.
/// - The ACS handler calls `verify_relay_state()` to recover the tenant context,
///   preventing tenant-confusion attacks where an attacker crafts a RelayState
///   that maps to a different tenant's SAML connection.
async fn saml_authorize(
    State(state): State<AppState>,
    Path(connection_id): Path<String>,
    Query(query): Query<SamlAuthorizeQuery>,
) -> Result<impl IntoResponse> {
    let tenant_id = query.tenant_id.unwrap_or_else(|| "platform".to_string());

    // Build SP entity_id and ACS URL from configured frontend/server URLs
    let sp_entity_id = saml_sp_entity_id(&state);
    let acs_url = saml_acs_url(&state);

    // MEDIUM-3 FIX: Use new_with_signing() with Option<String> params.
    // Signs AuthnRequests when SAML_SP_SIGNING_KEY_PEM + SAML_SP_SIGNING_CERT_PEM are set.
    let saml = SamlService::new_with_signing(
        state.db.clone(),
        sp_entity_id,
        acs_url,
        std::env::var("SAML_SP_SIGNING_KEY_PEM").ok(),
        std::env::var("SAML_SP_SIGNING_CERT_PEM").ok(),
    );

    // Verify the connection exists for this tenant before generating relay state
    let idp_config = saml.load_idp_config(&connection_id, &tenant_id).await?;

    // Generate opaque relay state token and store tenant context in Redis
    let redis_client = redis::Client::open(state.config.redis.url.as_str())
        .map_err(|e| AppError::Internal(format!("Redis client error: {e}")))?;
    let mut redis_conn = redis_client.get_async_connection().await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {e}")))?;

    let relay_token = saml.store_relay_state(&tenant_id, &connection_id, &mut redis_conn).await?;

    // MEDIUM-3 FIX: get_sso_redirect_url signs when key is configured
    let redirect_url = saml.get_sso_redirect_url(&idp_config, &relay_token)
        .map_err(|e| AppError::Internal(format!("Failed to build SAML redirect URL: {e}")))?;

    tracing::info!(
        tenant_id = %tenant_id,
        connection_id = %connection_id,
        "SAML authorize redirect generated"
    );

    Ok(Redirect::to(&redirect_url))
}

#[derive(Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// SAML Assertion Consumer Service (ACS) - receives POST from IdP
///
/// Security design:
/// - RelayState is treated as an opaque token, NOT as a raw tenant_id.
/// - We call `verify_relay_state()` to atomically consume the Redis entry and
///   recover the original `{tenant_id, connection_id}` stored during authorize.
/// - This prevents tenant-confusion attacks and CSRF via crafted RelayState.
async fn saml_acs(
    State(state): State<AppState>,
    Form(form): Form<SamlAcsForm>,
) -> Result<impl IntoResponse> {
    // 1. Get Redis connection (needed for relay state verification AND replay protection)
    let redis_client = redis::Client::open(state.config.redis.url.as_str())
        .map_err(|e| AppError::Internal(format!("Redis client error: {e}")))?;
    let mut redis_conn = redis_client.get_async_connection().await
        .map_err(|e| AppError::Internal(format!("Redis connection error: {e}")))?;

    // 2. Verify and consume relay state — recovers tenant_id + connection_id
    //    RelayState is REQUIRED for security; reject if missing.
    let relay_token = form.relay_state.as_deref()
        .ok_or_else(|| AppError::Unauthorized("Missing SAML RelayState — possible CSRF".into()))?;

    let sp_entity_id = saml_sp_entity_id(&state);
    let acs_url = saml_acs_url(&state);

    // Use a temporary SamlService instance just for relay state verification
    // (no signing key needed for ACS — we're verifying the IdP's signature, not signing)
    let saml = SamlService::new(
        state.db.clone(),
        sp_entity_id,
        acs_url,
    );

    let relay_payload = saml.verify_relay_state(relay_token, &mut redis_conn).await?;
    let saml_tenant_id = &relay_payload.tenant_id;
    let connection_id = &relay_payload.connection_id;

    tracing::info!(
        tenant_id = %saml_tenant_id,
        connection_id = %connection_id,
        "SAML ACS: relay state verified"
    );

    // 3. Load IdP config — scoped to verified tenant + connection_id
    let idp_config = saml.load_idp_config(connection_id, saml_tenant_id).await?;

    // 4. Strict XML-DSig Verification + Assertion extraction + Replay protection
    let assertion = saml.verify_and_extract(&form.saml_response, &idp_config, &mut redis_conn).await?;
    
    // 5. Normalize Facts
    let saml_facts = saml.normalize_facts(&assertion);

    // 6. EIAA: Execute Capsule (Real WASM)
    // Input: facts
    let input_json = serde_json::json!({
        "action": "login",
        "auth": saml_facts,
        "risk": { "score": 0 } // Placeholder for Risk Engine integration
    });
    
    // Generate Nonce
    let nonce: [u8; 16] = rand::random();
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    // Build AuthEvidence from SAML assertion
    // NOTE: The runtime client (state.runtime_client) is initialized after the
    // capsule cache resolution block below, which also uses state.runtime_client.clone().
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

    // Resolve capsule: Redis cache → compile fallback → write-back to cache.
    // F-2 FIX: track policy_version so cache entry has a meaningful version field.
    let (capsule, from_cache, policy_version) = if let Some(cached) = cache.get(&saml_tenant_id.to_string(), capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true, cached.version),
            Err(_) => {
                tracing::warn!("Failed to decode cached capsule for {}, recompiling", capsule_action);
                let (ast, ver) = build_sso_policy_ast(saml_tenant_id, &state.db).await?;
                let c = compile_sso_policy(&ast, saml_tenant_id, &state).await
                    .map_err(|e| AppError::Internal(format!("Compile error: {e}")))?;
                (c, false, ver)
            }
        }
    } else {
        tracing::info!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
        let (ast, ver) = build_sso_policy_ast(saml_tenant_id, &state.db).await?;
        let c = compile_sso_policy(&ast, saml_tenant_id, &state).await
            .map_err(|e| AppError::Internal(format!("Compile error: {e}")))?;
        (c, false, ver)
    };

    // Write compiled capsule back to Redis cache so subsequent requests are served from cache.
    // F-2 FIX: use real policy_version instead of sentinel 0.
    if !from_cache {
        use prost::Message;
        let mut capsule_bytes = Vec::new();
        if capsule.encode(&mut capsule_bytes).is_ok() {
            let cached = crate::services::capsule_cache::CachedCapsule {
                tenant_id: saml_tenant_id.to_string(),
                action: capsule_action.to_string(),
                version: policy_version,
                ast_hash: capsule.ast_hash_b64.clone(),
                wasm_hash: capsule.wasm_hash_b64.clone(),
                capsule_bytes,
                cached_at: chrono::Utc::now().timestamp(),
            };
            if let Err(e) = cache.set(&cached).await {
                tracing::warn!(
                    tenant_id = %saml_tenant_id,
                    action = %capsule_action,
                    policy_version = %policy_version,
                    error = %e,
                    "SAML SSO: failed to write compiled capsule to cache (non-fatal)"
                );
            } else {
                tracing::debug!(
                    tenant_id = %saml_tenant_id,
                    action = %capsule_action,
                    policy_version = %policy_version,
                    "SAML SSO: compiled capsule written to cache"
                );
            }
        }
    }

    // F-3 FIX: Reuse the shared runtime client from AppState instead of creating
    // a new TCP connection per request. state.runtime_client is Arc-backed with
    // a circuit breaker and retry logic — cloning it is O(1) (Arc ref-count bump).
    // The SAML ACS handler previously called EiaaRuntimeClient::connect() which
    // creates a new TCP+TLS connection on every SSO login, adding 50–200ms overhead.
    let client = state.runtime_client.clone();

    let response = client.execute_with_evidence(
        capsule.clone(),
        serde_json::to_string(&input_json).unwrap(),
        nonce_b64.clone(),
        evidence,
    ).await
        .map_err(|e| AppError::Internal(format!("Runtime error: {e}")))?;
        
    let decision = response.decision.ok_or(AppError::Internal("Missing decision".into()))?;
    
    // Log the reason if denied
    if !decision.allow {
        tracing::warn!("SAML Login denied: {}", decision.reason);
        return Err(AppError::Forbidden(format!("Policy denied login: {}", decision.reason)));
    }

    // 7. User Provisioning / Linking
    //
    // The `users` table is platform-level (no tenant_id column).
    // Tenant scoping is via `memberships`. We:
    //   a) Find or create the user by email identity (platform-wide).
    //   b) Ensure the user has a membership in the target organization.
    //
    // This supports JIT (Just-In-Time) provisioning: the first SAML login
    // for a new user creates both the user record and the org membership.
    let user_id = provision_saml_user(
        &state.db,
        &saml_facts.email,
        saml_tenant_id,
    ).await?;
    
    // 8. Store Attestation & Generate Decision Ref
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
            saml_tenant_id,
            &user_id
        )?;
    }
    
    // 7. Create Session
    let session_id = shared_types::id_generator::generate_id("sess");
    let session_token = shared_types::id_generator::generate_id("stok");

    // SAML logins start at AAL1 with saml capability
    let assurance_level = "aal1";
    let verified_capabilities = serde_json::json!(["saml"]);

    sqlx::query(
        r#"INSERT INTO sessions (
            id, user_id, token, user_agent, ip_address,
            expires_at, created_at, updated_at,
            session_type, decision_ref, assurance_level,
            verified_capabilities, is_provisional, tenant_id
        ) VALUES ($1, $2, $3, 'SAML-Client', '0.0.0.0',
            NOW() + INTERVAL '24 hours', NOW(), NOW(),
            'saml_session', $4, $5, $6, false, $7)"#
    )
        .bind(&session_id)
        .bind(&user_id)
        .bind(&session_token)   // opaque session token, not session_id
        .bind(&decision_ref)
        .bind(assurance_level)
        .bind(&verified_capabilities)
        .bind(saml_tenant_id)
        .execute(&state.db)
        .await?;

    // 8. Generate JWT — use verified tenant_id from relay state (not hardcoded "platform")
    let token = state.jwt_service.generate_token(
        &user_id,
        &session_id,
        saml_tenant_id,
        "saml_session",
    )?;
    
    // Redirect with httpOnly cookies (no token in URL)
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let session_cookie = crate::middleware::csrf::session_cookie_header(&token, is_secure);
    let csrf_token = crate::middleware::csrf::generate_csrf_token();
    let csrf_cookie = crate::middleware::csrf::csrf_cookie_header(&csrf_token, is_secure);

    // Redirect to frontend callback — never redirect to raw relay_state (it's an opaque token)
    let redirect_url = format!("{}/auth/callback", state.config.frontend_url);

    let response = axum::response::Response::builder()
        .status(axum::http::StatusCode::FOUND)
        .header(axum::http::header::LOCATION, &redirect_url)
        .header(axum::http::header::SET_COOKIE, session_cookie)
        .header(axum::http::header::SET_COOKIE, csrf_cookie)
        .body(axum::body::Body::empty())
        .map_err(|e| AppError::Internal(format!("Response build error: {e}")))?;

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
            .map_err(|e| AppError::Internal(format!("Attestation body json: {e}")))?;
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
        input_context: None,
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

// ── SP URL helpers ────────────────────────────────────────────────────────────

/// Canonical SP Entity ID — used in SP metadata and as the Audience in assertions.
///
/// Derived from `SAML_SP_ENTITY_ID` env var if set, otherwise constructed from
/// the configured frontend URL to ensure it matches what was registered with the IdP.
fn saml_sp_entity_id(state: &AppState) -> String {
    std::env::var("SAML_SP_ENTITY_ID")
        .unwrap_or_else(|_| format!("{}/auth/sso/saml", state.config.frontend_url))
}

/// ACS (Assertion Consumer Service) URL — where the IdP POSTs the SAML Response.
///
/// Derived from `SAML_ACS_URL` env var if set, otherwise constructed from the
/// server host. Must match the ACS URL registered with the IdP exactly.
fn saml_acs_url(state: &AppState) -> String {
    std::env::var("SAML_ACS_URL")
        .unwrap_or_else(|_| format!("https://{}/auth/sso/saml/acs", state.config.server.host))
}

// ── SAML User Provisioning ────────────────────────────────────────────────────

/// Find or create a user for a SAML login (JIT provisioning).
///
/// ## Design
/// The `users` table is platform-level (no `tenant_id` column). Tenant scoping
/// is via `memberships` (user ↔ organization). This function:
///
/// 1. Looks up the user by email identity (platform-wide, type = 'email').
/// 2. If not found, creates the user + email identity in a transaction.
/// 3. Ensures the user has a `member` role membership in the target organization.
///    - If the org doesn't exist, the membership insert is skipped (org must be
///      pre-created by an admin; SAML JIT does not auto-create organizations).
///
/// ## Security
/// - The `tenant_id` parameter is the verified tenant from the relay state,
///   NOT from the SAML assertion or request body.
/// - Email identity is marked `verified = true` because SAML assertions from
///   a trusted IdP imply the IdP has verified the email address.
async fn provision_saml_user(
    db: &sqlx::PgPool,
    email: &str,
    tenant_id: &str,
) -> shared_types::Result<String> {
    // 1. Find existing user by email identity
    let existing_user_id: Option<String> = sqlx::query_scalar(
        r#"SELECT u.id FROM users u
           INNER JOIN identities i ON i.user_id = u.id
           WHERE i.type = 'email' AND i.identifier = $1
           LIMIT 1"#
    )
    .bind(email)
    .fetch_optional(db)
    .await?;

    let user_id = if let Some(id) = existing_user_id {
        tracing::debug!(email = %email, user_id = %id, "SAML: existing user found");
        id
    } else {
        // 2. JIT provision: create user + email identity in a transaction
        let new_user_id = shared_types::id_generator::generate_id("user");
        let identity_id = shared_types::id_generator::generate_id("ident");

        let mut tx = db.begin().await?;

        sqlx::query(
            "INSERT INTO users (id, created_at, updated_at) VALUES ($1, NOW(), NOW())"
        )
        .bind(&new_user_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"INSERT INTO identities (id, user_id, type, identifier, verified, verified_at, created_at, updated_at)
               VALUES ($1, $2, 'email', $3, true, NOW(), NOW(), NOW())"#
        )
        .bind(&identity_id)
        .bind(&new_user_id)
        .bind(email)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        tracing::info!(
            email = %email,
            user_id = %new_user_id,
            tenant_id = %tenant_id,
            "SAML: JIT provisioned new user"
        );
        new_user_id
    };

    // 3. Ensure membership in the target organization (idempotent upsert)
    //    ON CONFLICT DO NOTHING — if membership already exists, no-op.
    //    If the org doesn't exist, the FK constraint will cause a silent skip
    //    (we use INSERT ... WHERE EXISTS to avoid FK violation noise).
    let membership_id = shared_types::id_generator::generate_id("memb");
    let rows_affected = sqlx::query(
        r#"INSERT INTO memberships (id, organization_id, user_id, role, created_at, updated_at)
           SELECT $1, $2, $3, 'member', NOW(), NOW()
           WHERE EXISTS (SELECT 1 FROM organizations WHERE id = $2 AND deleted_at IS NULL)
           ON CONFLICT (organization_id, user_id) DO NOTHING"#
    )
    .bind(&membership_id)
    .bind(tenant_id)
    .bind(&user_id)
    .execute(db)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        // Either org doesn't exist or membership already exists — both are acceptable
        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "SAML: membership upsert: no rows inserted (org missing or already member)"
        );
    } else {
        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "SAML: JIT membership created"
        );
    }

    Ok(user_id)
}

use capsule_compiler::ast::Program;
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};

/// Fetch the most recent SSO policy AST and its version number from the DB.
///
/// Returns `(Program, policy_version)` so callers can populate `CachedCapsule.version`
/// with a meaningful value instead of the sentinel `0`.
///
/// ## F-2 FIX: Policy version in cache
/// Previously this function returned only the `Program` (AST), discarding the
/// `version` integer from `eiaa_policies`. The cache write-back used `version: 0`
/// as a result, making it impossible to distinguish cache entries by policy version
/// for debugging, forced invalidation, or audit purposes.
async fn build_sso_policy_ast(tenant_id: &str, db: &sqlx::PgPool) -> Result<(Program, i32)> {
    let row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:sso_login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some((version, json)) = row {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
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
