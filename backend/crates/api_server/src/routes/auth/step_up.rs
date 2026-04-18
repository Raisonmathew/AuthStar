use crate::capsules::step_up_capsule::{compile_step_up_capsule, load_step_up_policy};
use crate::services::StoreAttestationParams;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::extract::{Extension, Query};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use shared_types::AssuranceLevel;

#[derive(Deserialize)]
pub struct StepUpRequest {
    pub factor_id: String,
    /// TOTP 6-digit code (required for TOTP factors)
    #[serde(default)]
    pub code: Option<String>,
    /// WebAuthn assertion response (required for passkey factors)
    #[serde(default)]
    pub assertion: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct PasskeyChallengeQuery {
    pub factor_id: String,
}

/// Response returned after a successful step-up.
#[derive(Serialize)]
pub struct StepUpResponse {
    pub token: String,
    pub aal_level: i16,
    pub provisional: bool,
    pub decision_ref: String,
    /// True when risk was high but the user's strongest available factor was
    /// weaker than what policy would prefer. The step-up succeeded but the
    /// frontend should nudge enrollment of a stronger factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_assurance: Option<bool>,
    /// When set, tells the frontend which kind of factor should be enrolled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enroll_recommendation: Option<String>,
}

/// Error body returned when step-up cannot proceed.
#[derive(Serialize)]
pub struct StepUpDenied {
    pub error: String,
    pub message: String,
    pub decision_ref: String,
    /// Present when the user must take an out-of-band action (e.g. enroll a
    /// factor) before step-up can succeed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_required: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrolled_factors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<serde_json::Value>,
}

/// Step-up authentication router
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/auth/step-up", post(step_up_session))
        .route("/auth/step-up/passkey-challenge", get(passkey_challenge))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth::require_auth_allow_provisional,
        ))
        .with_state(state)
}

/// GET /api/v1/auth/step-up/passkey-challenge?factor_id=<id>
///
/// Returns a WebAuthn challenge for passkey-based step-up verification.
async fn passkey_challenge(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<PasskeyChallengeQuery>,
) -> impl IntoResponse {
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    // Verify the factor belongs to this user and is a passkey
    let factor_type = match state
        .user_factor_service
        .get_factor_type(user_id.as_str(), tenant_id.as_str(), &query.factor_id)
        .await
    {
        Ok(ft) => ft,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "FACTOR_NOT_FOUND",
                    "message": "The specified factor does not exist for this user",
                })),
            )
                .into_response();
        }
    };

    if factor_type != "passkey" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "INVALID_FACTOR_TYPE",
                "message": "This endpoint only supports passkey factors",
            })),
        )
            .into_response();
    }

    // Start passkey authentication via PasskeyService
    match state
        .passkey_service
        .start_authentication(user_id.as_str())
        .await
    {
        Ok(auth_start) => {
            // Return the challenge options along with the session_id
            // The frontend needs session_id to send back with the assertion
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "session_id": auth_start.session_id,
                    "publicKey": auth_start.options,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to start passkey authentication for step-up");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "PASSKEY_CHALLENGE_FAILED",
                    "message": format!("{e}"),
                })),
            )
                .into_response()
        }
    }
}

async fn step_up_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<StepUpRequest>,
) -> impl IntoResponse {
    let session_id = &claims.sid;
    let user_id = &claims.sub;
    let tenant_id = &claims.tenant_id;

    // ── 1. Query enrolled factors FIRST ──────────────────────────────────────
    // We need to know what capabilities a user actually has before attempting
    // anything.  This feeds the capsule's capability-first decision logic.
    let enrolled_factors = match state
        .user_factor_service
        .list_factors(user_id.as_str(), tenant_id.as_str())
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list user factors");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query enrolled factors",
            )
                .into_response();
        }
    };

    let enrolled_factor_types: Vec<String> = enrolled_factors
        .iter()
        .map(|f| f.factor_type.clone())
        .collect();
    let enrolled_factor_count = enrolled_factors.len() as i64;
    let has_passkey = enrolled_factor_types.iter().any(|t| t == "passkey");
    let has_otp = enrolled_factor_types.iter().any(|t| t == "totp");

    // ── 2. Verify the submitted factor ──────────────────────────────────────
    // Factor verification (timing-sensitive crypto) stays in Rust — the capsule
    // only gates on the *type* and risk context after verification succeeds.
    //
    // Skip verification for the zero-factor case — we'll let the capsule deny
    // it cleanly with `no_factors_enrolled` instead of a cryptic 400.
    let factor_type: String;

    if enrolled_factor_count == 0 {
        // No factors enrolled — we'll pass this through to the capsule which
        // will deny it with an actionable error.  Set a placeholder so the
        // capsule context is well-formed.
        factor_type = "none".to_string();
    } else {
        // Look up the submitted factor's type before verifying
        factor_type = match state
            .user_factor_service
            .get_factor_type(user_id.as_str(), tenant_id.as_str(), &payload.factor_id)
            .await
        {
            Ok(ft) => ft,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "FACTOR_NOT_FOUND",
                        "message": "The submitted factor_id does not exist or is not enrolled for this user",
                        "enrolled_factor_types": enrolled_factor_types,
                    })),
                )
                    .into_response();
            }
        };

        // Branch on factor type: passkey uses WebAuthn ceremony, TOTP uses code
        if factor_type == "passkey" {
            // ── Passkey verification via WebAuthn assertion ──────────────────
            let assertion = match &payload.assertion {
                Some(a) => a,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "MISSING_ASSERTION",
                            "message": "Passkey verification requires an 'assertion' field with the WebAuthn response",
                        })),
                    )
                        .into_response();
                }
            };

            // The assertion from @simplewebauthn/browser needs to be parsed
            // as a webauthn-rs PublicKeyCredential
            let session_id_webauthn = assertion
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Extract the actual credential response (everything except session_id)
            let credential: webauthn_rs::prelude::PublicKeyCredential =
                match serde_json::from_value(assertion.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to parse passkey assertion");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": "INVALID_ASSERTION",
                                "message": format!("Failed to parse WebAuthn assertion: {e}"),
                            })),
                        )
                            .into_response();
                    }
                };

            match state
                .passkey_service
                .finish_authentication(user_id.as_str(), session_id_webauthn, &credential)
                .await
            {
                Ok(_result) => {
                    // Passkey verified successfully — continue to capsule evaluation
                }
                Err(e) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": "PASSKEY_VERIFICATION_FAILED",
                            "message": format!("{e}"),
                            "factor_type": "passkey",
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            // ── TOTP/code verification ──────────────────────────────────────
            let code = match &payload.code {
                Some(c) if !c.is_empty() => c.as_str(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "MISSING_CODE",
                            "message": "TOTP verification requires a 'code' field",
                        })),
                    )
                        .into_response();
                }
            };

            let factor_valid = match state
                .user_factor_service
                .verify_factor_for_session(
                    user_id.as_str(),
                    tenant_id.as_str(),
                    session_id.as_str(),
                    &payload.factor_id,
                    code,
                )
                .await
            {
                Ok(valid) => valid,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "VERIFICATION_FAILED",
                            "message": e.to_string(),
                            "factor_type": factor_type,
                        })),
                    )
                        .into_response();
                }
            };

            if !factor_valid {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "INVALID_CODE",
                        "message": "The verification code is incorrect or expired",
                        "factor_type": factor_type,
                    })),
                )
                    .into_response();
            }
        }
    }

    // ── 3. Resolve step-up capsule: cache → DB → default ────────────────────
    let capsule_action = "auth:step_up";
    let (capsule, from_cache, policy_version) =
        match resolve_step_up_capsule(&state, tenant_id, capsule_action).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Step-up capsule resolution failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Step-up capsule failed: {e}"),
                )
                    .into_response();
            }
        };

    if !from_cache {
        cache_capsule(&state, tenant_id, capsule_action, policy_version, &capsule).await;
    }

    // ── 4. Build capability-first capsule context ────────────────────────────
    let current_aal: i16 = sqlx::query_scalar(
        "SELECT aal_level FROM sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1",
    )
    .bind(session_id.as_str())
    .bind(tenant_id.as_str())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(1);

    let risk_score = {
        let request_ctx = risk_engine::RequestContext {
            network: risk_engine::NetworkInput {
                remote_ip: "127.0.0.1".parse().unwrap(),
                x_forwarded_for: None,
                user_agent: "step-up".to_string(),
                accept_language: None,
                timestamp: chrono::Utc::now(),
            },
            device: None,
        };
        let subject_ctx = risk_engine::SubjectContext {
            subject_id: user_id.to_string(),
            org_id: tenant_id.to_string(),
        };
        let is_admin = claims.session_type == "admin";
        let eval = state
            .risk_engine
            .evaluate(&request_ctx, Some(&subject_ctx), Some("step_up"), is_admin)
            .await;
        eval.risk.total_score()
    };

    let degraded_assurance = risk_score > 70.0 && !has_passkey && factor_type != "passkey";

    let input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 1,
        "risk_score": risk_score as i64,
        "factors_satisfied": [],
        "authz_decision": 1,

        // Capability-first context — capsule decides based on reality
        "user_id": user_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "session_type": claims.session_type,
        "current_aal": current_aal,
        "factor_verified": enrolled_factor_count > 0,
        "factor_type": factor_type,
        "enrolled_factor_count": enrolled_factor_count,
        "enrolled_factor_types": enrolled_factor_types,
        "has_passkey_enrolled": if has_passkey { 1 } else { 0 },
        "has_otp_enrolled": if has_otp { 1 } else { 0 },
    });
    let input_json = match serde_json::to_string(&input) {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Context serialization failed: {e}"),
            )
                .into_response()
        }
    };

    // ── 5. Execute capsule via gRPC ──────────────────────────────────────────
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();
    let response = match state
        .runtime_client
        .execute_capsule(capsule.clone(), input_json, nonce.clone())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Step-up capsule execution failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Step-up capsule execution failed: {e}"),
            )
                .into_response();
        }
    };

    // ── 6. Extract decision + store attestation ──────────────────────────────
    let decision = match response.decision {
        Some(d) => d,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No decision returned from step-up capsule",
            )
                .into_response()
        }
    };

    let decision_ref = shared_types::id_generator::generate_id("dec_stepup");

    if let Some(attestation) = response.attestation {
        if let Err(e) = state
            .audit_writer
            .store_attestation(StoreAttestationParams {
                decision_ref: &decision_ref,
                capsule: &capsule,
                decision: &decision,
                attestation,
                nonce: &nonce,
                action: "auth:step_up",
                capsule_version: "step_up_capsule_v1",
                tenant_id: tenant_id.as_str(),
                user_id: Some(user_id.as_str()),
            })
        {
            tracing::error!(error = %e, "Failed to store step-up attestation");
        }
    }

    // ── 7. Handle capsule denial ─────────────────────────────────────────────
    // The capsule may deny for several distinct reasons — we check the
    // context to return structured errors so the frontend knows what to do.
    if !decision.allow {
        // The capsule's Deny(true) has no reason string in WASM; we infer
        // the specific denial reason from the input context we already have.
        let is_no_factors = enrolled_factor_count == 0;

        let denied = StepUpDenied {
            error: if is_no_factors {
                "NO_FACTORS_ENROLLED".to_string()
            } else {
                "STEP_UP_FACTOR_REJECTED".to_string()
            },
            message: if is_no_factors {
                "You have no authentication factors enrolled. Please set up \
                 TOTP or a passkey before attempting step-up authentication."
                    .to_string()
            } else {
                decision.reason.clone()
            },
            decision_ref,
            action_required: if is_no_factors {
                Some("ENROLL_FACTOR".to_string())
            } else {
                None
            },
            enrolled_factors: if is_no_factors { Some(vec![]) } else { None },
            requirement: decision.requirement.as_ref().map(|r| {
                serde_json::json!({
                    "required_assurance": r.required_assurance,
                    "acceptable_capabilities": r.acceptable_capabilities,
                    "require_phishing_resistant": r.require_phishing_resistant,
                })
            }),
        };

        return (StatusCode::FORBIDDEN, Json(denied)).into_response();
    }

    // ── 8. Success: risk stabilization + re-issue JWT ────────────────────────
    state
        .risk_engine
        .on_successful_auth(user_id.as_str(), AssuranceLevel::AAL2)
        .await;

    match state.jwt_service.generate_token(
        user_id.as_str(),
        session_id.as_str(),
        tenant_id.as_str(),
        claims.session_type.as_str(),
    ) {
        Ok(token) => (
            StatusCode::OK,
            Json(StepUpResponse {
                token,
                aal_level: AssuranceLevel::AAL2.as_i16(),
                provisional: false,
                decision_ref,
                degraded_assurance: if degraded_assurance { Some(true) } else { None },
                enroll_recommendation: if degraded_assurance {
                    Some("passkey".to_string())
                } else {
                    None
                },
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to re-issue token: {e}"),
        )
            .into_response(),
    }
}

// --- Capsule Resolution Helpers ---

/// Resolve step-up capsule: Redis cache → DB policy → hardcoded default → compile
async fn resolve_step_up_capsule(
    state: &AppState,
    tenant_id: &str,
    capsule_action: &str,
) -> anyhow::Result<(grpc_api::eiaa::runtime::CapsuleSigned, bool, i32)> {
    let cache = &state.capsule_cache;

    if let Some(cached) = cache.get(tenant_id, capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => return Ok((c, true, cached.version)),
            Err(_) => {
                tracing::warn!("Failed to decode cached step-up capsule, recompiling");
            }
        }
    }

    let (ast, version) = load_step_up_policy(tenant_id, &state.db).await?;
    let capsule = compile_step_up_capsule(&ast, tenant_id, state).await?;
    Ok((capsule, false, version))
}

/// Write-back a freshly compiled capsule to Redis cache
async fn cache_capsule(
    state: &AppState,
    tenant_id: &str,
    capsule_action: &str,
    policy_version: i32,
    capsule: &grpc_api::eiaa::runtime::CapsuleSigned,
) {
    use prost::Message;
    let mut capsule_bytes = Vec::new();
    if capsule.encode(&mut capsule_bytes).is_ok() {
        let cached = crate::services::capsule_cache::CachedCapsule {
            tenant_id: tenant_id.to_string(),
            action: capsule_action.to_string(),
            version: policy_version,
            ast_hash: capsule.ast_hash_b64.clone(),
            wasm_hash: capsule.wasm_hash_b64.clone(),
            capsule_bytes,
            cached_at: chrono::Utc::now().timestamp(),
        };
        let _ = state.capsule_cache.set(&cached).await;
    }
}
