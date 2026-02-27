use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::capsules::signup_capsule::{compile_signup_capsule, build_signup_context};
use crate::clients::runtime_client::EiaaRuntimeClient;
use identity_engine::models::SignupTicket;
use shared_types::{AppError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Deserialize)]
pub struct InitFlowRequest {
    pub signup_ticket_id: String,
}

#[derive(Serialize)]
pub struct InitFlowResponse {
    pub flow_id: String,
    pub ui_step: UiStep,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type")]
pub enum UiStep {
    #[serde(rename = "verification_code")]
    VerificationCode {
        label: String,
        attempts_remaining: i32,
    },

}

#[derive(Deserialize)]
pub struct SubmitRequest {
    #[serde(rename = "type")]
    pub step_type: String,
    pub value: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SubmitResponse {
    DecisionReady {
        status: String,
        decision_ref: String,
    },
    NextStep {
        flow_id: String,
        ui_step: UiStep,
    },
}

#[derive(Serialize)]
pub struct CommitResult {
    pub status: String,
    pub user_id: String,
    pub identity_id: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/flows", post(init_flow))
        .route("/flows/:flow_id/submit", post(submit_flow))
        .route("/decisions/:decision_ref/commit", post(commit_decision))
}

async fn init_flow(
    State(state): State<AppState>,
    Json(payload): Json<InitFlowRequest>,
) -> Result<Json<InitFlowResponse>> {
    // Get signup ticket
    let ticket = sqlx::query_as::<_, SignupTicket>(
        "SELECT * FROM signup_tickets WHERE id = $1"
    )
    .bind(&payload.signup_ticket_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Signup ticket not found".into()))?;

    // Validate ticket
    if ticket.expires_at < chrono::Utc::now() {
        return Err(AppError::BadRequest("Signup ticket expired".into()));
    }

    if ticket.status != "awaiting_verification" {
        return Err(AppError::BadRequest("Ticket already used".into()));
    }

    // Generate flow ID
    let flow_id = shared_types::id_generator::generate_id("flow_signup");

    // Bind flow to ticket
    sqlx::query(
        "UPDATE signup_tickets SET flow_id = $1 WHERE id = $2"
    )
    .bind(&flow_id)
    .bind(&payload.signup_ticket_id)
    .execute(&state.db)
    .await?;

    Ok(Json(InitFlowResponse {
        flow_id,
        ui_step: UiStep::VerificationCode {
            label: "Enter the 6-digit code sent to your email".to_string(),
            attempts_remaining: 3 - ticket.verification_attempts,
        },
    }))
}

async fn submit_flow(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
    Json(payload): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>> {
    // Get ticket by flow_id
    let ticket = sqlx::query_as::<_, SignupTicket>(
        "SELECT * FROM signup_tickets WHERE flow_id = $1"
    )
    .bind(&flow_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Flow not found".into()))?;

    tracing::info!("Submitting signup flow step: type={}, flow_id={}", payload.step_type, flow_id);

    // Compile signup capsule
    let org_id = "platform"; // For now, platform-level signup
    let capsule = compile_signup_capsule(org_id, &state).await
        .map_err(|e| AppError::BadRequest(format!("Capsule compilation failed: {}", e)))?;

    // Build context
    let context = build_signup_context(&ticket, &payload.value);
    let input_json = serde_json::to_string(&context)?;

    // Execute via gRPC
    let mut runtime_client = EiaaRuntimeClient::connect(state.config.eiaa.runtime_grpc_addr.clone())
        .await
        .map_err(|e| AppError::BadRequest(format!("Runtime connection failed: {}", e)))?;

    let nonce = generate_nonce();
    let response = runtime_client
        .execute_capsule(capsule.clone(), input_json, nonce.clone())
        .await
        .map_err(|e| AppError::BadRequest(format!("Capsule execution failed: {}", e)))?;

    // Parse decision
    let decision = response.decision
        .ok_or_else(|| AppError::BadRequest("No decision returned".into()))?;

    // Increment attempts
    sqlx::query(
        "UPDATE signup_tickets SET verification_attempts = verification_attempts + 1, last_attempt_at = NOW() WHERE id = $1"
    )
    .bind(&ticket.id)
    .execute(&state.db)
    .await?;

    if decision.allow {
        // Generate decision reference
        let decision_ref = shared_types::id_generator::generate_id("dec_signup");

        // Store decision_ref on ticket
        sqlx::query(
            "UPDATE signup_tickets SET decision_ref = $1, status = 'verified' WHERE id = $2"
        )
        .bind(&decision_ref)
        .bind(&ticket.id)
        .execute(&state.db)
        .await?;

        // Store attestation if present
        if let Some(attestation) = response.attestation {
            store_attestation(
                &state.audit_writer,
                &decision_ref,
                &capsule,
                &decision,
                attestation,
                &nonce,
                "signup",
                "platform",
            )?;
        }

        Ok(Json(SubmitResponse::DecisionReady {
            status: "decision_ready".to_string(),
            decision_ref,
        }))
    } else {
        // Return error with attempts remaining
        let attempts_left = 3 - (ticket.verification_attempts + 1);
        
        Ok(Json(SubmitResponse::NextStep {
            flow_id,
            ui_step: UiStep::VerificationCode {
                label: if attempts_left > 0 {
                    format!("Verification failed. {} attempts remaining", attempts_left)
                } else {
                    "Too many attempts. Please start over.".to_string()
                },
                attempts_remaining: attempts_left,
            },
        }))
    }
}

async fn commit_decision(
    State(state): State<AppState>,
    Path(decision_ref): Path<String>,
) -> Result<Json<CommitResult>> {
    // This endpoint is INTERNAL only
    // In production, protect with service auth

    // Get ticket by decision_ref
    let ticket = sqlx::query_as::<_, SignupTicket>(
        "SELECT * FROM signup_tickets WHERE decision_ref = $1"
    )
    .bind(&decision_ref)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Decision not found".into()))?;

     // Idempotency check - if user already exists with this email, return it
    let email_str = ticket.email.as_deref().unwrap_or("");
    if let Some(existing) = check_existing_identity(&state.db, email_str).await? {
        return Ok(Json(CommitResult {
            status: "already_exists".to_string(),
            user_id: existing.0,
            identity_id: existing.1,
        }));
    }

    // Begin transaction
    let mut tx = state.db.begin().await?;

    // Create user
    let user_id = shared_types::id_generator::generate_id("usr");
    sqlx::query(
        r#"
        INSERT INTO users (id, email, first_name, last_name, organization_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, 'platform', NOW(), NOW())
        "#
    )
    .bind(&user_id)
    .bind(&ticket.email)
    .bind(&ticket.first_name)
    .bind(&ticket.last_name)
    .execute(&mut *tx)
    .await?;

    // Create identity
    let identity_id = shared_types::id_generator::generate_id("idn");
    sqlx::query(
        r#"
        INSERT INTO identities (id, user_id, type, identifier, verified, verified_at, created_at)
        VALUES ($1, $2, 'email', $3, true, NOW(), NOW())
        "#
    )
    .bind(&identity_id)
    .bind(&user_id)
    .bind(&ticket.email)
    .execute(&mut *tx)
    .await?;

    // Create password
    sqlx::query(
        r#"
        INSERT INTO passwords (id, user_id, hash, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        "#
    )
    .bind(shared_types::id_generator::generate_id("pwd"))
    .bind(&user_id)
    .bind(&ticket.password_hash)
    .execute(&mut *tx)
    .await?;

    // Delete signup ticket
    sqlx::query("DELETE FROM signup_tickets WHERE id = $1")
        .bind(&ticket.id)
        .execute(&mut *tx)
        .await?;

    // Commit transaction
    tx.commit().await?;

    Ok(Json(CommitResult {
        status: "signup_completed".to_string(),
        user_id,
        identity_id,
    }))
}

// Helper functions

fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn store_attestation(
    audit_writer: &crate::services::audit_writer::AuditWriter,
    decision_ref: &str,
    capsule: &grpc_api::eiaa::runtime::CapsuleSigned,
    decision: &grpc_api::eiaa::runtime::Decision,
    attestation: grpc_api::eiaa::runtime::Attestation,
    nonce: &str,
    action: &str,
    tenant_id: &str,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Hash full context for input_digest (not just nonce) - EIAA compliance
    let mut hasher = Sha256::new();
    hasher.update(capsule.capsule_hash_b64.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(action.as_bytes());
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
        capsule_version: "signup_capsule_v1".to_string(),
        action: action.to_string(),
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
        user_id: None,
    });

    tracing::info!("Queued attestation for decision: {}", decision_ref);
    Ok(())
}

async fn check_existing_identity(
    db: &sqlx::PgPool,
    email: &str,
) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT u.id, i.id
        FROM users u
        JOIN identities i ON i.user_id = u.id
        WHERE i.identifier = $1 AND i.type = 'email'
        LIMIT 1
        "#
    )
    .bind(email)
    .fetch_optional(db)
    .await?;

    Ok(row)
}
